#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#define MAX_LOG_PAYLOAD 32
#define AF_INET 2
#define MAX_FILTERS 256
#define MAX_TRANSITIONS 262144

//the biggest ip packet is max 65545 bytes long, minus the headders (134 bytes max) we get
//this value.
#define MAX_PAYLOAD_LEN 65401

#define PASS 0
#define DROP 2

#define ETH_P_IP   0x0800  // IPv4
#define ETH_P_IPV6 0x86DD  // IPv6
#define IPPROTO_TCP  6

//Structs for logging handling, the ringbuf is connected to a callback in libcursedproxy.
struct event {
    __u32 port;
    __u32 match_len;
    char matched_payload[MAX_LOG_PAYLOAD];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

//== Structs for DFA handling ==

//dfa_table stores the single transitions, this takes a lot of memory
//so i need to check if a hashmap even if less efficient could be better.
struct dfa_table {
    __u32 transitions[MAX_TRANSITIONS];
};

//contains the dfa_tables associated with an index
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FILTERS);
    __type(key, __u32);
    __type(value, struct dfa_table);
} dfa_array SEC(".maps");

//contains the single ports and an index.
//in the future i should implement a way to connect more ports to the same 
//array index reusing dfas.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    //port
    __type(value, __u32); // index into dfa_array 
    __uint(max_entries, 256);
} managed_ports SEC(".maps");

SEC("tc")
int judge(struct __sk_buff *skb) {

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // sanity check to make the checker happy
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return PASS;

    //making eth headder
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return PASS;

    //making ip headder
    struct iphdr *iph = (void *)data + sizeof(struct ethhdr);
    if (iph->protocol != IPPROTO_TCP)
        return PASS;
   
    //ihl is in words, so to know the bytes it needs to be multiplied
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > 60) //a ip headder cannot be bigger then 60 bytes
        return PASS;

    //making tcp headder
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end)
        return PASS;

    // Port check,if not present the lookup returns null
    __u32 port = bpf_htons(tcph->dest);
    __u32 *dfa_index_ptr = bpf_map_lookup_elem(&managed_ports, &port);
    if (!dfa_index_ptr) {
        return PASS;
    }
    __u32 dfa_index = *dfa_index_ptr;

    __u32 tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || tcp_hdr_len > 60)
        return PASS;

    // there seams to be a function called TFO that adds content to syn packets
    // so better to check directly the flags instead of the content.
    if (tcph->syn || tcph->rst || tcph->fin)
        return PASS;

    __u32 total_hdr_len = sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len;
    if (skb->len <= total_hdr_len)
        return PASS;

    __u32 payload_len = skb->len - total_hdr_len;
    if (payload_len > MAX_PAYLOAD_LEN) {
        payload_len = MAX_PAYLOAD_LEN;
    }
    
    __u32 current_state = 1;
    int matched = 0; 
    int i;
    __u32 match_index = 0;

    struct dfa_table *table = bpf_map_lookup_elem(&dfa_array, &dfa_index);
    if (!table) {
        return PASS;
    }

    //takes chunks of 256 bytes 256 times (64kb is ip max size)
    bpf_for(i, 0, 256) {
        __u32 offset = total_hdr_len + (i * 256);
        if (offset >= total_hdr_len + payload_len) {
            break;
        }

        __u32 remaining = total_hdr_len + payload_len - offset;
        // I had to add volatile because clang is too smart for its own
        // good and optimized away the sanity checks below. The checker
        // is stupid as f
        volatile __u32 please_let_me_be = remaining;
        __u32 bytes_to_read = please_let_me_be;
        if (bytes_to_read > 256) {
            bytes_to_read = 256;
        }
        if (bytes_to_read == 0) {
            break;
        }

        __u8 buf[256];
        if (bpf_skb_load_bytes(skb, offset, buf, bytes_to_read) < 0) {
            break;
        }

        int dfa_failed = 0;
        for (int j = 0; j < 256; j++) {
            if (j >= bytes_to_read) break;
            __u8 byte = buf[j];

            __u32 key = (current_state << 8) | byte;
            if (key >= MAX_TRANSITIONS) {
                dfa_failed = 1;
                break;
            }

            __u32 val = table->transitions[key];
            if (val == 0) {
                dfa_failed = 1;
                break;
            }

            current_state = val & 0x7FFFFFFF;
            if (val & 0x80000000) {
                matched = 1;
                match_index = (i * 256) + j;
                break;
            }
        }

        if (dfa_failed || matched) {
            break;
        }
    }

    if (matched) {
        // logging stuff
        struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->port = port;
            
            __u32 len_to_copy = match_index + 1;
            if (len_to_copy > 20) {
                len_to_copy = 20;
            }
            len_to_copy &= 31;
            e->match_len = len_to_copy;

            __builtin_memset(e->matched_payload, 0, MAX_LOG_PAYLOAD);
            for (int j = 0; j < 20; j++) {
                if (j >= len_to_copy) break;
                __u8 byte = 0;
                bpf_skb_load_bytes(skb, total_hdr_len + j, &byte, 1);
                e->matched_payload[j] = byte;
            }
            e->matched_payload[len_to_copy] = '\0';
            
            bpf_ringbuf_submit(e, 0); 
        }

        return DROP;

        // The next part was done with an LLM because i am too stupid to write
        // a TCP packet from zero.

        //rst packets dont have a payload so we will truncate the data
        __u32 actual_payload_len = skb->len - total_hdr_len;
        struct tcphdr *orig_tcph = data + sizeof(struct ethhdr) + ip_hdr_len;
        if ((void *)(orig_tcph + 1) > data_end) {
            return DROP;
        }
        __u32 orig_seq = bpf_ntohl(orig_tcph->seq);
        __u32 orig_ack = bpf_ntohl(orig_tcph->ack_seq);
        
        //Trucnating till tcp data region (not included)
        if (bpf_skb_change_tail(skb, 54, 0) < 0) {
            return DROP;
        }
        
        // 3. Re-derive pointers (MANDATORY after bpf_skb_change_tail)
        void *d = (void *)(long)skb->data;
        void *d_end = (void *)(long)skb->data_end;
        if (d + 54 > d_end) {
            return DROP;
        }
        
        struct ethhdr *eth_new = d;
        struct iphdr *iph_new = d + sizeof(struct ethhdr);
        struct tcphdr *tcph_new = d + sizeof(struct ethhdr) + sizeof(struct iphdr);
        
        // 4. Swap MACs
        __u8 tmp_mac[6]; // ETH_ALEN is 6
        __builtin_memcpy(tmp_mac, eth_new->h_source, 6);
        __builtin_memcpy(eth_new->h_source, eth_new->h_dest, 6);
        __builtin_memcpy(eth_new->h_dest, tmp_mac, 6);
        
        // 5. Swap IPs and update length
        __u32 tmp_ip = iph_new->saddr;
        iph_new->saddr = iph_new->daddr;
        iph_new->daddr = tmp_ip;
        
        iph_new->ihl = 5;
        iph_new->tot_len = bpf_htons(40); // 20 IP + 20 TCP
        iph_new->check = 0; 
        
        // Calculate IP checksum
        __u32 ip_csum = 0;
        __u16 *ip_ptr = (__u16 *)iph_new;
        #pragma clang loop unroll(full)
        for (int j = 0; j < 10; j++) {
            ip_csum += ip_ptr[j];
        }
        ip_csum = (ip_csum & 0xffff) + (ip_csum >> 16);
        ip_csum = (ip_csum & 0xffff) + (ip_csum >> 16);
        iph_new->check = ~ip_csum;
        
        // 6. Swap Ports
        __u16 tmp_port = tcph_new->source;
        tcph_new->source = tcph_new->dest;
        tcph_new->dest = tmp_port;
        
        // 7. Update TCP Flags and Sequence
        tcph_new->doff = 5;
        tcph_new->seq = bpf_htonl(orig_ack);
        tcph_new->ack_seq = bpf_htonl(orig_seq + actual_payload_len);
        
        tcph_new->res1 = 0;
        tcph_new->fin = 0;
        tcph_new->syn = 0;
        tcph_new->rst = 1;
        tcph_new->psh = 0;
        tcph_new->ack = 1;
        tcph_new->urg = 0;
        tcph_new->ece = 0;
        tcph_new->cwr = 0;
        
        tcph_new->window = 0;
        tcph_new->check = 0;
        tcph_new->urg_ptr = 0;
        
        // 8. Calculate TCP Checksum
        __u32 tcp_csum = 0;
        // Pseudo header
        tcp_csum += (iph_new->saddr >> 16) & 0xFFFF;
        tcp_csum += iph_new->saddr & 0xFFFF;
        tcp_csum += (iph_new->daddr >> 16) & 0xFFFF;
        tcp_csum += iph_new->daddr & 0xFFFF;
        tcp_csum += bpf_htons(IPPROTO_TCP);
        tcp_csum += bpf_htons(20);
        
        // TCP header
        __u16 *tcp_ptr = (__u16 *)tcph_new;
        #pragma clang loop unroll(full)
        for (int j = 0; j < 10; j++) {
            tcp_csum += tcp_ptr[j];
        }
        
        tcp_csum = (tcp_csum & 0xffff) + (tcp_csum >> 16);
        tcp_csum = (tcp_csum & 0xffff) + (tcp_csum >> 16);
        tcph_new->check = ~tcp_csum;
        
        // 9. Redirect packet out the same interface
        return bpf_redirect(skb->ifindex, 0);
    }

    return PASS;
}

char LICENSE[] SEC("license") = "GPL";
