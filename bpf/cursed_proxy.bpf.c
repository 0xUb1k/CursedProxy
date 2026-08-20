#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#define MAX_LOG_PAYLOAD 32
#define AF_INET 2

#define PASS 0
#define DROP 2

#define ETH_P_IP   0x0800  // IPv4
#define ETH_P_IPV6 0x86DD  // IPv6
#define IPPROTO_TCP  6
struct event {
    __u32 port;
    __u32 match_len;
    char matched_payload[MAX_LOG_PAYLOAD];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct inner_map_type {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);
    __type(value, __u32);
} inner_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 256);
    __type(key, __u32);
    __array(values, struct inner_map_type);
} dfa_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    //port
    __type(value, __u32); // 1 = true, 0 = false 
    __uint(max_entries, 256);
} managed_ports SEC(".maps");

SEC("tc")
int judge(struct __sk_buff *skb) {

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // check both eth and ip headers upfront so verifier bounds the base data pointer
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return PASS;

    struct iphdr *iph = (void *)data + sizeof(struct ethhdr);
    if (iph->protocol != IPPROTO_TCP)
        return PASS; // Not TCP, pass it
    
    __u32 ip_hdr_len = iph->ihl * 4;

    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > 60)
        return PASS;

    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end)
        return PASS;

    //checks if the port is on of out targets
    __u32 port = bpf_htons(tcph->dest);
    __u32 *is_managed = bpf_map_lookup_elem(&managed_ports, &port);
    if (!is_managed || !*is_managed) {
        return PASS; 
    }

    __u32 tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || tcp_hdr_len > 60) 
        return PASS;

    __u32 total_hdr_len = sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len;

    // at this point the packet needs to be checked, so i pull it in a 
    // linear buffer. this is slow so we only want to do it if it is really needed.

    if (bpf_skb_pull_data(skb, skb->len) < 0) {
        return PASS;
    }

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    __u8 *payload = data + total_hdr_len;
    if ((void *)payload > data_end) {
        return PASS;
    }

    __u32 payload_len = (__u8 *)data_end - payload;
    if (payload_len > 65401) { //overkill but the checker is happy so i am happy
        payload_len = 65401;
    }
    __u32 current_state = 1;
    int matched = 0; 
    int i;
    __u32 match_index = 0;
    __u8 byte;

    // DFA map, this could be improved, maybe multiple ports use the same DFA if they can or something
    void *inner_dfa = bpf_map_lookup_elem(&dfa_map, &port);
    if (!inner_dfa) {
        return PASS;
    }

    bpf_for(i, 0, payload_len) {
        void *d = (void *)(long)skb->data;
        void *d_end = (void *)(long)skb->data_end;
        __u8 *ptr = d + total_hdr_len + i;
        
        if ((void *)(ptr + 1) > d_end) {
            break;
        }
        byte = *ptr;
        
        __u32 key = (current_state << 8) | byte;
        __u32 *lookup = bpf_map_lookup_elem(inner_dfa, &key);
        
        if (lookup) {
            __u32 val = *lookup;
            current_state = val & 0x7FFFFFFF;
            if (val & 0x80000000) {
                matched = 1;
                match_index = i;
                break;
            }
        } else {
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

            void *d = (void *)(long)skb->data;
            void *d_end = (void *)(long)skb->data_end;
            __u8 *ptr = d + total_hdr_len;
            
            #pragma clang loop unroll(full)
            for (int j = 0; j < 20; j++) {
                if (j >= len_to_copy) break;
                if ((void *)(ptr + j + 1) > d_end) break;
                e->matched_payload[j] = ptr[j];
            }
            e->matched_payload[len_to_copy] = '\0';
            
            bpf_ringbuf_submit(e, 0); 
        }

        return DROP;
    }

    return PASS;
}

char LICENSE[] SEC("license") = "GPL";
