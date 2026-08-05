#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_SCAN_DEPTH 2048 //please god pleasee
#define MAX_LOG_PAYLOAD 32
#define AF_INET 2

#define PASS 0
#define DROP 1

struct event {
    __u32 port;
    __u32 match_len;
    char matched_payload[MAX_LOG_PAYLOAD];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 1024 * 256);
} dfa_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    //port
    __type(value, __u32); // 1 = true, 0 = false 
    __uint(max_entries, 256);
} managed_ports SEC(".maps");

SEC("cgroup_skb/ingress")
int judge(struct __sk_buff *ctx) {

    //we do not like ipv6
    if (ctx->family != AF_INET) return 1;

    //casting to ipv4 and checking if it is tcp
    struct iphdr iph;
    if (bpf_skb_load_bytes(ctx, 0, &iph, sizeof(iph)) < 0) return 1;
    if (iph.protocol != IPPROTO_TCP) return 1;
    
    __u8 *ip_bytes = (__u8 *)&iph;
    __u32 ip_len = (ip_bytes[0] & 0x0F) * 4;

    //casting to tcp
    struct tcphdr tcph;
    if (bpf_skb_load_bytes(ctx, ip_len, &tcph, sizeof(tcph)) < 0) return 1;
    
    __u8 *tcp_bytes = (__u8 *)&tcph;
    __u32 tcp_len = (tcp_bytes[12] >> 4) * 4;

    //checks if the port is on of out targets
    __u32 port = __builtin_bswap16(tcph.dest);
    __u32 *is_managed = bpf_map_lookup_elem(&managed_ports, &port);
    if (!is_managed || !*is_managed) {
        return PASS; 
    }

    __u32 payload_offset = ip_len + tcp_len;
    if (ctx->len <= payload_offset) {
        return PASS;
    }
    __u32 payload_len = ctx->len - payload_offset;

    __u32 scan_limit = payload_len;
    if (scan_limit > MAX_SCAN_DEPTH) {
        scan_limit = MAX_SCAN_DEPTH;
    }

    __u32 current_state = 1;
    int matched = 0; 
    int i;
    __u8 byte;

    // DFA execution
    for (i = 0; i < MAX_SCAN_DEPTH; i++) {
        if (i >= payload_len) break;
        
        if (bpf_skb_load_bytes(ctx, payload_offset + i, &byte, 1) < 0) break;
        
        __u64 key = (((__u64)port) << 24) | (((__u64)current_state) << 8) | byte;
        __u32 *lookup = bpf_map_lookup_elem(&dfa_map, &key);
        
        if (lookup) {
            __u32 val = *lookup;
            current_state = val & 0x7FFFFFFF;
            if (val & 0x80000000) {
                matched = 1;
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
            
            __u32 len_to_copy = i + 1;
            if (len_to_copy > 20) {
                len_to_copy = 20;
            }
            len_to_copy &= 31;
            e->match_len = len_to_copy;
            
            // Re-read the matched portion into the event buffer safely
            bpf_skb_load_bytes(ctx, payload_offset, e->matched_payload, len_to_copy);
            e->matched_payload[len_to_copy] = '\0';
            
            bpf_ringbuf_submit(e, 0); 
        }
        return DROP;
    }

    return PASS;
}

char LICENSE[] SEC("license") = "GPL";
