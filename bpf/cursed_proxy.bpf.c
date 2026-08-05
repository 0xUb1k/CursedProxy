#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_SCAN_DEPTH 4094 //please god pleasee

/*
 * simply says "everything that arrives must pass :)"
 * this creates a problem with fragmented packets, like packet1: [expl] packet2: [oit]
 * maybe I can make the DFA save its last state or something
*/
SEC("sk_skb")
int police_officer(struct __sk_buff *ctx)
{
    return ctx->len;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 1024 * 256);
} dfa_map SEC(".maps");

SEC("sk_skb")
int judge(struct __sk_buff *ctx) {
  if (bpf_skb_pull_data(ctx, ctx->len) < 0) {
    /*
    * there is a possibility that this function fails, at that point there will be bigger
    * problems then the proxy itself, but to reduce the catastrofy lets make everything pass.
    * also if tcpdump is running the packets will be uncloned by this funciton, could worsen performance a little bit.
    */
    return SK_PASS;
  }

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    unsigned char *payload = data;
    
    __u64 port = ctx->local_port; 
    __u32 current_state = 1;
    int matched = 0;

    for (int i = 0; i < MAX_SCAN_DEPTH; i++) {
        if ((void *)(payload + i + 1) > data_end) {
            break; 
        }
        
        __u64 key = (port << 24) | (current_state << 8) | payload[i];
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
        bpf_printk("Regex matched! Dropping payload.\\n");
        return SK_DROP;
    }

    return SK_PASS;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    //port
    __type(value, __u32); // 1 = true, 0 = false 
    __uint(max_entries, 256);
} managed_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 65535);
} sock_hash SEC(".maps");

/*
* Sockops gets executed for every socket event, bpf_sockmap registers all socket connecions that have the right
* local port. Userspace hooks the above functions to this map. 
* In the future I could add more sock_hash maps for different stuff, or use tail functions, i'm to incompetent for this decision.
*/
SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
  __u32 op = skops->op;
   
  //BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB for outgoing traffic,
  //could be interesting for msg modification
  if (op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        
    unsigned long local_p = skops->local_port;
    
    char *is_managed_local = bpf_map_lookup_elem(&managed_ports, &local_p);
    
    if (is_managed_local && *is_managed_local) {
      //to remember that this packet needs to be proxied later
      __u64 cookie = bpf_get_socket_cookie(skops);
      bpf_sock_hash_update(skops, &sock_hash, &cookie, BPF_NOEXIST);
    }
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
