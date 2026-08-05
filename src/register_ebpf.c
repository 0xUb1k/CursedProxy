#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/cursed_proxy.skel.h" 
#include <fcntl.h>

struct cursed_proxy_bpf *skel = NULL;
int cgroup_fd = -1;
struct bpf_link *sockops_link = NULL;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

void enable_libbpf_logging() {
    libbpf_set_print(libbpf_print_fn);
}

static int libbpf_print_fn_silent(enum libbpf_print_level level, const char *format, va_list args) {
    return 0;
}

void disable_libbpf_logging() {
    libbpf_set_print(libbpf_print_fn_silent);
}

int load_ebpf()
{
    int err;

    skel = cursed_proxy_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = cursed_proxy_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton (err: %d)\n", err);
        cursed_proxy_bpf__destroy(skel);
        skel = NULL;
        return err;
    }

    err = cursed_proxy_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton (err: %d)\n", err);
        cursed_proxy_bpf__destroy(skel);
        skel = NULL;
        return err;
    }

    cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
    if (cgroup_fd < 0) {
        cgroup_fd = open("/sys/fs/cgroup/unified", O_RDONLY);
    }
    if (cgroup_fd >= 0) {
        sockops_link = bpf_program__attach_cgroup(skel->progs.bpf_sockmap, cgroup_fd);
        if (!sockops_link) {
            fprintf(stderr, "Failed to attach sockops to cgroup\n");
        }
    } else {
        fprintf(stderr, "Failed to open cgroup v2 mount for sockops\n");
    }

    int map_fd = bpf_map__fd(skel->maps.sock_hash);
    int parser_fd = bpf_program__fd(skel->progs.police_officer);
    int verdict_fd = bpf_program__fd(skel->progs.judge);
    
    err = bpf_prog_attach(parser_fd, map_fd, BPF_SK_SKB_STREAM_PARSER, 0);
    if (err) {
        fprintf(stderr, "Failed to attach parser to sock_hash map (err: %d)\n", err);
    }
    
    err = bpf_prog_attach(verdict_fd, map_fd, BPF_SK_SKB_STREAM_VERDICT, 0);
    if (err) {
        fprintf(stderr, "Failed to attach verdict to sock_hash map (err: %d)\n", err);
    }

    printf("Successfully attached! Proxy is running...\n");
    return 0;
}

int add_managed_port(unsigned int port)
{
    if (!skel) return -1;
    unsigned int val = 1;
    int fd = bpf_map__fd(skel->maps.managed_ports);
    return bpf_map_update_elem(fd, &port, &val, BPF_ANY);
}

int remove_managed_port(unsigned int port)
{
    if (!skel) return -1;
    int fd = bpf_map__fd(skel->maps.managed_ports);
    return bpf_map_delete_elem(fd, &port);
}

int add_dfa_transition(__u64 key, __u32 val)
{
    if (!skel) return -1;
    int fd = bpf_map__fd(skel->maps.dfa_map);
    return bpf_map_update_elem(fd, &key, &val, BPF_ANY);
}

void unload_ebpf()
{
    if (sockops_link) {
        bpf_link__destroy(sockops_link);
        sockops_link = NULL;
    }
    if (cgroup_fd >= 0) {
        close(cgroup_fd);
        cgroup_fd = -1;
    }
    if (skel) {
        cursed_proxy_bpf__destroy(skel);
        skel = NULL;
    }
}

#ifdef STANDALONE
int main(int argc, char **argv)
{
    enable_libbpf_logging();
    printf("Starting standalone eBPF proxy...\n");

    if (load_ebpf() != 0) {
        fprintf(stderr, "Failed to load eBPF program.\n");
        return 1;
    }

    if (add_managed_port(1234) == 0) {
        printf("Port 1234 added to managed_ports.\n");
    }

    while (1) {
        sleep(1);
    }

    unload_ebpf();
    return 0;
}
#endif
