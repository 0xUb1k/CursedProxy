#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/cursed_proxy.skel.h" 
#include <fcntl.h>

struct cursed_proxy_bpf *skel = NULL;
int cgroup_fd = -1;
struct bpf_link *cgroup_link = NULL;

struct event {
    __u32 port;
    __u32 match_len;
    char matched_payload[32];
};

static void (*python_event_callback)(int, int, const char*) = NULL;

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    if (python_event_callback) {
        python_event_callback(e->port, e->match_len, e->matched_payload);
    }
    return 0;
}

struct ring_buffer *rb = NULL;

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
        cgroup_link = bpf_program__attach_cgroup(skel->progs.judge, cgroup_fd);
        if (!cgroup_link) {
            fprintf(stderr, "Failed to attach judge to cgroup\n");
        }
    } else {
        fprintf(stderr, "Failed to open cgroup v2 mount\n");
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

int update_port_dfa(unsigned int port, unsigned int *keys, unsigned int *values, unsigned int num_transitions)
{
    if (!skel) return -1;
    
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "inner_dfa", sizeof(__u32), sizeof(__u32), 8192, &opts);
    if (inner_map_fd < 0) {
        perror("bpf_map_create failed");
        return -1;
    }

    for (unsigned int i = 0; i < num_transitions; i++) {
        if (bpf_map_update_elem(inner_map_fd, &keys[i], &values[i], BPF_ANY) != 0) {
            perror("bpf_map_update_elem inner failed");
        }
    }

    int outer_fd = bpf_map__fd(skel->maps.dfa_map);
    int err = bpf_map_update_elem(outer_fd, &port, &inner_map_fd, BPF_ANY);
    if (err != 0) {
        perror("bpf_map_update_elem outer failed");
    }
    
    close(inner_map_fd);
    return err;
}

int remove_port_dfa(unsigned int port)
{
    if (!skel) return -1;
    int fd = bpf_map__fd(skel->maps.dfa_map);
    return bpf_map_delete_elem(fd, &port);
}

int setup_ringbuf(void (*callback)(int, int, const char*)) {
    if (!skel) return -1;
    
    python_event_callback = callback;
    
    if (!rb) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            return -1;
        }
    }
    return 0;
}

int poll_ringbuf(int timeout_ms) {
    if (!rb) return -1;
    return ring_buffer__poll(rb, timeout_ms);
}

void teardown_ringbuf() {
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }
}

void unload_ebpf()
{
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }
    if (cgroup_link) {
        bpf_link__destroy(cgroup_link);
        cgroup_link = NULL;
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
