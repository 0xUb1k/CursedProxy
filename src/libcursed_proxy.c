#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/cursed_proxy.skel.h" 
#include <fcntl.h>

struct cursed_proxy_bpf *skel = NULL;
int tc_hook_ifindex = -1;

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

static void (*python_log_callback)(int, const char*) = NULL;

void setup_c_logging(void (*callback)(int, const char*)) {
    python_log_callback = callback;
}

void c_log(int level, const char *fmt, ...) {
    if (!python_log_callback) {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        return;
    }
    
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    
    python_log_callback(level, buffer);
}

struct ring_buffer *rb = NULL;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    // libbpf levels: 0=warn, 1=info, 2=debug
    int mapped_level = 10; // default INFO
    if (level == LIBBPF_WARN) mapped_level = 30;
    else if (level == LIBBPF_INFO) mapped_level = 20;
    else mapped_level = 10; // DEBUG
    
    if (python_log_callback) {
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), format, args);
        python_log_callback(mapped_level, buffer);
        return 0;
    }
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

int load_ebpf(int ifindex)
{
    int err;

    skel = cursed_proxy_bpf__open();
    if (!skel) {
        c_log(40, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = cursed_proxy_bpf__load(skel);
    if (err) {
        c_log(40, "Failed to load and verify BPF skeleton (err: %d)\n", err);
        cursed_proxy_bpf__destroy(skel);
        skel = NULL;
        return err;
    }

    // Note: We don't use bpf__attach for TC programs usually, but if the skeleton contains
    // other auto-attachable programs, we can keep it. However, since the program is TC,
    // we attach it manually below.
    err = cursed_proxy_bpf__attach(skel);
    if (err) {
        c_log(40, "Failed to attach BPF skeleton (err: %d)\n", err);
        cursed_proxy_bpf__destroy(skel);
        skel = NULL;
        return err;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1, .prog_fd = bpf_program__fd(skel->progs.judge));

    int hook_err = bpf_tc_hook_create(&hook);
    if (hook_err && hook_err != -EEXIST) {
        c_log(40, "Failed to create TC hook: %d\n", hook_err);
        return hook_err;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, query_opts, .handle = 1, .priority = 1);
    if (bpf_tc_query(&hook, &query_opts) == 0) {
        c_log(40, "A judge filter is already attached to this interface!\n");
        return -EEXIST;
    }

    int attach_err = bpf_tc_attach(&hook, &opts);
    if (attach_err) {
        c_log(40, "Failed to attach TC hook: %d\n", attach_err);
        return attach_err;
    }
    
    tc_hook_ifindex = ifindex;

    c_log(20, "Successfully attached! Proxy is running...\n");
    return 0;
}

struct dfa_table {
    __u32 transitions[262144];
};

static int port_to_index[65536];
static int index_in_use[256];
static int globals_initialized = 0;

static void init_globals() {
    if (!globals_initialized) {
        for (int i = 0; i < 65536; i++) port_to_index[i] = -1;
        for (int i = 0; i < 256; i++) index_in_use[i] = 0;
        globals_initialized = 1;
    }
}

static int allocate_index(unsigned int port) {
    init_globals();
    if (port < 65536 && port_to_index[port] != -1) return port_to_index[port];
    for (int i = 0; i < 256; i++) {
        if (!index_in_use[i]) {
            index_in_use[i] = 1;
            if (port < 65536) port_to_index[port] = i;
            return i;
        }
    }
    return -1;
}

static void free_index(unsigned int port) {
    init_globals();
    if (port < 65536) {
        int idx = port_to_index[port];
        if (idx != -1) {
            index_in_use[idx] = 0;
            port_to_index[port] = -1;
        }
    }
}

int add_managed_port(unsigned int port)
{
    if (!skel) return -1;
    int idx = allocate_index(port);
    if (idx == -1) {
        c_log(40, "No free DFA indices available\n");
        return -1;
    }
    int fd = bpf_map__fd(skel->maps.managed_ports);
    unsigned int val = idx;
    return bpf_map_update_elem(fd, &port, &val, BPF_ANY);
}

int remove_managed_port(unsigned int port)
{
    if (!skel) return -1;
    int fd = bpf_map__fd(skel->maps.managed_ports);
    int ret = bpf_map_delete_elem(fd, &port);
    free_index(port);
    return ret;
}

int update_port_dfa(unsigned int port, unsigned int *keys, unsigned int *values, unsigned int num_transitions)
{
    if (!skel) return -1;
    
    int idx = allocate_index(port);
    if (idx == -1) {
        c_log(40, "No free DFA indices available\n");
        return -1;
    }

    struct dfa_table *table = malloc(sizeof(struct dfa_table));
    if (!table) {
        c_log(40, "Failed to allocate DFA table memory\n");
        return -1;
    }
    memset(table, 0, sizeof(struct dfa_table));

    for (unsigned int i = 0; i < num_transitions; i++) {
        unsigned int key = keys[i];
        if (key < 262144) {
            table->transitions[key] = values[i];
        }
    }

    int fd = bpf_map__fd(skel->maps.dfa_array);
    unsigned int map_idx = idx;
    int err = bpf_map_update_elem(fd, &map_idx, table, BPF_ANY);
    if (err != 0) {
        c_log(40, "bpf_map_update_elem dfa_array failed\n");
    }
    free(table);
    
    // Proactively update managed_ports so the index is linked
    int m_fd = bpf_map__fd(skel->maps.managed_ports);
    bpf_map_update_elem(m_fd, &port, &map_idx, BPF_ANY);

    return err;
}

int remove_port_dfa(unsigned int port)
{
    if (!skel) return -1;
    free_index(port);
    return 0;
}

int setup_ringbuf(void (*callback)(int, int, const char*)) {
    if (!skel) return -1;
    
    python_event_callback = callback;
    
    if (!rb) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
        if (!rb) {
            c_log(40, "Failed to create ring buffer\n");
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

__attribute__((destructor))
void unload_ebpf()
{
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }
    if (tc_hook_ifindex >= 0) {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = tc_hook_ifindex, .attach_point = BPF_TC_INGRESS);
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1);
        if (skel) {
            opts.prog_fd = bpf_program__fd(skel->progs.judge);
        }
        bpf_tc_detach(&hook, &opts);
        bpf_tc_hook_destroy(&hook);
        tc_hook_ifindex = -1;
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
    c_log(20, "Starting standalone eBPF proxy...\n");

    if (load_ebpf(1) != 0) {
        c_log(40, "Failed to load eBPF program.\n");
        return 1;
    }

    if (add_managed_port(1234) == 0) {
        c_log(20, "Port 1234 added to managed_ports.\n");
    }

    while (1) {
        sleep(1);
    }

    unload_ebpf();
    return 0;
}
#endif
