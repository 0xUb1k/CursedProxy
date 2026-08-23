#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include "engine_globals.h"
#include "cursed_engine.h"

// Define the globals here
struct cursed_engine_bpf *skel = NULL;
int tc_hook_ifindex = -1;

int load_ebpf(int ifindex)
{
    int err;

    skel = cursed_engine_bpf__open();
    if (!skel) {
        c_log(40, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = cursed_engine_bpf__load(skel);
    if (err) {
        c_log(40, "Failed to load and verify BPF skeleton (err: %d)\n", err);
        cursed_engine_bpf__destroy(skel);
        skel = NULL;
        return err;
    }

    err = cursed_engine_bpf__attach(skel);
    if (err) {
        c_log(40, "Failed to attach BPF skeleton (err: %d)\n", err);
        cursed_engine_bpf__destroy(skel);
        skel = NULL;
        return err;
    }

    //ptting the right interface
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    //proxy only connects if no othr priority 1 tc is connected on a specific interfacd
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
        c_log(50, "Failed to attach TC hook: %d\n", attach_err);
        return attach_err;
    }
    
    tc_hook_ifindex = ifindex;

    c_log(20, "Successfully attached! Proxy is running...\n");
    return 0;
}

__attribute__((destructor))
void unload_ebpf(void)
{
    //rb is a global var for the logging ring buf
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
        cursed_engine_bpf__destroy(skel);
        skel = NULL;
    }
}
