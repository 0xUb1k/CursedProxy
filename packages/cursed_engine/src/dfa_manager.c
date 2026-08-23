#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "engine_globals.h"
#include "cursed_engine.h"

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

//finds the first suitable slot in the managed_ports map.
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

    //allocate port returns the same idx for the same port
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

    return err;
}

//you can notice that i dont remove the dfa only the 
//connection port - dfa. This is only for efficiency reason.
int remove_port_dfa(unsigned int port)
{
    if (!skel) return -1;
    free_index(port);
    return 0;
}
