#ifndef CURSED_ENGINE_H
#define CURSED_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

// Logging
void setup_c_logging(void (*callback)(int, const char*));
void enable_libbpf_logging(void);
void disable_libbpf_logging(void);

//eBPF Lifecycle
int load_ebpf(int ifindex);
void unload_ebpf(void);

//DFA Maps
int add_managed_port(unsigned int port);
int remove_managed_port(unsigned int port);
int update_port_dfa(unsigned int port, unsigned int *keys, unsigned int *values, unsigned int num_transitions);
int remove_port_dfa(unsigned int port);

//Events Ringbuffer
int setup_ringbuf(void (*callback)(int, int, const char*));
int poll_ringbuf(int timeout_ms);
void teardown_ringbuf(void);

#ifdef __cplusplus
}
#endif

#endif // CURSED_ENGINE_H
