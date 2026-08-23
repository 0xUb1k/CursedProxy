#ifndef ENGINE_GLOBALS_H
#define ENGINE_GLOBALS_H

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/cursed_engine.skel.h" 

extern struct cursed_engine_bpf *skel;
extern int tc_hook_ifindex;
extern struct ring_buffer *rb;

extern void (*python_event_callback)(int, int, const char*);
extern void (*python_log_callback)(int, const char*);

void c_log(int level, const char *fmt, ...);

#endif // ENGINE_GLOBALS_H
