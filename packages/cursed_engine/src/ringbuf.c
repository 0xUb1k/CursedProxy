#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stddef.h>
#include "engine_globals.h"
#include "cursed_engine.h"

struct event {
    __u32 port;
    __u32 match_len;
    char matched_payload[32];
};

struct ring_buffer *rb = NULL;
void (*python_event_callback)(int, int, const char*) = NULL;

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    if (python_event_callback) {
        python_event_callback(e->port, e->match_len, e->matched_payload);
    }
    return 0;
}

int setup_ringbuf(void (*callback)(int, int, const char*)) {
    if (!skel) return -1;
   
    //global var
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
