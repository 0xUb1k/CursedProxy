#include <stdio.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include "engine_globals.h"
#include "cursed_engine.h"

//i am not good enough in C to have written this, thanks gemini for the support
//but at least i commented it

void (*python_log_callback)(int, const char*) = NULL;

//called by the python part
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
