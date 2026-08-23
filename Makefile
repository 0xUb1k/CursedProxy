CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS = -g -O2 -Wall -fPIC
LDFLAGS = -shared -lbpf -lelf -lz
BPF_CFLAGS = -g -O2 -target bpf

BPF_DIR = packages/cursed_engine/bpf
SRC_DIR = packages/cursed_engine/src
PY_DIR = packages/cursed_engine/cursed_engine

VMLINUX = $(BPF_DIR)/vmlinux.h
BPF_OBJ = $(BPF_DIR)/cursed_engine.bpf.o
BPF_SKEL = $(BPF_DIR)/cursed_engine.skel.h
SHARED_LIB = $(PY_DIR)/libcursed_engine.so

all: $(SHARED_LIB)

$(VMLINUX):
	@echo "  GEN      $@"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_DIR)/cursed_engine.bpf.c $(VMLINUX)
	@echo "  CLANG    $@"
	$(CLANG) $(BPF_CFLAGS) -I$(BPF_DIR) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	@echo "  GEN-SKEL $@"
	$(BPFTOOL) gen skeleton $< > $@

C_SRCS = $(wildcard $(SRC_DIR)/*.c)

$(SHARED_LIB): $(C_SRCS) $(BPF_SKEL)
	@echo "  CC       $@"
	$(CC) $(CFLAGS) -I$(BPF_DIR) $(C_SRCS) -o $@ $(LDFLAGS)

clean:
	rm -f $(VMLINUX) $(BPF_OBJ) $(BPF_SKEL) $(SHARED_LIB)

test: all
	@echo "  TEST     Unit tests"
	PYTHONPATH=packages/cursed_proxy:packages/cursed_engine uv run pytest packages/cursed_proxy/tests/test_proxy.py packages/cursed_engine/tests/test_engine.py

test-integration: all
	@echo "  TEST     Integration tests (requires root)"
	sudo PYTHONPATH=packages/cursed_proxy:packages/cursed_engine .venv/bin/pytest packages/cursed_engine/tests/test_ebpf_integration.py

.PHONY: all clean test test-integration
