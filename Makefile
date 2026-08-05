CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS = -g -O2 -Wall -fPIC
LDFLAGS = -shared -lbpf -lelf -lz
# Important for CO-RE: -g and -target bpf
BPF_CFLAGS = -g -O2 -target bpf

BPF_DIR = bpf
SRC_DIR = src
PY_DIR = cursed_proxy

VMLINUX = $(BPF_DIR)/vmlinux.h
BPF_OBJ = $(BPF_DIR)/cursed_proxy.bpf.o
BPF_SKEL = $(BPF_DIR)/cursed_proxy.skel.h
SHARED_LIB = $(PY_DIR)/libcursed_proxy.so

all: $(SHARED_LIB)

$(VMLINUX):
	@echo "  GEN      $@"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_DIR)/cursed_proxy.bpf.c $(VMLINUX)
	@echo "  CLANG    $@"
	$(CLANG) $(BPF_CFLAGS) -I$(BPF_DIR) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	@echo "  GEN-SKEL $@"
	$(BPFTOOL) gen skeleton $< > $@

$(SHARED_LIB): $(SRC_DIR)/register_ebpf.c $(BPF_SKEL)
	@echo "  CC       $@"
	$(CC) $(CFLAGS) -I$(BPF_DIR) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(VMLINUX) $(BPF_OBJ) $(BPF_SKEL) $(SHARED_LIB)

.PHONY: all clean
