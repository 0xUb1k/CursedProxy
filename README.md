# cursed-proxy

A highly cursed, eBPF-based TCP proxy meant for Attack & Defence CTF competitions (or just messing around with kernel stuff). 

Instead of routing packets to userspace, `cursed-proxy` compiles your regex rules into Deterministic Finite Automata and injects them directly into the Linux kernel using eBPF maps. It reads your packets byte-by-byte at the socket layer and silently drops malicious payloads before your CTF services even know they exist.

## Why?
Honestly? I really needed an excuse to learn how eBPF filters work, and I needed an excuse to write a TCP proxy too. This is still a fun side-project and definitely not production-tested, so use it carefully!

## TODOs
* [ ] When a DFA gets updated there is a time interval where no rule is applied to that specific port. We absolutely don't want this.
* [ ] Handle fragmented packets correctly (right now, if a payload is split across two packets like `[GET /a][dmin]`, the DFA resets and it slips through)
* [ ] Make the DFA state-machine parsing faster
* [ ] Allow injecting custom replacement payloads instead of just dropping

## How to use it

### Requirements
* A relatively modern Linux Kernel (with BTF enabled, most are nowadays)
* Python 3.8+

### Installation
I've already included the pre-compiled, CO-RE compatible `libcursed_proxy.so` in the repo:

```bash
git clone https://github.com/0xUb1k/CursedProxy.git
cd CursedProxy
pip install .
```
*(If you don't trust my `.so` file, you can easily compile it from source. See the section at the bottom).*

### Running the Proxy

1. Create a plain text config file (like `proxy.conf`). Each line maps a listening port to a regex string you want to ban.

```text
# proxy.conf
# Format: <PORT>: <REGEX>

1234: .*dropme.*
8080: GET /admin.*
```

> **Note on Regex Rules:** 
> `cursed-proxy` uses `pyformlang` to compile your regex into a pure mathematical DFA.
> * **Supported Syntax:** Standard formal regex features work perfectly. You can use `.` (any char), `*` (0 or more), `+` (1 or more), `?` (0 or 1), `|` (OR), `()` (Grouping), character classes like `[a-zA-Z]` or `\d`, and quantifiers like `a{1,3}`.
> The eBPF kernel program evaluates rules starting from the very first byte of the TCP payload. This means a rule like `GET /admin.*` automatically acts as a "starts-with" rule. If you want to match a string anywhere inside the payload, you must explicitly prefix it with `.*` (e.g., `.*dropme.*`).

2. Run the proxy as root:
```bash
sudo cursed-proxy -c proxy.conf
```

That's it! The proxy watches `proxy.conf` in the background. If you edit and save the file, it will instantly compile the new regex and hot-reload the eBPF maps without dropping any active connections.

---

## Building from Source

If you want to hack on the eBPF C code (`bpf/cursed_proxy.bpf.c`) or you just don't trust my pre-compiled binaries, you'll need the eBPF build toolchain.

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install clang llvm make gcc libbpf-dev libelf-dev zlib1g-dev bpftool
```

**Arch Linux:**
```bash
sudo pacman -S clang llvm make gcc libbpf libelf zlib bpf
```

**To build:**
```bash
make clean
make
```
This dumps your kernel's BTF to `vmlinux.h`, compiles the eBPF object, generates the C skeleton, and spits out a fresh `libcursed_proxy.so` shared library.

## Testing
If you're making changes and want to run the test suite (requires root for the integration tests):
```bash
pip install -e .[dev]
sudo pytest tests/
```
