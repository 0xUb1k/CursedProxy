# cursed-proxy

A highly cursed, eBPF-based TCP proxy using Deterministic Finite Automata, meant for Attack & Defence CTF competitions (or just messing around with kernel stuff). 

Instead of routing packets to userspace, `cursed-proxy` compiles your regex rules into DFS and injects them directly into the Linux kernel using eBPF maps. It silently drops malicious payloads before your CTF services even know they exist. It handles iperf3 tests with 44 Gbits/sec of loopback traffic.

## Why?
Honestly? I really needed an excuse to learn how eBPF filters work, and I needed an excuse to write a TCP proxy too. This is still a fun side-project and definitely not production-tested, so use it carefully!

## TODOs
* [ ] Exposing a /metrics endpoint for Prometheus.
* [ ] Forge reset packet to stop connection
* [ ] Handle fragmented packets correctly (right now, if a payload is split across two packets like `[GET /a][dmin]`, the DFA resets and it slips through)
* [ ] Compatibility with ipv6
* [ ] More regex for the same ports could be fused together
* [ ] Compatibility with UDP
* [x] Move to the traffic control layer, this makes forging packets and reading in place possible. 
* [x] Change DFA compiler for faster parsing.
* [x] Integrate libcursed_proxy logging into python logging.

## How to use it

### Requirements
* Linux Kernel v6.4+ (with BTF enabled, most are nowadays)
* Python 3.8+

### Configuration

Create a plain text config file (like `proxy.conf`). Each line maps a listening port to a regex string you want to ban.

```text
# proxy.conf
# Format: <PORT>: <REGEX>

1234: .*dropme.*
8080: GET /admin.*
```

> **Note on Regex Rules:** 
> `cursed-proxy` uses `interegular` to compile your regex into a DFA.
> * **Supported Syntax:** Standard formal regex features work perfectly. You can use `.` (any char), `*` (0 or more), `+` (1 or more), `?` (0 or 1), `|` (OR), `()` (Grouping), character classes like `[a-zA-Z]` or `\d`, and quantifiers like `a{1,3}`.
> * **Unsupported Syntax:** non-regular features like backreferences (e.g., `\1`), conditional matching, and lookarounds are **not** supported.
> 
> The eBPF kernel program evaluates rules starting from the very first byte of the TCP payload. This means a rule like `GET /admin.*` automatically acts as a "starts-with" rule. If you want to match a string anywhere inside the payload, you must explicitly prefix it with `.*` (e.g., `.*dropme.*`).

### Running the Proxy
```bash
git clone https://github.com/0xUb1k/CursedProxy.git
cd CursedProxy

# Using uv
sudo uv run cursed-proxy -c proxy.conf

# Using pip
pip install .
sudo cursed-proxy -c proxy.conf
```
*(If you don't trust my `.so` file, you can easily compile it from source. See the section at the bottom).*

The proxy watches `proxy.conf` in the background. If you edit and save the file, it will instantly compile the new regex.

---

## Building from Source
```bash
#Ubuntu / Debian
sudo apt update
sudo apt install clang llvm make gcc libbpf-dev libelf-dev zlib1g-dev bpftool

#Arch Linux
sudo pacman -S clang llvm make gcc libbpf libelf zlib bpf

#To build
make clean
make
