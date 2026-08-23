"""
benchmark_deep.py — Low-level hardware and kernel metric benchmark for cursed-proxy.

Collects 10 metric categories for each iperf3 scenario:
  1.  perf stat  — hardware PMU counters (cache misses, IPC, TLB, branches…)
  2.  bpftool    — BPF program invocations, total runtime, avg latency/packet
  3.  tc qdisc   — TC-layer packet/byte/drop counters for the clsact hook
  4.  /proc/net/dev — kernel NIC counters for the loopback interface
  5.  CPU freq   — per-core frequency and thermal throttle check
  6.  Thermal    — CPU temperature via /sys/class/thermal
  7.  perf trace — syscall profile (epoll, bpf, futex overhead)
  8.  /proc/<pid>/status — process memory (VmRSS, VmPeak)
  9.  iperf3 extended JSON — per-interval Gbps, jitter, CPU%, retransmits
  10. DFA complexity — states, transitions, map density (static analysis)

Does NOT touch benchmark.py, the PNG graph, or benchmark_results.txt.

Usage (must be run as root):
    sudo python tests/benchmark_deep.py [options]
"""

import argparse
import json
import multiprocessing
import os
import re
import subprocess
import sys
import textwrap
import threading
import time
from datetime import datetime
from pathlib import Path

import iperf3

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_PORT = 5201
DEFAULT_TIME = 10
DEFAULT_WARMUP = 3
DEFAULT_PATTERN = ".*findme.*"
PROXY_CONF = "benchmark_deep_proxy.conf"
LOOPBACK_IFACE = "lo"


# ===========================================================================
# iperf3 helpers
# ===========================================================================

def run_iperf_server(port):
    """Run iperf3 server in an infinite loop (runs in a subprocess)."""
    while True:
        server = iperf3.Server()
        server.port = port
        server.run()
        del server


def run_iperf_warmup(port, duration, blksize=None):
    """Short iperf3 run to warm up kernel caches — result is discarded."""
    cmd = ["iperf3", "-c", "127.0.0.1", "-p", str(port), "-t", str(duration), "-Z"]
    if blksize:
        cmd.extend(["-M", str(blksize)])
    subprocess.run(cmd, capture_output=True, text=True)
    time.sleep(1)


def run_iperf_client_extended(port, duration, blksize=None):
    """
    Run iperf3 and return a rich result dict parsed from the full JSON output.

    Keys:
      bps, sender_cpu, receiver_cpu, retransmits,
      interval_bps, bps_stddev, bps_min, bps_max,
      elapsed_s, bytes_sent, raw
    """
    cmd = ["iperf3", "-c", "127.0.0.1", "-p", str(port), "-t", str(duration), "-J"]
    if blksize:
        cmd.extend(["-M", str(blksize)])

    res = subprocess.run(cmd, capture_output=True, text=True)
    time.sleep(1)

    result = {
        "bps": 0, "sender_cpu": 0.0, "receiver_cpu": 0.0,
        "retransmits": 0, "interval_bps": [], "bps_stddev": 0.0,
        "bps_min": 0.0, "bps_max": 0.0, "elapsed_s": 0.0,
        "bytes_sent": 0, "raw": {},
    }

    if res.returncode != 0:
        print(f"  [iperf3 error] {res.stderr.strip()}", file=sys.stderr)
        return result

    try:
        data = json.loads(res.stdout)
        result["raw"] = data
        end = data.get("end", {})

        sent = end.get("sum_sent", {})
        result["bps"] = sent.get("bits_per_second", 0)
        result["elapsed_s"] = sent.get("seconds", 0.0)
        result["bytes_sent"] = sent.get("bytes", 0)

        cpu = end.get("cpu_utilization_percent", {})
        result["sender_cpu"] = cpu.get("host_total", 0.0)
        result["receiver_cpu"] = cpu.get("remote_total", 0.0)

        for stream in end.get("streams", []):
            result["retransmits"] += stream.get("sender", {}).get("retransmits", 0)

        intervals = [
            iv["sum"]["bits_per_second"] / 1e9
            for iv in data.get("intervals", [])
            if "sum" in iv
        ]
        result["interval_bps"] = intervals
        if intervals:
            n = len(intervals)
            mean = sum(intervals) / n
            variance = sum((x - mean) ** 2 for x in intervals) / n
            result["bps_stddev"] = variance ** 0.5
            result["bps_min"] = min(intervals)
            result["bps_max"] = max(intervals)

    except Exception as exc:
        print(f"  [iperf3 JSON parse error] {exc}", file=sys.stderr)

    return result


# ===========================================================================
# Proxy config
# ===========================================================================

def create_proxy_conf(rules, port, conf_path):
    with open(conf_path, "w") as f:
        for rule in rules:
            f.write(f"{port}: {rule}\n")


# ===========================================================================
# Sampler: perf stat
# ===========================================================================

_PERF_EVENTS = ",".join([
    "cache-misses",
    "cache-references",
    "LLC-load-misses",
    "LLC-loads",
    "branch-misses",
    "branches",
    "instructions",
    "cycles",
    "dTLB-load-misses",
    "iTLB-load-misses",
    "page-faults",
    "context-switches",
    "task-clock",
])

# perf stat line format:  "   1,234,567      cache-misses   # ..."
# The counter value may also be "<not supported>" or "<not counted>".
_PERF_LINE_RE = re.compile(
    r"^\s*([\d,.]+|<not supported>|<not counted>)\s+([-\w:]+)"
)


def _parse_perf_stat(text):
    """
    Parse `perf stat` stderr output into a dict of counter -> value.
    Handles both comma-grouped integers and decimal floats (task-clock).
    """
    counters = {}
    for line in text.splitlines():
        m = _PERF_LINE_RE.match(line)
        if not m:
            continue
        raw_val, name = m.group(1), m.group(2)
        name = name.rstrip(":")
        if raw_val in ("<not supported>", "<not counted>"):
            counters[name] = None
        else:
            clean = raw_val.replace(",", "")
            try:
                # task-clock is a float; everything else is an integer
                counters[name] = float(clean) if "." in clean else int(clean)
            except ValueError:
                counters[name] = None
    return counters


def _check_perf():
    try:
        r = subprocess.run(["perf", "--version"], capture_output=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _read_sysctl_int(key):
    """Read a sysctl integer value, e.g. 'kernel.perf_event_paranoid'."""
    try:
        path = "/proc/sys/" + key.replace(".", "/")
        return int(Path(path).read_text().strip())
    except Exception:
        return None


def _set_sysctl(key, value):
    """Set a sysctl value. Returns the previous value, or None on failure."""
    prev = _read_sysctl_int(key)
    try:
        subprocess.run(
            ["sysctl", "-w", f"{key}={value}"],
            capture_output=True, check=True,
        )
    except Exception:
        pass
    return prev


class PerfStatSampler:
    """
    Collects system-wide hardware PMU counters during the benchmark window
    using `perf stat -a`.

    Why system-wide (-a) instead of --pid:
      The eBPF TC program runs in *kernel* context, not attributed to the
      proxy's userspace PID. Using --pid on the nearly-idle Python process
      would capture almost nothing useful. System-wide mode catches the
      actual CPU cycles burned by the kernel softirq / BPF JIT path.

    Requires kernel.perf_event_paranoid <= 0 (we auto-set and restore it).
    """

    _PARANOID_KEY = "kernel.perf_event_paranoid"

    def __init__(self):
        self._proc = None
        self._result = {}
        self._prev_paranoid = None
        self._available = _check_perf()

    def start(self):
        if not self._available:
            return
        # Ensure paranoid level allows system-wide sampling
        cur = _read_sysctl_int(self._PARANOID_KEY)
        if cur is None or cur > 0:
            self._prev_paranoid = _set_sysctl(self._PARANOID_KEY, 0)
            print(f"  [perf stat] set {self._PARANOID_KEY}=0 (was {cur}), will restore after")
        else:
            self._prev_paranoid = cur  # already fine

        cmd = ["perf", "stat", "-a", "-e", _PERF_EVENTS]
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True,
        )

    def stop(self):
        if not self._available or self._proc is None:
            return {}
        import signal
        # SIGINT causes perf stat to flush its summary cleanly (SIGTERM does not)
        try:
            self._proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            _, stderr = self._proc.communicate(timeout=8)
            self._result = _parse_perf_stat(stderr)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._result = {}

        # Restore paranoid level
        if self._prev_paranoid is not None:
            _set_sysctl(self._PARANOID_KEY, self._prev_paranoid)

        return self._result

    @property
    def available(self):
        return self._available


# ===========================================================================
# Sampler: bpftool prog stats
# ===========================================================================

def _bpf_stats_enabled():
    try:
        val = Path("/proc/sys/kernel/bpf_stats_enabled").read_text().strip()
        return val == "1"
    except Exception:
        return False


def _set_bpf_stats(enable):
    """Toggle kernel.bpf_stats_enabled. Returns previous state."""
    prev = _bpf_stats_enabled()
    val = "1" if enable else "0"
    try:
        subprocess.run(
            ["sysctl", "-w", f"kernel.bpf_stats_enabled={val}"],
            capture_output=True,
        )
    except Exception:
        pass
    return prev


def _bpftool_prog_info(prog_name="judge"):
    """Query bpftool for a loaded BPF program by name."""
    try:
        r = subprocess.run(
            ["bpftool", "prog", "show", "--json"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return {}
        progs = json.loads(r.stdout)
        for prog in progs:
            if prog.get("name", "").startswith(prog_name):
                return {
                    "run_cnt": prog.get("run_cnt", 0),
                    "run_time_ns": prog.get("run_time_ns", 0),
                    "verified_insns": prog.get("verified_insns"),
                    "id": prog.get("id"),
                    "tag": prog.get("tag", ""),
                    "bytes_xlated": prog.get("bytes_xlated"),
                    "bytes_jited": prog.get("bytes_jited"),
                }
    except Exception as exc:
        print(f"  [bpftool error] {exc}", file=sys.stderr)
    return {}


class BpftoolProgSampler:
    """Takes a delta snapshot of BPF prog stats before and after a run."""

    def __init__(self, prog_name="judge"):
        self._name = prog_name
        self._before = {}
        self._after = {}
        self._prev_sysctl = False

    def start(self):
        self._prev_sysctl = _set_bpf_stats(True)
        time.sleep(0.05)
        self._before = _bpftool_prog_info(self._name)

    def stop(self):
        self._after = _bpftool_prog_info(self._name)
        _set_bpf_stats(self._prev_sysctl)

        if not self._before or not self._after:
            return {}

        delta_cnt = self._after.get("run_cnt", 0) - self._before.get("run_cnt", 0)
        delta_ns = self._after.get("run_time_ns", 0) - self._before.get("run_time_ns", 0)

        return {
            "invocations": delta_cnt,
            "total_run_ns": delta_ns,
            "avg_ns_per_call": (delta_ns / delta_cnt) if delta_cnt > 0 else 0,
            "verified_insns": self._after.get("verified_insns"),
            "bytes_xlated": self._after.get("bytes_xlated"),
            "bytes_jited": self._after.get("bytes_jited"),
            "prog_id": self._after.get("id"),
            "prog_tag": self._after.get("tag", ""),
        }


# ===========================================================================
# Sampler: TC qdisc stats
# ===========================================================================

_TC_SENT_RE = re.compile(r"Sent\s+([\d]+)\s+bytes\s+([\d]+)\s+pkt")
_TC_DROP_RE = re.compile(r"dropped\s+([\d]+)")
_TC_OVERLAP_RE = re.compile(r"overlimits\s+([\d]+)")


def _parse_tc_qdisc(text):
    """
    Parse only the clsact section of `tc -s qdisc show dev <iface>` output.

    The root qdisc (noqueue/pfifo_fast) accumulates lifetime counters for ALL
    traffic since boot — we must skip it and read only the clsact ffff: block
    which is the hook our eBPF TC program sits in.
    """
    result = {"bytes": 0, "pkts": 0, "dropped": 0, "overlimits": 0}

    # Locate the clsact block: starts with "qdisc clsact" and ends at the
    # next "qdisc" header line (or EOF).
    in_clsact = False
    for line in text.splitlines():
        if line.startswith("qdisc clsact"):
            in_clsact = True
            continue
        # A new qdisc block starts with "qdisc <name>" — leave clsact section
        if in_clsact and line.startswith("qdisc "):
            break
        if not in_clsact:
            continue

        m = _TC_SENT_RE.search(line)
        if m:
            result["bytes"]   = int(m.group(1))
            result["pkts"]    = int(m.group(2))
        m = _TC_DROP_RE.search(line)
        if m:
            result["dropped"] = int(m.group(1))
        m = _TC_OVERLAP_RE.search(line)
        if m:
            result["overlimits"] = int(m.group(1))

    return result if in_clsact else {}  # return empty if clsact not found


def _tc_qdisc_stats(iface=LOOPBACK_IFACE):
    try:
        r = subprocess.run(
            ["tc", "-s", "qdisc", "show", "dev", iface],
            capture_output=True, text=True,
        )
        return _parse_tc_qdisc(r.stdout)
    except Exception:
        return {}


class TcQdiscSampler:
    def __init__(self, iface=LOOPBACK_IFACE):
        self._iface = iface
        self._before = {}
        self._t_start = 0.0

    def start(self):
        self._before = _tc_qdisc_stats(self._iface)
        self._t_start = time.monotonic()

    def stop(self, elapsed_s=None):
        after = _tc_qdisc_stats(self._iface)
        wall = elapsed_s or (time.monotonic() - self._t_start)

        if not self._before or not after or wall <= 0:
            return {}

        d_pkts = after["pkts"] - self._before["pkts"]
        d_bytes = after["bytes"] - self._before["bytes"]
        d_dropped = after["dropped"] - self._before["dropped"]

        return {
            "pkts_total": d_pkts,
            "bytes_total": d_bytes,
            "dropped": d_dropped,
            "pkt_rate": d_pkts / wall,
            "byte_rate_gbps": (d_bytes * 8) / wall / 1e9,
        }


# ===========================================================================
# Sampler: /proc/net/dev
# ===========================================================================

def _read_net_dev(iface=LOOPBACK_IFACE):
    """Parse /proc/net/dev counters for the given interface."""
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if iface + ":" not in line:
                    continue
                parts = line.split()
                return {
                    "rx_bytes":   int(parts[1]),
                    "rx_packets": int(parts[2]),
                    "rx_errs":    int(parts[3]),
                    "rx_drop":    int(parts[4]),
                    "tx_bytes":   int(parts[9]),
                    "tx_packets": int(parts[10]),
                    "tx_errs":    int(parts[11]),
                    "tx_drop":    int(parts[12]),
                }
    except Exception:
        pass
    return {}


class NetDevSampler:
    def __init__(self, iface=LOOPBACK_IFACE):
        self._iface = iface
        self._before = {}
        self._t_start = 0.0

    def start(self):
        self._before = _read_net_dev(self._iface)
        self._t_start = time.monotonic()

    def stop(self, elapsed_s=None):
        after = _read_net_dev(self._iface)
        wall = elapsed_s or (time.monotonic() - self._t_start)

        if not self._before or not after or wall <= 0:
            return {}

        d = {}
        for key in after:
            d[f"delta_{key}"] = after[key] - self._before.get(key, 0)

        d["rx_pkt_rate"] = d["delta_rx_packets"] / wall
        d["rx_gbps"]     = (d["delta_rx_bytes"] * 8) / wall / 1e9
        d["tx_pkt_rate"] = d["delta_tx_packets"] / wall
        d["tx_gbps"]     = (d["delta_tx_bytes"] * 8) / wall / 1e9
        return d


# ===========================================================================
# Sampler: CPU frequency & temperature
# ===========================================================================

def _read_cpu_freqs_mhz():
    freqs = []
    for cpu_dir in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*")):
        freq_file = cpu_dir / "cpufreq" / "scaling_cur_freq"
        try:
            freqs.append(int(freq_file.read_text().strip()) / 1000.0)
        except Exception:
            pass
    return freqs


def _read_cpu_governor():
    try:
        return Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read_text().strip()
    except Exception:
        return "unknown"


def _read_cpu_temp_celsius():
    temps = []
    try:
        for tz in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
            try:
                temps.append(int((tz / "temp").read_text().strip()) / 1000.0)
            except Exception:
                pass
    except Exception:
        pass
    return temps


class CpuSampler:
    def __init__(self):
        self._samples = []
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._samples = []
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()

    def _sample_loop(self):
        while not self._stop_event.is_set():
            self._samples.append(_read_cpu_freqs_mhz())
            time.sleep(1.0)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

        all_flat = [f for sample in self._samples for f in sample]
        temps = _read_cpu_temp_celsius()

        result = {
            "governor": _read_cpu_governor(),
            "temps_celsius": temps,
            "max_temp_celsius": max(temps) if temps else None,
        }

        if all_flat:
            result["avg_freq_mhz"] = sum(all_flat) / len(all_flat)
            result["min_freq_mhz"] = min(all_flat)
            result["max_freq_mhz"] = max(all_flat)
            result["num_cores_sampled"] = len(self._samples[0]) if self._samples else 0
        else:
            result["avg_freq_mhz"] = None
            result["min_freq_mhz"] = None
            result["max_freq_mhz"] = None
            result["num_cores_sampled"] = 0

        return result


# ===========================================================================
# Sampler: /proc/<pid>/status
# ===========================================================================

def _read_proc_status(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            raw = f.read()
        result = {}
        for line in raw.splitlines():
            if line.startswith(("VmRSS:", "VmPeak:", "VmSize:", "VmSwap:",
                                "Threads:", "voluntary_ctxt_switches:",
                                "nonvoluntary_ctxt_switches:")):
                key, _, val = line.partition(":")
                val = val.strip()
                if val.endswith(" kB"):
                    result[key] = int(val[:-3])
                else:
                    try:
                        result[key] = int(val)
                    except ValueError:
                        result[key] = val
        return result
    except Exception:
        return {}


class ProcStatusSampler:
    def __init__(self, pid):
        self._pid = pid
        self._before = {}

    def start(self):
        self._before = _read_proc_status(self._pid)

    def stop(self):
        after = _read_proc_status(self._pid)
        return {"before": self._before, "after": after}


# ===========================================================================
# Sampler: perf trace (syscall summary)
# ===========================================================================

def _parse_perf_trace_summary(text):
    """
    Parse `perf trace --summary` output into a list of dicts.
    Returns list of {syscall, calls, total_ms, avg_ms} sorted by total_ms desc.
    """
    syscalls = []
    header_seen = False
    for line in text.splitlines():
        stripped = line.strip()
        if "syscall" in stripped.lower() and "calls" in stripped.lower():
            header_seen = True
            continue
        if not header_seen:
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        try:
            name   = parts[0]
            calls  = int(parts[1])
            total_ms = _parse_time_str_ms(parts[2])
            avg_ms   = _parse_time_str_ms(parts[4]) if len(parts) > 4 else 0.0
            syscalls.append({"syscall": name, "calls": calls,
                             "total_ms": total_ms, "avg_ms": avg_ms})
        except (ValueError, IndexError):
            continue
    return sorted(syscalls, key=lambda x: x["total_ms"], reverse=True)


def _parse_time_str_ms(s):
    s = s.strip()
    try:
        if s.endswith("ms"):
            return float(s[:-2])
        elif s.endswith("us"):
            return float(s[:-2]) / 1000.0
        elif s.endswith("s"):
            return float(s[:-1]) * 1000.0
        return float(s)
    except ValueError:
        return 0.0


class PerfTraceSampler:
    """
    Runs `perf trace --summary --pid <pid>` alongside the iperf3 run to
    produce a syscall frequency profile for the proxy process.

    Requires kernel.yama.ptrace_scope <= 1 when running as root (we
    auto-set it to 0 and restore it afterward).
    """

    _PTRACE_KEY = "kernel.yama.ptrace_scope"

    def __init__(self, pid):
        self._pid = pid
        self._proc = None
        self._prev_ptrace = None
        self._available = _check_perf()

    def start(self):
        if not self._available or not self._pid:
            return
        # Ensure ptrace scope allows attaching
        cur = _read_sysctl_int(self._PTRACE_KEY)
        if cur is not None and cur > 0:
            self._prev_ptrace = _set_sysctl(self._PTRACE_KEY, 0)
            print(f"  [perf trace] set {self._PTRACE_KEY}=0 (was {cur}), will restore after")
        else:
            self._prev_ptrace = cur

        cmd = ["perf", "trace", "--pid", str(self._pid), "--summary"]
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

    def stop(self):
        if not self._available or self._proc is None:
            return []
        import signal
        # SIGINT flushes the summary; SIGTERM causes perf trace to exit silently
        try:
            self._proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            stdout, _ = self._proc.communicate(timeout=8)
            result = _parse_perf_trace_summary(stdout)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            result = []

        # Restore ptrace scope
        if self._prev_ptrace is not None:
            _set_sysctl(self._PTRACE_KEY, self._prev_ptrace)

        return result

    @property
    def available(self):
        return self._available


# ===========================================================================
# Sampler: /proc/softirqs
# ===========================================================================

def _read_softirq_net(kind="NET_RX"):
    try:
        with open("/proc/softirqs") as f:
            for line in f:
                if line.strip().startswith(kind + ":"):
                    return [int(x) for x in line.split()[1:]]
    except Exception:
        pass
    return []


class SoftirqSampler:
    def __init__(self):
        self._before_rx = []
        self._before_tx = []

    def start(self):
        self._before_rx = _read_softirq_net("NET_RX")
        self._before_tx = _read_softirq_net("NET_TX")

    def stop(self):
        after_rx = _read_softirq_net("NET_RX")
        after_tx = _read_softirq_net("NET_TX")
        result = {}

        if after_rx and self._before_rx:
            delta = [a - b for a, b in zip(after_rx, self._before_rx)]
            result["net_rx_per_cpu"] = delta
            result["net_rx_total"]   = sum(delta)
            result["net_rx_max_cpu"] = max(delta)
            result["net_rx_imbalance_pct"] = (
                (max(delta) - min(delta)) / max(delta) * 100.0
                if max(delta) > 0 else 0.0
            )

        if after_tx and self._before_tx:
            delta = [a - b for a, b in zip(after_tx, self._before_tx)]
            result["net_tx_per_cpu"] = delta
            result["net_tx_total"]   = sum(delta)

        return result


# ===========================================================================
# DFA complexity analysis
# ===========================================================================

def collect_dfa_stats(pattern):
    """
    Import interegular directly (same lib the proxy uses) and compile the pattern
    to extract static DFA complexity metrics. Does not require the proxy to be running.
    """
    result = {
        "pattern": pattern,
        "states": None, "transitions": None, "map_density_pct": None,
        "accept_states": None, "alphabet_classes": None,
        "compile_time_ms": None, "error": None,
    }
    try:
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
        import interegular

        t0 = time.monotonic()
        parsed = interegular.parse_pattern(pattern)
        fsm = parsed.to_fsm()
        compile_ms = (time.monotonic() - t0) * 1000.0

        states = list(fsm.states)
        state_to_idx = {s: i for i, s in enumerate(states)}

        # Reproduce the exact key-generation logic from proxy.py
        byte_to_symbol = {}
        anything_else_sym = None
        for symbol_id, chars in fsm.alphabet._by_transition.items():
            for char in chars:
                try:
                    if char is interegular.fsm.anything_else:
                        anything_else_sym = symbol_id
                    else:
                        byte_to_symbol[ord(char)] = symbol_id
                except (TypeError, AttributeError):
                    anything_else_sym = symbol_id

        for b in range(256):
            if b not in byte_to_symbol and anything_else_sym is not None:
                byte_to_symbol[b] = anything_else_sym

        keys = []
        for state, transitions in fsm.map.items():
            src_idx = state_to_idx[state]
            for byte_val in range(256):
                sym_id = byte_to_symbol.get(byte_val)
                if sym_id is not None and sym_id in transitions:
                    keys.append((src_idx << 8) | byte_val)

        MAX_TRANSITIONS = 262144
        result.update({
            "states":           len(states),
            "transitions":      len(keys),
            "map_density_pct":  len(keys) / MAX_TRANSITIONS * 100.0,
            "accept_states":    len(fsm.finals),
            "alphabet_classes": len(fsm.alphabet._by_transition),
            "compile_time_ms":  compile_ms,
        })

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ===========================================================================
# BPF map info
# ===========================================================================

def collect_bpf_map_info():
    """Return info about cursed-proxy BPF maps via bpftool."""
    _OUR_MAPS = {"dfa_array", "managed_ports", "rb"}
    try:
        r = subprocess.run(
            ["bpftool", "map", "show", "--json"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return []
        maps = json.loads(r.stdout)
        return [
            {
                "id":           m.get("id"),
                "name":         m.get("name", "?"),
                "type":         m.get("type", "?"),
                "bytes_memlock": m.get("bytes_memlock", 0),
                "max_entries":  m.get("max_entries", 0),
                "key_size":     m.get("key_size", 0),
                "value_size":   m.get("value_size", 0),
            }
            for m in maps
            if m.get("name") in _OUR_MAPS
        ]
    except Exception:
        return []


# ===========================================================================
# Scenario runner — orchestrates all samplers for a single iperf3 run
# ===========================================================================

def run_scenario(label, iperf_port, duration, blksize, proxy_pid, args):
    """Run one iperf3 scenario with all samplers active. Returns a data dict."""

    # Instantiate samplers
    perf_stat     = PerfStatSampler() if not args.no_perf_stat else None
    bpf_sampler   = BpftoolProgSampler() if proxy_pid else None
    netdev        = NetDevSampler(args.iface)
    tc_qdisc      = TcQdiscSampler(args.iface)
    cpu_sampler   = CpuSampler()
    softirq       = SoftirqSampler()
    proc_mem      = ProcStatusSampler(proxy_pid) if proxy_pid else None
    perf_trace    = PerfTraceSampler(proxy_pid)  if proxy_pid and args.syscall_profile else None

    # Start samplers
    netdev.start();    tc_qdisc.start(); cpu_sampler.start(); softirq.start()
    if proc_mem:   proc_mem.start()
    if perf_stat:  perf_stat.start()
    if bpf_sampler: bpf_sampler.start()
    if perf_trace:  perf_trace.start()

    # Run iperf3
    iperf_result = run_iperf_client_extended(iperf_port, duration, blksize)
    elapsed = iperf_result["elapsed_s"] or float(duration)

    # Stop samplers
    perf_data    = perf_stat.stop()    if perf_stat    else {}
    bpf_data     = bpf_sampler.stop()  if bpf_sampler  else {}
    netdev_data  = netdev.stop(elapsed_s=elapsed)
    tc_data      = tc_qdisc.stop(elapsed_s=elapsed)
    cpu_data     = cpu_sampler.stop()
    softirq_data = softirq.stop()
    proc_data    = proc_mem.stop()     if proc_mem     else {}
    syscall_data = perf_trace.stop()   if perf_trace   else []

    # Derived metrics
    instr  = perf_data.get("instructions")
    cycles = perf_data.get("cycles")
    ipc    = (instr / cycles) if (instr and cycles and cycles > 0) else None

    cache_refs = perf_data.get("cache-references")
    cache_miss = perf_data.get("cache-misses")
    cache_miss_rate = (cache_miss / cache_refs * 100.0) if (cache_refs and cache_miss and cache_refs > 0) else None

    llc_loads = perf_data.get("LLC-loads")
    llc_miss  = perf_data.get("LLC-load-misses")
    llc_miss_rate = (llc_miss / llc_loads * 100.0) if (llc_loads and llc_miss and llc_loads > 0) else None

    branch_total = perf_data.get("branches")
    branch_miss  = perf_data.get("branch-misses")
    branch_miss_rate = (branch_miss / branch_total * 100.0) if (branch_total and branch_miss and branch_total > 0) else None

    bpf_inv = bpf_data.get("invocations", 0)
    bpf_calls_per_sec = bpf_inv / elapsed if (elapsed > 0 and bpf_inv) else None

    return {
        "label": label, "blksize": blksize, "elapsed_s": elapsed,
        "iperf": iperf_result,
        "perf_stat": perf_data,
        "ipc": ipc,
        "cache_miss_rate_pct": cache_miss_rate,
        "llc_miss_rate_pct": llc_miss_rate,
        "branch_miss_rate_pct": branch_miss_rate,
        "bpftool": bpf_data,
        "bpf_calls_per_sec": bpf_calls_per_sec,
        "tc": tc_data,
        "netdev": netdev_data,
        "cpu": cpu_data,
        "softirq": softirq_data,
        "proc_mem": proc_data,
        "syscalls": syscall_data,
    }


# ===========================================================================
# Argument parsing
# ===========================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="cursed-proxy deep hardware+kernel benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Must be run as root (eBPF requires CAP_BPF / CAP_NET_ADMIN).
            Does NOT modify benchmark.py or benchmark_results.png.
        """),
    )
    parser.add_argument("-p", "--port",    type=int, default=DEFAULT_PORT,
                        help=f"iperf3 server port (default: {DEFAULT_PORT})")
    parser.add_argument("-t", "--time",    type=int, default=DEFAULT_TIME,
                        help=f"iperf3 test duration per run in seconds (default: {DEFAULT_TIME})")
    parser.add_argument("-w", "--warmup",  type=int, default=DEFAULT_WARMUP,
                        help=f"warmup duration in seconds (default: {DEFAULT_WARMUP})")
    parser.add_argument("--pattern",       type=str, default=DEFAULT_PATTERN,
                        help=f"DFA regex pattern (default: '{DEFAULT_PATTERN}')")
    parser.add_argument("--out-txt",       type=str, default="benchmark_deep_results.txt",
                        help="Output text report path")
    parser.add_argument("--syscall-profile", action="store_true",
                        help="Enable perf trace syscall profiling (needs perf)")
    parser.add_argument("--no-perf-stat",  action="store_true",
                        help="Skip perf stat hardware counter collection")
    parser.add_argument("--iface",         type=str, default=LOOPBACK_IFACE,
                        help=f"Network interface to monitor (default: {LOOPBACK_IFACE})")
    return parser.parse_args()


# ===========================================================================
# Report writer
# ===========================================================================

def _fmt(val, spec=".2f", unit="", na="N/A"):
    if val is None:
        return na
    return f"{val:{spec}}{unit}"


def _fmt_int(val, unit="", na="N/A"):
    if val is None:
        return na
    try:
        return f"{int(val):,}{unit}"
    except (TypeError, ValueError):
        return na


def _kv(lines, label, value, width=30):
    lines.append(f"  {label:<{width}} {value}")


def _section(lines, title):
    lines.append(f"\n[{title}]")


def build_scenario_block(data, args):
    lines = []
    blk = f"{data['blksize']}B" if data["blksize"] else "Max (64KB)"
    lines.append(f"\n{'─' * 64}")
    lines.append(f"  Packet size: {blk:<10}  |  Elapsed: {data['elapsed_s']:.1f}s")
    lines.append(f"{'─' * 64}")

    iperf = data["iperf"]
    gbps  = iperf["bps"] / 1e9

    _section(lines, "Throughput")
    _kv(lines, "Throughput:", f"{gbps:.3f} Gbps")
    _kv(lines, "Std dev (1s intervals):", _fmt(iperf["bps_stddev"], unit=" Gbps"))
    _kv(lines, "Min / Max interval:", f"{_fmt(iperf['bps_min'])} / {_fmt(iperf['bps_max'])} Gbps")
    _kv(lines, "Sender CPU%:", _fmt(iperf["sender_cpu"], unit="%"))
    _kv(lines, "Receiver CPU%:", _fmt(iperf["receiver_cpu"], unit="%"))
    _kv(lines, "TCP Retransmits:", _fmt_int(iperf["retransmits"]))
    _kv(lines, "Bytes sent:", _fmt_int(iperf["bytes_sent"], unit=" B"))

    # BPF stats
    bpf = data.get("bpftool", {})
    _section(lines, "BPF Program Stats")
    if bpf:
        _kv(lines, "Invocations:", _fmt_int(bpf.get("invocations")))
        _kv(lines, "Calls/sec:", _fmt_int(data.get("bpf_calls_per_sec"), unit=" pkt/s"))
        _kv(lines, "Avg latency/packet:", _fmt(bpf.get("avg_ns_per_call"), unit=" ns"))
        total_ns = bpf.get("total_run_ns", 0)
        _kv(lines, "Total BPF runtime:", f"{total_ns / 1e9:.3f} s  ({total_ns:,} ns)")
        _kv(lines, "Verified instructions:", _fmt_int(bpf.get("verified_insns")))
        _kv(lines, "Translated (xlated):", _fmt_int(bpf.get("bytes_xlated"), unit=" B"))
        _kv(lines, "JIT compiled:", _fmt_int(bpf.get("bytes_jited"), unit=" B"))
        _kv(lines, "Prog ID / tag:", f"{bpf.get('prog_id', 'N/A')} / {bpf.get('prog_tag', 'N/A')}")
    else:
        lines.append("  (proxy not running or bpftool unavailable)")

    # perf stat
    ps = data.get("perf_stat", {})
    _section(lines, "Hardware Counters (perf stat)")
    if ps:
        def _pc(key, friendly):
            v = ps.get(key)
            _kv(lines, f"{friendly}:", _fmt_int(v) if v is not None else "not supported")

        _pc("instructions",      "Instructions")
        _pc("cycles",            "Cycles")
        _kv(lines, "IPC:", _fmt(data.get("ipc"), ".3f") if data.get("ipc") else "N/A")
        _pc("cache-references",  "Cache references")
        _pc("cache-misses",      "Cache misses")
        cmr = data.get("cache_miss_rate_pct")
        _kv(lines, "Cache miss rate:", _fmt(cmr, unit="%") if cmr is not None else "N/A")
        _pc("LLC-loads",         "LLC loads")
        _pc("LLC-load-misses",   "LLC load misses")
        llc = data.get("llc_miss_rate_pct")
        _kv(lines, "LLC miss rate:", _fmt(llc, unit="%") if llc is not None else "N/A")
        _pc("branches",          "Branches")
        _pc("branch-misses",     "Branch misses")
        bmr = data.get("branch_miss_rate_pct")
        _kv(lines, "Branch miss rate:", _fmt(bmr, unit="%") if bmr is not None else "N/A")
        _pc("dTLB-load-misses",  "dTLB load misses")
        _pc("iTLB-load-misses",  "iTLB load misses")
        _pc("context-switches",  "Context switches")
        _pc("page-faults",       "Page faults")
        task_ms = ps.get("task-clock")
        _kv(lines, "Task clock:", f"{task_ms:,} ms" if task_ms else "N/A")
    else:
        lines.append("  (perf stat not available or disabled via --no-perf-stat)")

    # TC qdisc
    tc = data.get("tc", {})
    _section(lines, "TC Qdisc (lo clsact)")
    if tc:
        _kv(lines, "Packets processed:", _fmt_int(tc.get("pkts_total")))
        _kv(lines, "Bytes processed:", _fmt_int(tc.get("bytes_total"), unit=" B"))
        _kv(lines, "Packet rate:", _fmt_int(tc.get("pkt_rate"), unit=" pkt/s"))
        _kv(lines, "Throughput (TC):", _fmt(tc.get("byte_rate_gbps"), unit=" Gbps"))
        _kv(lines, "TC dropped:", _fmt_int(tc.get("dropped")))
    else:
        lines.append("  (no TC stats — clsact hook may not be attached)")

    # /proc/net/dev
    nd = data.get("netdev", {})
    _section(lines, "Network Interface (/proc/net/dev lo)")
    if nd:
        _kv(lines, "RX packets:", _fmt_int(nd.get("delta_rx_packets")))
        _kv(lines, "RX rate:", _fmt_int(nd.get("rx_pkt_rate"), unit=" pkt/s"))
        _kv(lines, "RX throughput:", _fmt(nd.get("rx_gbps"), unit=" Gbps"))
        _kv(lines, "RX dropped:", _fmt_int(nd.get("delta_rx_drop")))
        _kv(lines, "TX packets:", _fmt_int(nd.get("delta_tx_packets")))
        _kv(lines, "TX throughput:", _fmt(nd.get("tx_gbps"), unit=" Gbps"))
    else:
        lines.append("  (netdev stats unavailable)")

    # Softirqs
    sir = data.get("softirq", {})
    _section(lines, "Softirq Distribution")
    if sir:
        _kv(lines, "NET_RX total:", _fmt_int(sir.get("net_rx_total")))
        _kv(lines, "NET_RX max single CPU:", _fmt_int(sir.get("net_rx_max_cpu")))
        _kv(lines, "NET_RX imbalance:", _fmt(sir.get("net_rx_imbalance_pct"), unit="%"))
        per_cpu = sir.get("net_rx_per_cpu", [])
        if per_cpu:
            _kv(lines, "NET_RX per-CPU:", " ".join(str(x) for x in per_cpu))
    else:
        lines.append("  (softirq data unavailable)")

    # CPU freq / thermal
    cpu = data.get("cpu", {})
    _section(lines, "CPU Frequency & Thermal")
    _kv(lines, "Governor:", cpu.get("governor", "N/A"))
    _kv(lines, "Avg freq:", _fmt(cpu.get("avg_freq_mhz"), unit=" MHz"))
    _kv(lines, "Min / Max freq:",
        f"{_fmt(cpu.get('min_freq_mhz'))} / {_fmt(cpu.get('max_freq_mhz'))} MHz")
    mt = cpu.get("max_temp_celsius")
    _kv(lines, "Max CPU temp:", f"{mt:.1f} °C" if mt is not None else "N/A")
    _kv(lines, "Cores sampled:", str(cpu.get("num_cores_sampled", 0)))

    # Memory
    _section(lines, "Process Memory (/proc/<pid>/status)")
    after_mem = data.get("proc_mem", {}).get("after", {})
    if after_mem:
        _kv(lines, "VmRSS:", _fmt_int(after_mem.get("VmRSS"), unit=" KB"))
        _kv(lines, "VmPeak:", _fmt_int(after_mem.get("VmPeak"), unit=" KB"))
        _kv(lines, "VmSize:", _fmt_int(after_mem.get("VmSize"), unit=" KB"))
        _kv(lines, "Threads:", _fmt_int(after_mem.get("Threads")))
        _kv(lines, "Voluntary ctx sw:", _fmt_int(after_mem.get("voluntary_ctxt_switches")))
        _kv(lines, "Involuntary ctx sw:", _fmt_int(after_mem.get("nonvoluntary_ctxt_switches")))
    else:
        lines.append("  (proxy not running — no memory data)")

    # Syscall profile
    syscalls = data.get("syscalls", [])
    _section(lines, "Syscall Profile (top 10 by total time)")
    if syscalls:
        lines.append(f"  {'Syscall':<22} {'Calls':>10} {'Total ms':>12} {'Avg ms':>10}")
        lines.append(f"  {'─' * 22} {'─' * 10} {'─' * 12} {'─' * 10}")
        for sc in syscalls[:10]:
            lines.append(
                f"  {sc['syscall']:<22} {sc['calls']:>10,} "
                f"{sc['total_ms']:>12.3f} {sc['avg_ms']:>10.4f}"
            )
    elif args.syscall_profile:
        lines.append("  (perf trace ran but produced no output)")
    else:
        lines.append("  (disabled — run with --syscall-profile to enable)")

    return lines


# ===========================================================================
# Report assembler
# ===========================================================================

def save_deep_text_report(scenarios_data, dfa_stats, bpf_maps, simulations, args):
    """Assemble and write the full deep benchmark report."""
    report = []
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report.append("=" * 64)
    report.append("  CURSED-PROXY DEEP BENCHMARK REPORT")
    report.append("=" * 64)
    report.append(f"  Generated : {ts}")
    report.append(f"  Pattern   : {args.pattern}")
    report.append(f"  Duration  : {args.time}s per run  |  Warmup: {args.warmup}s")
    report.append(f"  Interface : {args.iface}")
    report.append("")

    # DFA complexity section
    report.append("━" * 64)
    report.append("  DFA COMPLEXITY (static analysis)")
    report.append("━" * 64)
    if dfa_stats.get("error"):
        report.append(f"  Error during DFA analysis: {dfa_stats['error']}")
    else:
        _kv(report, "Pattern:", dfa_stats.get("pattern", "?"))
        _kv(report, "DFA states:", _fmt_int(dfa_stats.get("states")))
        _kv(report, "Non-zero transitions:", _fmt_int(dfa_stats.get("transitions")))
        _kv(report, "Map density:", _fmt(dfa_stats.get("map_density_pct"), unit="%"))
        _kv(report, "Accept states:", _fmt_int(dfa_stats.get("accept_states")))
        _kv(report, "Alphabet equivalence classes:", _fmt_int(dfa_stats.get("alphabet_classes")))
        _kv(report, "Compile time:", _fmt(dfa_stats.get("compile_time_ms"), unit=" ms"))

    # BPF map memory section
    if bpf_maps:
        report.append("")
        report.append("━" * 64)
        report.append("  BPF MAP MEMORY")
        report.append("━" * 64)
        report.append(f"  {'Map name':<20} {'Type':<15} {'Entries':>8} {'Locked mem':>12}")
        report.append(f"  {'─' * 20} {'─' * 15} {'─' * 8} {'─' * 12}")
        for m in bpf_maps:
            report.append(
                f"  {m['name']:<20} {m['type']:<15} "
                f"{m['max_entries']:>8,} {m['bytes_memlock']:>10,} B"
            )

    # One block per scenario × packet-size combination
    for scenario_name, sim_data in scenarios_data.items():
        report.append("")
        report.append("━" * 64)
        report.append(f"  SCENARIO: {scenario_name}")
        report.append("━" * 64)
        for sim in simulations:
            sim_name = sim["name"]
            if sim_name in sim_data:
                report.extend(build_scenario_block(sim_data[sim_name], args))

    report.append("")
    report.append("=" * 64)
    report.append("  END OF REPORT")
    report.append("=" * 64)
    report.append("")

    out = "\n".join(report)
    with open(args.out_txt, "w") as f:
        f.write(out)

    print(f"\nDeep report written to '{args.out_txt}'")
    # Also print to stdout so the user can see it immediately
    print(out)


# ===========================================================================
# Main
# ===========================================================================

def main():
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (eBPF requires CAP_BPF/CAP_NET_ADMIN).")
        sys.exit(1)

    args = parse_args()

    print("=" * 64)
    print("  cursed-proxy DEEP BENCHMARK")
    print("=" * 64)
    print(f"  Pattern   : {args.pattern}")
    print(f"  Duration  : {args.time}s per run  |  Warmup: {args.warmup}s")
    print(f"  perf stat : {'disabled' if args.no_perf_stat else 'enabled'}")
    print(f"  perf trace: {'enabled' if args.syscall_profile else 'disabled'}")
    print()

    # 1. Static DFA analysis — no proxy needed
    print("[1/5] Analysing DFA complexity...")
    dfa_stats = collect_dfa_stats(args.pattern)
    if dfa_stats.get("error"):
        print(f"  WARNING: DFA analysis failed: {dfa_stats['error']}")
    else:
        print(f"  States={dfa_stats['states']}  Transitions={dfa_stats['transitions']}  "
              f"Density={dfa_stats['map_density_pct']:.2f}%  "
              f"Compile={dfa_stats['compile_time_ms']:.0f}ms")

    # 2. Start iperf3 server
    print("\n[2/5] Starting iperf3 server...")
    server_process = multiprocessing.Process(
        target=run_iperf_server, args=(args.port,), daemon=True
    )
    server_process.start()
    time.sleep(1)

    simulations = [
        {"name": "Max (64KB)", "blksize": None},
        {"name": "4KB",        "blksize": 4000},
        {"name": "256B",       "blksize": 256},
        {"name": "88B",        "blksize": 88},
    ]

    scenarios_data = {}
    bpf_maps = []

    try:
        # 3. Baseline — no proxy
        print("\n[3/5] Baseline (no proxy)...")
        print("  Warming up...")
        run_iperf_warmup(args.port, args.warmup)

        scenarios_data["Baseline"] = {}
        for sim in simulations:
            print(f"  → {sim['name']}")
            scenarios_data["Baseline"][sim["name"]] = run_scenario(
                label=f"Baseline / {sim['name']}",
                iperf_port=args.port,
                duration=args.time,
                blksize=sim["blksize"],
                proxy_pid=None,
                args=args,
            )

        # 4. Proxy: no rules
        print("\n[4/5] Proxy (no rules)...")
        create_proxy_conf([], args.port, PROXY_CONF)
        proxy_cmd = [sys.executable, "-m", "cursed_proxy", "-c", PROXY_CONF]
        proxy_proc = subprocess.Popen(
            proxy_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

        bpf_maps = collect_bpf_map_info()

        print("  Warming up proxy...")
        run_iperf_warmup(args.port, args.warmup)

        scenarios_data["Proxy (No Rules)"] = {}
        for sim in simulations:
            print(f"  → {sim['name']}")
            scenarios_data["Proxy (No Rules)"][sim["name"]] = run_scenario(
                label=f"Proxy (No Rules) / {sim['name']}",
                iperf_port=args.port,
                duration=args.time,
                blksize=sim["blksize"],
                proxy_pid=proxy_proc.pid,
                args=args,
            )

        proxy_proc.terminate()
        proxy_proc.wait()

        # 5. Proxy: with rules
        print(f"\n[5/5] Proxy (with rules: {args.pattern})...")
        create_proxy_conf([args.pattern], args.port, PROXY_CONF)
        proxy_proc = subprocess.Popen(
            proxy_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

        print("  Warming up proxy...")
        run_iperf_warmup(args.port, args.warmup)

        scenarios_data["Proxy (With Rules)"] = {}
        for sim in simulations:
            print(f"  → {sim['name']}")
            scenarios_data["Proxy (With Rules)"][sim["name"]] = run_scenario(
                label=f"Proxy (With Rules) / {sim['name']}",
                iperf_port=args.port,
                duration=args.time,
                blksize=sim["blksize"],
                proxy_pid=proxy_proc.pid,
                args=args,
            )

        proxy_proc.terminate()
        proxy_proc.wait()

    finally:
        print("\nStopping iperf3 server...")
        server_process.terminate()
        server_process.join()
        if os.path.exists(PROXY_CONF):
            os.remove(PROXY_CONF)

    save_deep_text_report(scenarios_data, dfa_stats, bpf_maps, simulations, args)


if __name__ == "__main__":
    main()
