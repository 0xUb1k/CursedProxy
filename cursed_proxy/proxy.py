import ctypes
import logging
import os
import sys
import threading
from collections import Counter
from functools import lru_cache

from pyformlang.regular_expression import PythonRegex

from cursed_proxy.log import Spinner

logger = logging.getLogger(__name__)


class CursedProxy:
    def __init__(self, ebpf_path=None):
        if ebpf_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            ebpf_path = os.path.join(current_dir, "libcursed_proxy.so")
        try:
            self.bpf_lib = ctypes.CDLL(ebpf_path)
        except OSError:
            logger.error(
                f"libcursed_proxy.so was not found at {ebpf_path}, did you run make?"
            )
            sys.exit()

        self.ports = set()
        self.config = {}
        self.regex_keys = {}
        self.running = False

        # stats
        self.n_dropped = Counter()

        self._configure_ctypes_signatures()

    def _configure_ctypes_signatures(self):
        # Ringbuf polling bindings
        self.CALLBACK_TYPE = ctypes.CFUNCTYPE(
            None, ctypes.c_int, ctypes.c_int, ctypes.c_void_p
        )
        self.c_callback = self.CALLBACK_TYPE(self._ringbuf_callback)

        self.bpf_lib.setup_ringbuf.argtypes = [self.CALLBACK_TYPE]
        self.bpf_lib.setup_ringbuf.restype = ctypes.c_int

        self.bpf_lib.poll_ringbuf.argtypes = [ctypes.c_int]
        self.bpf_lib.poll_ringbuf.restype = ctypes.c_int

        self.bpf_lib.teardown_ringbuf.argtypes = []
        self.bpf_lib.teardown_ringbuf.restype = None

        # DFA transitions
        self.bpf_lib.update_port_dfa.argtypes = [
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint),
            ctypes.c_uint,
        ]
        self.bpf_lib.update_port_dfa.restype = ctypes.c_int

        self.bpf_lib.remove_port_dfa.argtypes = [ctypes.c_uint]
        self.bpf_lib.remove_port_dfa.restype = ctypes.c_int

        # Ports management
        self.bpf_lib.add_managed_port.argtypes = [ctypes.c_uint]
        self.bpf_lib.add_managed_port.restype = ctypes.c_int

        self.bpf_lib.remove_managed_port.argtypes = [ctypes.c_uint]
        self.bpf_lib.remove_managed_port.restype = ctypes.c_int

        # Core eBPF lifecycle
        self.bpf_lib.load_ebpf.argtypes = []
        self.bpf_lib.load_ebpf.restype = ctypes.c_int

        self.bpf_lib.unload_ebpf.argtypes = []
        self.bpf_lib.unload_ebpf.restype = None

        self.bpf_lib.enable_libbpf_logging.argtypes = []
        self.bpf_lib.enable_libbpf_logging.restype = None

        self.bpf_lib.disable_libbpf_logging.argtypes = []
        self.bpf_lib.disable_libbpf_logging.restype = None

    def _ringbuf_callback(self, port, match_len, payload_ptr):
        raw_bytes = ctypes.string_at(payload_ptr, match_len)
        self.n_dropped[port] += 1
        matched_str = repr(raw_bytes)
        logger.warning(
            f"\033[91m[DROPPED]\033[0m packet on port {port}! Matched snippet: {matched_str}"
        )

    def _poll_ringbuf_loop(self):
        while self.running:
            self.bpf_lib.poll_ringbuf(100)

    def start(self, verbose=False):
        if verbose:
            self.bpf_lib.enable_libbpf_logging()
            logger.info("Verbose eBPF checker logging enabled.")
        else:
            self.bpf_lib.disable_libbpf_logging()

        logger.info("Loading eBPF proxy into kernel...")
        ret = self.bpf_lib.load_ebpf()
        if ret != 0:
            logger.error(f"Failed to load eBPF programm, error code: {ret}")
            raise RuntimeError(
                f"Failed to load eBPF program, error code: {ret}. See stderr output above for details."
            )
        logger.info("eBPF proxy loaded successfully.")

        if self.bpf_lib.setup_ringbuf(self.c_callback) != 0:
            logger.error("Failed to setup BPF ring buffer!")

        self.running = True
        self.poll_thread = threading.Thread(target=self._poll_ringbuf_loop)
        self.poll_thread.daemon = True
        self.poll_thread.start()

    def add_port(self, port):
        ret = self.bpf_lib.add_managed_port(ctypes.c_uint(port))
        if ret == 0:
            self.ports.add(port)
            logger.info(f"Port {port} added successfully.")
        else:
            logger.error(f"Failed to add port {port}.")

    def remove_port(self, port):
        ret = self.bpf_lib.remove_managed_port(ctypes.c_uint(port))
        if ret == 0:
            self.ports.discard(port)
            logger.info(f"Port {port} deactivated successfully.")
        else:
            logger.error(f"Failed to remove port {port}.")

    def stop(self):
        self.running = False
        if hasattr(self, "poll_thread") and self.poll_thread:
            self.poll_thread.join(timeout=1.0)

        logger.info("Tearing down eBPF resources...")
        self.bpf_lib.teardown_ringbuf()
        self.bpf_lib.unload_ebpf()
        logger.info("eBPF program unloaded.")

        if self.n_dropped:
            logger.info("=== Final Drop Statistics ===")
            for port, count in self.n_dropped.most_common():
                logger.info(f"Port {port}: {count} packets dropped")
            logger.info("=============================")
        else:
            logger.info("No packets were dropped during this session.")

    # config in the form of {port: "ebpf", ...}
    def sync_config(self, new_config: dict):
        logger.info("Syncing config...")

        new_config_ports = set(new_config.keys())
        current_ports = set(self.ports)

        old_ports = current_ports - new_config_ports
        for p in old_ports:
            self.remove_port(p)
            self.remove_regex(p)

        for p in new_config_ports:
            if p in self.config:
                if new_config[p] != self.config[p]:
                    logger.debug(f"Updating regex on port {p}")
                    self.add_regex(p, new_config[p])
            else:
                self.add_regex(p, new_config[p])

            if p not in self.ports:
                self.add_port(p)

        logger.info("Sync completed.")

    def remove_regex(self, port):
        if port in self.regex_keys:
            ret = self.bpf_lib.remove_port_dfa(ctypes.c_uint(port))
            if ret != 0:
                logger.error(f"Failed to remove DFA for port {port}")
            else:
                logger.info(f"Removed DFA for port {port}.")

            self.config.pop(port, None)
            del self.regex_keys[port]

    @staticmethod
    @lru_cache(maxsize=32)
    def compile_regex(regex_pattern):
        regex = PythonRegex(regex_pattern)

        logger.info(
            f"Compiling regex pattern: {regex_pattern}, this may take a while..."
        )

        with Spinner("Creating epsilon NFA..."):
            enfa = regex.to_epsilon_nfa()

        with Spinner("Folding into deterministic finite automata..."):
            dfa = enfa.to_deterministic()

        with Spinner("Minimizing DFA..."):
            minimized_dfa = dfa.minimize()

        with Spinner("Mapping states for eBPF consumption..."):
            states = list(minimized_dfa.states)
        state_to_idx = {state: i for i, state in enumerate(states)}

        start_idx = state_to_idx[minimized_dfa.start_state]
        accept_indices = {state_to_idx[s] for s in minimized_dfa.final_states}

        transition_dict = minimized_dfa.to_dict()

        ebpf_transitions = {}

        for state in states:
            curr_idx = state_to_idx[state]
            transitions = transition_dict.get(state, {})

            for symbol, target_state in transitions.items():
                target = (
                    next(iter(target_state))
                    if isinstance(target_state, set)
                    else target_state
                )
                char_val = ord(str(symbol))
                ebpf_transitions[(curr_idx, char_val)] = state_to_idx[target]

        return {
            "start_state": start_idx,
            "accept_states": accept_indices,
            "transitions": ebpf_transitions,
            "total_states": len(states),
        }

    def add_regex(self, port, regex_string):
        self.config[port] = regex_string
        if port not in self.regex_keys:
            self.regex_keys[port] = []

        hits_before = self.compile_regex.cache_info().hits
        dfa_info = self.compile_regex(regex_string)
        hits_after = self.compile_regex.cache_info().hits

        if hits_after > hits_before:
            logger.debug(f"Using cached DFA for regex: {regex_string}")

        # eBPF uses 1 as the hardcoded start state
        state_mapping = {dfa_info["start_state"]: 1}
        next_id = 2
        for s in range(dfa_info["total_states"]):
            if s != dfa_info["start_state"]:
                state_mapping[s] = next_id
                next_id += 1

        keys = []
        values = []

        for (src_state, char_val), dst_state in dfa_info["transitions"].items():
            mapped_src = state_mapping[src_state]
            mapped_dst = state_mapping[dst_state]

            # Key is just state and char (no port needed)
            key = (mapped_src << 8) | char_val

            val = mapped_dst
            if dst_state in dfa_info["accept_states"]:
                val |= 0x80000000

            keys.append(key)
            values.append(val)

        # Create ctypes arrays
        num_transitions = len(keys)
        keys_array = (ctypes.c_uint * num_transitions)(*keys)
        values_array = (ctypes.c_uint * num_transitions)(*values)

        ret = self.bpf_lib.update_port_dfa(
            ctypes.c_uint(port),
            keys_array,
            values_array,
            ctypes.c_uint(num_transitions)
        )
        
        if ret == 0:
            logger.info(
                f"Added '{regex_string}' with {num_transitions} DFA transitions on port {port} atomically."
            )
            # regex_keys just records that we have it for this port
            self.regex_keys[port] = [port] 
        else:
            logger.error(f"Failed to update DFA for port {port}")
