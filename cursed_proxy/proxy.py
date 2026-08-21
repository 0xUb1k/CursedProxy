import ctypes
import logging
import os
import socket
import sys
import threading
from collections import Counter
from functools import lru_cache

import interegular


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

        self.config = {}
        self.running = False

        # stats
        self.n_dropped = Counter()

        self._configure_ctypes_signatures()
        self.bpf_lib.setup_c_logging(self.c_log_callback)

    def _configure_ctypes_signatures(self):
        # Logging bindings
        self.LOG_CALLBACK_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_char_p)
        self.c_log_callback = self.LOG_CALLBACK_TYPE(self._c_log_callback)
        self.bpf_lib.setup_c_logging.argtypes = [self.LOG_CALLBACK_TYPE]
        self.bpf_lib.setup_c_logging.restype = None

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
        self.bpf_lib.load_ebpf.argtypes = [ctypes.c_int]
        self.bpf_lib.load_ebpf.restype = ctypes.c_int

        self.bpf_lib.unload_ebpf.argtypes = []
        self.bpf_lib.unload_ebpf.restype = None

        self.bpf_lib.enable_libbpf_logging.argtypes = []
        self.bpf_lib.enable_libbpf_logging.restype = None

        self.bpf_lib.disable_libbpf_logging.argtypes = []
        self.bpf_lib.disable_libbpf_logging.restype = None

    def _c_log_callback(self, level, msg):
        msg_str = msg.decode('utf-8', errors='replace').strip()
        if not msg_str:
            return
            
        ebpf_logger = logging.getLogger("cursed_proxy.eBPF")
        if level <= 10:
            ebpf_logger.debug(msg_str)
        elif level <= 20:
            ebpf_logger.info(msg_str)
        elif level <= 30:
            ebpf_logger.warning(msg_str)
        else:
            ebpf_logger.error(msg_str)

    def _ringbuf_callback(self, port, match_len, payload_ptr):
        raw_bytes = ctypes.string_at(payload_ptr, match_len)
        self.n_dropped[port] += 1
        matched_str = repr(raw_bytes)
        ebpf_logger = logging.getLogger("cursed_proxy.eBPF")
        ebpf_logger.warning(
            f"\033[91m[DROPPED]\033[0m packet on port {port}! Matched snippet: {matched_str}"
        )

    def _poll_ringbuf_loop(self):
        while self.running:
            self.bpf_lib.poll_ringbuf(100)

    def start(self, ifname="lo", verbose=False):
        if verbose:
            self.bpf_lib.enable_libbpf_logging()
            logger.info("Verbose eBPF checker logging enabled.")
        else:
            self.bpf_lib.disable_libbpf_logging()

        try:
            ifindex = socket.if_nametoindex(ifname)
        except OSError:
            logger.error(f"Interface {ifname} not found.")
            raise RuntimeError(f"Interface {ifname} not found.")

        logger.info(f"Loading eBPF proxy into kernel on interface {ifname} (index {ifindex})...")
        ret = self.bpf_lib.load_ebpf(ifindex)
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
            logger.info(f"Port {port} activated successfully.")
        else:
            logger.error(f"Failed to add port {port}.")

    def remove_port(self, port):
        ret = self.bpf_lib.remove_managed_port(ctypes.c_uint(port))
        if ret == 0:
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
        current_ports = set(self.config.keys())

        old_ports = current_ports - new_config_ports
        for p in old_ports:
            self.remove_port(p)
            self.remove_regex(p)

        for p in new_config_ports:
            is_new_port = p not in self.config
            
            if p in self.config:
                if new_config[p] != self.config[p]:
                    logger.debug(f"Updating regex on port {p}")
                    self.add_regex(p, new_config[p])
            else:
                self.add_regex(p, new_config[p])

            if is_new_port:
                self.add_port(p)

        logger.info("Sync completed.")

    def remove_regex(self, port):
        if port in self.config:
            ret = self.bpf_lib.remove_port_dfa(ctypes.c_uint(port))
            if ret != 0:
                logger.error(f"Failed to remove DFA for port {port}")
            else:
                logger.info(f"Removed DFA for port {port}.")

            self.config.pop(port, None)

    @staticmethod
    @lru_cache(maxsize=32)
    def compile_regex(regex_pattern: str):
        logger.info(f"Compiling regex pattern: {regex_pattern}, this may take a while...")

        try:
            with Spinner("Parsing pattern"):
                pattern = interegular.parse_pattern(regex_pattern)

            with Spinner("Reducing to DFA and minimizing"):
                fsm = pattern.to_fsm()
        except Exception as e:
            logger.error(f"Failed to compile regex '{regex_pattern}': {type(e).__name__}")
            return None, None
        
        with Spinner("Mapping states for eBPF consumption..."):
            states = list(fsm.states)
            state_to_idx = {state: i for i, state in enumerate(states)}
            
            fsm_start_idx = state_to_idx[fsm.initial]
          
            # this shifts everything so that 1 is the start state and all the rest comes after 
            # {real_state: state_we_want}
            state_mapping = {fsm_start_idx: 1}
            next_id = 2
            for s in range(len(states)):
                if s != fsm_start_idx:
                    state_mapping[s] = next_id
                    next_id += 1
            
            accept_indices = {state_to_idx[s] for s in fsm.finals}
         
            #this lib uses symbols that work as eq-classes. so we need to unpack it in somethin
            # usable
            byte_to_symbol = {}
            anything_else_sym = None
            for symbol_id, chars in fsm.alphabet._by_transition.items():
                for char in chars:
                    if char == interegular.fsm.anything_else:
                        anything_else_sym = symbol_id
                    else:
                        byte_to_symbol[ord(char)] = symbol_id

            for b in range(256):
                if b not in byte_to_symbol and anything_else_sym is not None:
                    byte_to_symbol[b] = anything_else_sym

            keys = []
            values = []

            for state, transitions in fsm.map.items():
                src_idx = state_to_idx[state]
                mapped_src = state_mapping[src_idx]
                
                for byte_val in range(256):
                    sym_id = byte_to_symbol.get(byte_val)
                    
                    if sym_id is not None and sym_id in transitions:
                        target_state = transitions[sym_id]
                        target_idx = state_to_idx[target_state]
                        mapped_dst = state_mapping[target_idx]
                        
                        val = mapped_dst
                        if target_idx in accept_indices:
                            val |= 0x80000000
                            
                        key = (mapped_src << 8) | byte_val
                        keys.append(key)
                        values.append(val)
                                            
            return keys, values

    def add_regex(self, port: int, regex_string: str):
        hits_before = self.compile_regex.cache_info().hits
        keys, values = self.compile_regex(regex_string)
        
        if keys is None or values is None:
            logger.error(f"Skipping update for port {port} due to regex compilation failure.")
            return
            
        hits_after = self.compile_regex.cache_info().hits

        if hits_after > hits_before:
            logger.debug(f"Using cached DFA for regex: {regex_string}")

        num_transitions = len(keys)
        if num_transitions > 262144:
            logger.error(
                f"Failed to add regex '{regex_string}' to port {port}: "
                f"Regex is too complex ({num_transitions} transitions) and exceeds the maximum allowed (262144)."
            )
            return

        if keys:
            max_key = max(keys)
            if max_key >= 262144:
                logger.error(
                    f"Failed to add regex '{regex_string}' to port {port}: "
                    f"Regex is too complex (max key {max_key}) and exceeds the eBPF array map capacity (262144)."
                )
                return

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
                f"Added '{regex_string}' with {num_transitions} DFA transitions on port {port}."
            )
            self.config[port] = regex_string
        elif ret == -2:
            logger.error(f"Failed to update DFA for port {port}: Kernel rejected the transitions (map full or out of memory).")
        else:
            logger.error(f"Failed to update DFA for port {port}: Internal kernel error (code {ret}).")
