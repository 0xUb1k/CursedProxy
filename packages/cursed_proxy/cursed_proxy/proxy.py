import logging

from cursed_engine import CursedEngine

logger = logging.getLogger(__name__)


class CursedProxy:
    def __init__(self, ebpf_path=None):
        self.engine = CursedEngine(ebpf_path=ebpf_path)

    def start(self, ifname="lo", verbose=False):
        self.engine.start(ifname=ifname, verbose=verbose)

    def stop(self):
        self.engine.stop()

    def sync_config(self, new_config: dict):
        self.engine.sync_config(new_config)
