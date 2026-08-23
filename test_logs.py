import logging
from cursed_proxy.log import setup_logging
from cursed_engine.engine import CursedEngine

setup_logging(verbose=False)
logger = logging.getLogger("main")
logger.info("Starting test")

engine = CursedEngine()
engine.add_regex(1234, ".*test.*")
