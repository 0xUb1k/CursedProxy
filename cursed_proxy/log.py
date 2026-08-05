import logging
import sys
import threading
import time
import typing

# this is all LLM's work


class Spinner:
    def __init__(self, message="Loading..."):
        self.message = message
        self.running = False
        self.thread = None

    def spin(self):
        chars = "|/-\\"
        idx = 0
        while self.running:
            current_time = time.strftime("%H:%M:%S", time.localtime())
            sys.stdout.write(
                f"\r\033[90m{current_time}\033[0m \033[94m[*]\033[0m {self.message} {chars[idx % len(chars)]}"
            )
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)

    def __enter__(self):
        self.running = True
        self.thread = threading.Thread(target=self.spin)
        self.thread.daemon = True
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write("\r\033[K")  # Clear the line completely without a newline
        sys.stdout.flush()


class ColorFormatter(logging.Formatter):
    COLORS: typing.ClassVar[dict] = {
        logging.DEBUG: "\033[94m[*]\033[0m",  # Blue [*]
        logging.INFO: "\033[92m[+]\033[0m",  # Green [+]
        logging.WARNING: "\033[93m[!]\033[0m",  # Yellow [!]
        logging.ERROR: "\033[91m[-]\033[0m",  # Red [-]
        logging.CRITICAL: "\033[1;91m[!]\033[0m",  # Bold Red [!]
    }

    def format(self, record):
        prefix = self.COLORS.get(record.levelno, "[?]")

        if "proxy" in record.name and record.name != "cursed_proxy":
            name_colored = (
                f"\033[96m[{record.name.split('.')[-1]}]\033[0m"  # Cyan for core proxy
            )
        else:
            name_colored = "\033[95m[main]\033[0m"  # Magenta for main

        log_fmt = f"\033[90m%(asctime)s\033[0m {prefix} {name_colored} %(message)s"
        formatter = logging.Formatter(log_fmt, datefmt="%H:%M:%S")
        return formatter.format(record)


def setup_logging(verbose=False):
    logger = logging.getLogger("cursed_proxy")
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    return logger
