from .proxy import CursedProxy
import argparse
import logging
import time
import os
import sys

class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\033[94m[*]\033[0m",     # Blue [*]
        logging.INFO: "\033[92m[+]\033[0m",      # Green [+]
        logging.WARNING: "\033[93m[!]\033[0m",   # Yellow [!]
        logging.ERROR: "\033[91m[-]\033[0m",     # Red [-]
        logging.CRITICAL: "\033[1;91m[!]\033[0m" # Bold Red [!]
    }

    def format(self, record):
        prefix = self.COLORS.get(record.levelno, "[?]")
        log_fmt = f"\033[90m%(asctime)s\033[0m {prefix} %(message)s"
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

def load_config(filepath):
    """Safely load and parse the config file."""
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            
        config = {}
        logger = logging.getLogger("cursed_proxy")
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            if ':' in line:
                port_str, regex = line.split(':', 1)
                try:
                    port = int(port_str.strip())
                    config[port] = regex.strip()
                except ValueError:
                    logger.error(f"Invalid port in config: {port_str}")
            else:
                logger.error(f"Ignoring config line (missing ':'): {line}")
        return config
    except FileNotFoundError:
        return None


def main():

    parser = argparse.ArgumentParser(description="Cursed Proxy Handler")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose eBPF checker logging")
    parser.add_argument("-c", "--config", dest="config_path", default="proxy.conf", help="Path to configuration file")
    parser.add_argument("-i", "--interval", type=int, default=1, help="Config polling interval in seconds")
    args = parser.parse_args()
    logger = setup_logging(args.verbose)

    logger.info("Starting Cursed Proxy...")
    if os.geteuid() != 0:
        logger.warning("eBPF requires root privileges. Escalating via sudo...")
        os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)

    proxy = CursedProxy()
    try:
        proxy.start(verbose=args.verbose)

        logger.info("Proxy running... Press Ctrl+C to stop.")
        
        abs_config_path = os.path.abspath(args.config_path)
        logger.info(f"Watching configuration file at: {abs_config_path}")
        if not os.path.exists(abs_config_path):
            logger.warning("Configuration file does not exist yet. Waiting for it to be created...")

        last_mtime = 0
        while True:
            try:
                mtime = os.path.getmtime(args.config_path)
                if mtime > last_mtime:
                    new_config = load_config(args.config_path)
                    if new_config is not None:
                        logger.info("Configuration change detected!")
                        proxy.sync_config(new_config)
                    last_mtime = mtime
            except FileNotFoundError:
                # If the file is deleted while running, clear the proxy
                if last_mtime != 0:
                    logger.warning(f"Config file {args.config_path} was deleted! Clearing proxy rules...")
                    proxy.sync_config({})
                    last_mtime = 0

            time.sleep(args.interval)

    except KeyboardInterrupt:
        logger.info("Stopping proxy via KeyboardInterrupt...")
    finally:
        proxy.stop()

if __name__ == "__main__":
    main()
