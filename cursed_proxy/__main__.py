import argparse
import logging
import os
import sys
import time

from cursed_proxy.log import setup_logging
from cursed_proxy.proxy import CursedProxy


def load_config(filepath):
    """Safely load and parse the config file."""
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()

        config = {}
        logger = logging.getLogger("cursed_proxy")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line:
                port_str, regex = line.split(":", 1)
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
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose eBPF checker logging",
    )
    parser.add_argument("-c", "--config", dest="config_path", default="proxy.conf", help="Path to configuration file")
    parser.add_argument("-i", "--interval", type=int, default=1, help="Config polling interval in seconds")
    parser.add_argument("-l", "--log-file", dest="log_file", default=None, help="Path to output log file")
    parser.add_argument("-n", "--interface", dest="interface", default="lo", help="Network interface to attach to (default: lo)")
    args = parser.parse_args()
    logger = setup_logging(args.verbose, args.log_file)

    if os.geteuid() != 0:
        logger.warning("eBPF requires root privileges. Escalating via sudo...")
        os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)
    logger.info(f"Starting Cursed Proxy on interface {args.interface}...")

    proxy = CursedProxy()
    try:
        proxy.start(ifname=args.interface, verbose=args.verbose)

        abs_config_path = os.path.abspath(args.config_path)
        logger.info(f"Watching configuration file at: {abs_config_path}")
        if not os.path.exists(abs_config_path):
            logger.warning(
                "Configuration file does not exist yet. Waiting for it to be created..."
            )

        # Config file update routine
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
                if last_mtime != 0:
                    logger.warning(
                        f"Config file {args.config_path} was deleted! Clearing proxy rules... if this was an error, good luck..."
                    )
                    proxy.sync_config({})
                    last_mtime = 0

            time.sleep(args.interval)

    except KeyboardInterrupt:
        logger.info("Stopping proxy via KeyboardInterrupt...")
    finally:
        proxy.stop()


if __name__ == "__main__":
    main()
