import argparse
import json
from logging import getLogger, StreamHandler, DEBUG, Formatter, WARN, INFO

from DashConfigLoader import load_config
from DashMonitor import DashMonitor

logger = getLogger(__name__)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Packet Capture')
    parser.add_argument('-d', action='store_true', help='DEBUG')
    args = parser.parse_args()

    handler = StreamHandler()
    if args.d:
        handler.setLevel(DEBUG)
    else:
        handler.setLevel(INFO)
    handler.setFormatter(Formatter(fmt='%(asctime)-15s %(message)s'))
    if args.d:
        logger.setLevel(DEBUG)
    else:
        logger.setLevel(INFO)

    logger.addHandler(handler)

    buttons = load_config("config/config.json", logger=logger)
    users = json.load(open("config/users.json")).get("users", [])
    monitor = DashMonitor(buttons=buttons, logger=logger, users=users)
    monitor.start()
