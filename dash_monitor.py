import json
from logging import getLogger, StreamHandler, DEBUG, Formatter

from DashConfigLoader import load_config
from DashMonitor import DashMonitor

logger = getLogger(__name__)
handler = StreamHandler()
handler.setLevel(DEBUG)
handler.setFormatter(Formatter(fmt='%(asctime)-15s %(message)s'))
logger.setLevel(DEBUG)
logger.addHandler(handler)

if __name__ == '__main__':
    buttons = load_config("config/config.json", logger=logger)
    users = json.load(open("config/users.json")).get("users", [])
    monitor = DashMonitor(buttons=buttons, logger=logger, users=users)
    monitor.start()
