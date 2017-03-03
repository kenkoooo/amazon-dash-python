from logging import getLogger, StreamHandler, DEBUG, Formatter

from DashConfigLoader import load_config
from DashMonitor import DashMonitor

logger = getLogger(__name__)
handler = StreamHandler()
handler.setLevel(DEBUG)
handler.setFormatter(Formatter(fmt='%(asctime)-15s %(message)s'))
logger.setLevel(DEBUG)
logger.addHandler(handler)


def is_valid_mac_address(mac_address):
    """
    validate mac address
    :param mac_address:
    :return:
    """
    nums = mac_address.split(":")
    if len(nums) != 6:
        return False
    for num in nums:
        try:
            int(num, 16)
        except ValueError as e:
            logger.error(e)
            return False
    return True


if __name__ == '__main__':
    buttons = load_config("config/config.json", logger=logger)
    monitor = DashMonitor(buttons=buttons, logger=logger)
    monitor.start()
