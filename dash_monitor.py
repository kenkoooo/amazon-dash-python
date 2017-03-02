import argparse
from logging import getLogger, StreamHandler, DEBUG, Formatter

from DashMonitor import DashMonitor

logger = getLogger(__name__)
handler = StreamHandler()
handler.setLevel(DEBUG)
handler.setFormatter(Formatter(fmt='%(asctime)-15s %(message)s'))
logger.setLevel(DEBUG)
logger.addHandler(handler)


def happy_function():
    logger.info("YEAH!!!")


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
    parser = argparse.ArgumentParser(description='Amazon Dash Button Monitor')
    parser.add_argument('-m', nargs='?', help="MAC Address of the Dash Button")
    args = parser.parse_args()
    if args.m and not is_valid_mac_address(args.m):
        parser.print_help()
    else:
        monitor = DashMonitor(mac_address=args.m, runnable=happy_function, logger=logger)
        monitor.start()
