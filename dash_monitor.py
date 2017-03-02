import argparse
from logging import getLogger, StreamHandler, DEBUG

from scapy.all import sniff, ARP

logger = getLogger(__name__)
handler = StreamHandler()
handler.setLevel(DEBUG)
logger.setLevel(DEBUG)
logger.addHandler(handler)


class DashMonitor:
    def __init__(self, mac_address):
        self.mac_address = mac_address

    def start(self):
        logger.info("Start monitoring: %s", self.mac_address)
        sniff(prn=self.arp_monitor_callback, filter="arp", store=0)

    def arp_monitor_callback(self, pkt):
        """
        show MAC address and IP address from sniffed packet
        :param pkt: sniffed packet
        :return: None
        """
        if ARP not in pkt or pkt[ARP].op not in (1, 2):
            return

        if not self.mac_address:
            # ARPSourceMACField: mac address
            logger.info("MAC Address: %s", pkt[ARP].hwsrc)
            # SourceIPField: source ip address
            logger.info("IP Address: %s", pkt[ARP].psrc)
        elif pkt[ARP].hwsrc == self.mac_address:
            logger.info("Called")


def running_monitor(target):
    monitor = DashMonitor(target)
    monitor.start()


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
        running_monitor(args.m)
