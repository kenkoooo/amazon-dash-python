import json
from datetime import datetime

import requests
from scapy.all import sniff, ARP
from scapy.layers.l2 import Ether


class DashMonitor:
    """
    Monitoring dash button pushing
    """

    def __init__(self, *, buttons, users: list, logger):
        """
        :param buttons: information about buttons
        :param logger: logger to use
        """
        self.buttons = buttons
        self.logger = logger
        self.users = users

    def start(self):
        self.logger.info("Start monitoring")
        sniff(prn=self.arp_monitor_callback, store=0)

    def arp_monitor_callback(self, pkt: Ether):
        """
        catch button-pushing and execute the set function
        show MAC address and IP address from sniffed packet
        :param pkt: sniffed packet
        :return: None
        """
        if pkt[Ether].src in self.users:
            self.logger.info("%s の人が来ました！！！", pkt[Ether].src)
        if ARP not in pkt:
            return

        # all packet information will be logged
        self.logger.info("MAC Address:\t%s", pkt[ARP].hwsrc)  # ARPSourceMACField: mac address
        self.logger.info("IP Address:\t%s", pkt[ARP].psrc)  # SourceIPField: source ip address

        if pkt[ARP].op not in (1, 2):
            # pkt[ARP].op == 1: who-has
            # pkt[ARP].op == 2: is-at
            return

        for button in self.buttons:
            if pkt[ARP].hwsrc == button["address"]:
                current_time = int(datetime.now().strftime("%s"))
                button["next_time"] = button.get("next_time", 0)
                if button["next_time"] > current_time:
                    continue
                button["next_time"] = current_time + button["interval"]

                self.logger.info("Dash Button %s was pushed", button["name"])
                requests.post(button["url"], data=json.dumps(button["data"]))
