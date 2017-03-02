from scapy.all import sniff, ARP


class DashMonitor:
    """
    Monitoring dash button pushing
    """

    def __init__(self, *, mac_address, runnable, logger):
        """
        :param mac_address: MAC address to monitor
        :param runnable: function which will be executed when the button is pushed
        :param logger: logger to use
        """
        self.mac_address = mac_address
        self.runnable = runnable
        self.logger = logger

    def start(self):
        self.logger.info("Start monitoring: %s", self.mac_address)
        sniff(prn=self.arp_monitor_callback, filter="arp", store=0)

    def arp_monitor_callback(self, pkt):
        """
        catch button-pushing and execute the set function
        show MAC address and IP address from sniffed packet
        :param pkt: sniffed packet
        :return: None
        """
        if ARP not in pkt or pkt[ARP].op not in (1, 2):
            # pkt[ARP].op == 1: who-has
            # pkt[ARP].op == 2: is-at
            return

        if not self.mac_address:
            # when the MAC address is not set, all packet information will be logged
            self.logger.info("MAC Address: %s", pkt[ARP].hwsrc)  # ARPSourceMACField: mac address
            self.logger.info("IP Address: %s", pkt[ARP].psrc)  # SourceIPField: source ip address
        elif pkt[ARP].hwsrc == self.mac_address:
            self.logger.info("Dash Button Pushed")
            self.runnable()
