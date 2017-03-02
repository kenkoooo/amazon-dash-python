from scapy.all import sniff, ARP


def arp_monitor_callback(pkt):
    """
    show MAC address and IP address from sniffed packet
    :param pkt: sniffed packet
    :return: None
    """
    if ARP in pkt and pkt[ARP].op in (1, 2):
        """
        op==1: who has
        誰がこの ip やねんみたいな感じで聞いてる
        op==2: is at
        ワイのこの mac address がその ip やみたいな感じで教えてる
        """

        # ARPSourceMACField: mac address
        print("MAC Address: {}".format(pkt[ARP].hwsrc))

        # SourceIPField: source ip address
        print("IP Address: {}".format(pkt[ARP].psrc))


sniff(prn=arp_monitor_callback, filter="arp", store=0, count=10)
