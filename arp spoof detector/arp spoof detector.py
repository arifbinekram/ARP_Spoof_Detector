#!/usr/bin/python3
# put the script in startup folder to run when the system boots
# put in /etc/init.d/script.py make executable sudo chmod 755 /etc/init.d/script.py
# Register script to be run at startup sudo update-rc.d script.py defaults

from scapy.all import ARP, Ether, srp, sniff

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc if answered_list else None

def process_sniffed_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP response (is-at)
        try:
            real_mac = get_mac(packet[ARP].psrc)
            response_mac = packet[ARP].hwsrc

            if real_mac and real_mac != response_mac:
                print("[+] You are under attack !!")

        except IndexError:
            pass

def sniff_packets(interface):
    sniff(iface=interface, store=False, prn=process_sniffed_packet)

if __name__ == "__main__":
    sniff_packets("eth0")

