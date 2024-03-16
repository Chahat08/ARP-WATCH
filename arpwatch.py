# CSE 508 HW2: ARP poisoning attack detector

import argparse
from scapy.all import *
import colorama

colorama.init()
GREEN=colorama.Fore.GREEN
RED=colorama.Fore.RED
YELLOW=colorama.Fore.YELLOW
RESET=colorama.Fore.RESET

def get_current_arp_cache():
    arp_cache = {}
    with open("/proc/net/arp") as f:
        next(f) 
        for line in f:
            parts = line.split()
            ip_address = parts[0]
            mac_address = parts[3]
            arp_cache[ip_address] = mac_address
    return arp_cache

def arp_watch(interface):
    current_arp_cache = get_current_arp_cache()

    def arp_display(pkt):
        if ARP in pkt and pkt[ARP].op in (1,2): 
            ip_address = pkt[ARP].psrc
            mac_address = pkt[ARP].hwsrc
            if ip_address in current_arp_cache and current_arp_cache[ip_address] != mac_address:
                print(f"{YELLOW}{ip_address}{RESET} changed from {GREEN}{current_arp_cache[ip_address]}{RESET} to {RED}{mac_address}{RESET}")
                current_arp_cache[ip_address] = mac_address

    print(f"ARP watch started on interface {interface}")
    sniff(prn=arp_display, filter="arp", store=0, iface=interface)

def main():
    parser = argparse.ArgumentParser(description="ARP cache poisoning detector.", epilog="Created and submitted by Chahat Kalsi (115825394) for CSE 508 HW2")
    parser.add_argument("-i", "--interface", help="Network interface for the capture, eg. eth0, wlan0, etc.")
    args = parser.parse_args()

    print("----------------------------------------------------")
    print(f"         {YELLOW}ARP CACHE POISONING DETECTOR{RESET}")
    print("----------------------------------------------------")

    interface = args.interface or conf.iface 
    arp_watch(interface)

if __name__ == "__main__":
    main()
