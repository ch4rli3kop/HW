#!/usr/bin/python3

from scapy.all import *

def print_pkt(pkt):
	pkt.show()

#pkt = sniff(filter='icmp', prn=print_pkt)
#pkt = sniff(filter='tcp and src net 192.168.41.1 and dst port 23', prn=print_pkt)
pkt = sniff(filter='dst net 192.168.41.144 mask 255.255.255.255', prn=print_pkt)


