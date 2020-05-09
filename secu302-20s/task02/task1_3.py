#!/usr/bin/python3
from scapy.all import *

TARGET = '8.8.8.8'
MAX_TTL = 14
TIMEOUT = 1.5

ip = IP()
icmp = ICMP()

ip.dst = TARGET

ip.ttl = (1,MAX_TTL)
p = ip/icmp
ans, uans= sr(p, timeout=TIMEOUT)

for snd, rcv in ans:
	result = str(snd.ttl) + '\t' + rcv.src
	if rcv.src == TARGET:
		result += ' \t <== TARGET!'
		print(result)
		break
	print(result)

