#!/usr/bin/python3

from scapy.all import *

a = IP()
a.src = '192.168.41.140'
a.dst = '192.168.41.141'
b = ICMP()
p = a/b
p.show2()
send(p)
