# Lex @ https://github.com/claire-lex
# Script for Ethernet/IP device discovery

from sys import argv
from socket import socket
from scapy.supersocket import StreamSocket
from scapy.compat import raw
from scapy.packet import Raw
from enipTCP import ENIPTCP

if len(argv) != 2:
    print("Usage: {0} ip_address".format(argv[0]))
    exit(-1)

s = socket()
s.connect((argv[1], 44818))
ss = StreamSocket(s, Raw)

pkt = ENIPTCP()
pkt.commandId = 0x63

resp = ss.sr1(pkt)
resp = ENIPTCP(raw(resp))

resp.show2()
