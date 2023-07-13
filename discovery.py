# Lex @ https://github.com/claire-lex
# Script for HICP device discovery

from scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sendp, sniff
from hicp import HICPModuleScan

hicp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst="255.255.255.255")
hicp_broadcast = hicp_broadcast/UDP(dport=3250, sport=3250)

# Discovery
sendp(hicp_broadcast/HICPModuleScan(), verbose=False)
responses = sniff(filter="port 3250", timeout=1)
for resp in responses:
    if resp.hicp_command != b"Module scan response":
        continue
    # Display information
    print("HICP Device:")
    if len(resp.hostname):
        print("- Hostname:", resp.hostname)
    print("- MAC address:", resp.mac_address)
    print("- IP address:", resp.ip_address)
    print("- DHCP:", resp.dhcp.decode('utf-8'))
    print("- Password:", resp.password.decode('utf-8'))
    print("- Subnet mask:", resp.subnet_mask)
    print("- Gateway address:", resp.gateway_address)
    print("- DNS 1:", resp.dns1)
    print("- DNS 2:", resp.dns2)
    print("")
