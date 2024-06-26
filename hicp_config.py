# Lex @ https://github.com/claire-lex
# Script for HICP device configuration

from sys import argv
from os import geteuid
from getpass import getpass
from socket import gaierror
from scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff
from hicp import HICPModuleScan, HICPConfigure

PARAMS = [x.name for x in HICPConfigure.fields_desc \
          if x.name not in ("target", "padding")]

# Arguments check
if len(argv) != 4:
    print("Usage: {0} ip_address parameter value".format(argv[0]))
    exit(-1)
elif argv[2] not in PARAMS:
    print("Parameter can be: {0}".format(", ".join(PARAMS)))
    exit(-1)

# Privileges check
if geteuid() != 0:
    print("The program requires root privileges! Please run again with sudo.")
    exit(-1)
    
# Prepare
target = IP(dst=argv[1])/UDP(dport=3250, sport=3250)
param, value = argv[2], argv[3]

# Warning and check
print("WARNING!!! NEVER USE THIS IN RUNNING PRODUCTION ENVIRONMENTS")
check = input("Are you sure you want to proceed? [y/N]: ")
if check not in ["y", "Y"]:
    exit(0)

# Retrieve required information to build the configuration request
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
conf = HICPConfigure(
    target=resp.mac_address,
    ip_address=resp.ip_address,
    subnet_mask=resp.subnet_mask,
    gateway_address=resp.gateway_address,
    dhcp=resp.dhcp,
    hostname=resp.hostname,
    dns1=resp.dns1,
    dns2=resp.dns2,
    password="OFF",
    new_password=";"
)
# Change the value (we don't check so be careful :)
setattr(conf, param, value) 

# Send it and check response
while True:
    send(target/conf, verbose=False)
    resp = sniff(filter="port 3250", count=1)[0]
    if resp.hicp_command == b"Reconfigured":
        print("Configuration successful: {0} = {1}".format(param, value))
        break
    elif resp.hicp_command == b"Invalid Configuration":
        print("Configuration failed: {0} = {1}".format(param, value))
        break
    elif resp.hicp_command == b"Invalid Password":
        print("The device is password-protected.".format(param, value))
        pwd = getpass("Please enter password: ")
        conf.password = pwd
    else:
        print("Unknown response received.")
        break
