# Lex @ https://github.com/claire-lex
# Script for HICP device configuration

from sys import argv
from socket import gaierror
from scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff
from hicp import HICPModuleScan, HICPConfigure

PARAMS = [x.name for x in HICPConfigure.fields_desc \
          if x.name not in ("target", "padding")]

if len(argv) != 4:
    print("Usage: {0} ip_address parameter value".format(argv[0]))
    exit(-1)
elif argv[2] not in PARAMS:
    print("Parameter can be: {0}".format(", ".join(PARAMS)))
    exit(-1)

# Prepare
target = IP(dst=argv[1])/UDP(dport=3250, sport=3250)
param, value = argv[2], argv[3]

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
    dns2=resp.dns2
)
setattr(conf, param, value) 

# Send it and check response
send(target/conf, verbose=False)
resp = sniff(filter="port 3250", count=1)[0]
if resp.hicp_command == b"Reconfigured":
    print("Configuration successful: {0} = {1}.".format(param, value))
elif resp.hicp_command == b"Invalid Configuration":
    print("Configuration failed: {0} = {1}.".format(param, value))
else:
    print("Unknown response received.")

