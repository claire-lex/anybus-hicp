HICP (Host Interface Control Protocol)
======================================

HICP is a protocol used by HMS Networks software and devices to discover and
change the network settings of Anybus devices over IP.

This repository contains useful stuff to talk to Anybus devices using HICP and
several protocols and proof of concepts for CVE targeting Anybus X-Gateway
devices.

## HICP

- `hicp.py`: HICP layer for Scapy (pushed to Scapy main)

- `hicp_discovery.py`: Discover HICP devices on a network (broadcast)
- `hicp_config.py`: Change the network configurations of a HICP device

> Please note that Anybus devices usually broadcast everything: a device will
  probably reply to your messages (even direct messages) on address
  255.255.255.255.


## Ethernet/IP (only for Anybus X-Gateway with Ethernet/IP support)

- `enipTCP.py`: Ethernet/IP layer for Scapy (pushed to Scapy main)

- `enip_discovery.py`: Discover Ethernet/IP devices (not only Anybus)


## CVE proof of concept

I have published [3 vulnerabilities related to HICP](https://sensepost.com/blog/2024/targeting-an-industrial-protocol-gateway/).

| CVE ID | PoC |
|--------|-----|
| [CVE-2024-23765](https://nvd.nist.gov/vuln/detail/CVE-2024-23765) | Not available* |
| [CVE-2024-23766](https://nvd.nist.gov/vuln/detail/CVE-2024-23766) | `http_dos.py` |
| [CVE-2024-23767](https://nvd.nist.gov/vuln/detail/CVE-2024-23767) | `hicp_bruteforce.py` |

- `hicp_bruteforce.py`: Bruteforce the password when it is enabled (requires a
  wordlist)
- `cve-2024-23766.py`: Constantly send unauthenticated reboot web requests to
  make the device reboot over and over again (Denial of Service)

> *Due to CVE-2024-23765's dangerousness and difficulty to remediate, the PoC is
  not public.