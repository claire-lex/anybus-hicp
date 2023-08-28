HICP (Host Interface Control Protocol)
======================================

HICP is a protocol used by HMS software and devices to discover and change the
network settings of Anybus devices over IP.

This repository contains useful stuff to talk to Anybus devices using HICP and web requests.


## Using HICP

- `hicp.py`: HICP layer for Scapy (pushed to Scapy main)

- `hicp_discovery.py`: Discover HICP devices on a network (broadcast)
- `hicp_config.py`: Change the network configurations of a HICP device
- `hich_bruteforce.py`: Bruteforce the password when it is enabled (requires a
  wordlist)

> Please note that Anybus devices usually broadcast everything: a device will
  probably reply to your messages (even direct messages) on address
  255.255.255.255.

