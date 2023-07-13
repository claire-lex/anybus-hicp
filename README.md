HICP (Host Interface Control Protocol)
======================================

HICP is a protocol used by HMS software and devices to discover and change the
network settings of Anybus devices over IP.

This repository contains useful stuff to talk to devices using HICP:

- `hicp.py`: HICP layer for Scapy
- `discovery.py`: Discover HICP devices on a network (broadcast)
- `config.py`: Change the network configurations of a HICP device

> Please note that Anybus devices usually broadcast everything: a device will
  probably reply to your messages (even direct messages) on address
  255.255.255.255.
