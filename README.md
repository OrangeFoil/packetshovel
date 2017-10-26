Packet Shovel                         {#mainpage}
=============


# Installation #
## Requirements ##
- libpcap
- GNU make
- gcc

## Compilation ##
> make all  
> make install


# Usage #
To start Packet Shovel use the following command
> packetshovel \<IP Address\> \<Port\> [Interface]

| Argument   | Description                                                               |
|:-----------|:--------------------------------------------------------------------------|
| IP Address | IP Address of an EsperIO socket                                           |
| Port       | Port of an EsperIO socket that is configured to accept CSV formatted data |  
| Interface  | (Optional) Interface to sniff on                                          |

If no interface is specified Packet Shovel tries to detect the default interface


# EsperIO configuration #
Esper must be configured to accept CSV formatted events on a network socket. Packet Shovel reports two types of events:
- IPv4Packet
- IPv6Packet

The event type information that are being transmitted are the respective IPv4/IPv6 header fields, the base64 encoded payload and the VLAN ID of the underlying ethernet frame.
