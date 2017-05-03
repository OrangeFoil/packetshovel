#pragma once
#include "ethernet_frame.h"
#include <pcap.h>

int connect_esper();
void packet_callback(uint8_t *args, const struct pcap_pkthdr *header,
                     const uint8_t *packet);
int start_sniffing(char *dev);
void dissect_ipv4(const struct ethernet_frame *ethernet,
                  const struct pcap_pkthdr *header, const uint8_t *packet);
void dissect_ipv6(const struct ethernet_frame *ethernet,
                  const struct pcap_pkthdr *header, const uint8_t *packet);
