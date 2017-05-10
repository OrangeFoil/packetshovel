#pragma once
#include "ethernet_frame.h"
#include <pcap.h>
#include <stdint.h>

char errbuf[PCAP_ERRBUF_SIZE];

void sniffer_callback(uint8_t *args, const struct pcap_pkthdr *header,
                      const uint8_t *packet);
void sniffer_start(char *dev);
void dissect_ipv4(const uint32_t size_ethernet_header,
                  const struct pcap_pkthdr *header, const uint8_t *packet,
                  const uint16_t *vlan_id);
void dissect_ipv6(const uint32_t size_ethernet_header,
                  const struct pcap_pkthdr *header, const uint8_t *packet,
                  const uint16_t *vlan_id);
