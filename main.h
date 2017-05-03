#pragma once
#include <pcap.h>

int connect_esper();
void packet_callback(uint8_t *args, const struct pcap_pkthdr *header,
                     const uint8_t *packet);
int start_sniffing(char *dev);
void dissect_ipv4(const struct sniff_ethernet *ethernet,
                  const struct pcap_pkthdr *header,
                  const uint8_t *packet);
void dissect_ipv6(const struct sniff_ethernet *ethernet,
                  const struct pcap_pkthdr *header,
                  const uint8_t *packet);
