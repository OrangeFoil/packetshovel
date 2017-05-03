#pragma once
#include <stdint.h>
#include <arpa/inet.h>

struct ipv6_packet {
    uint32_t vtf;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    struct in6_addr source, destination;
};

uint32_t ipv6_version(const struct ipv6_packet* ip);
uint32_t ipv6_traffic_class(const struct ipv6_packet* ip);
uint32_t ipv6_flow_label(const struct ipv6_packet* ip);
uint16_t ipv6_payload_length(const struct ipv6_packet* ip);
void ipv6_inetaddress_to_string(const struct in6_addr* address, char* buffer);