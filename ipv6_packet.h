/*
struct ipv6_packet matches the layout of the IPv4 header according to RFC 2460.

With the exception of next_header and hop_limit, all values must be accessed by
passing the struct to the provided fucntions prefixed with "ipv6_"!
The two reasons for this are:
- a header field has a length other than 8, 16 or 32 bits and the true value has
  to be determined by masking and/or shifting
- a header field has a length higher than 8 and endianness needs to corrected
  from big endian (network byte order) to little endian (x86)
*/
#pragma once
#include <arpa/inet.h>
#include <stdint.h>

struct ipv6_packet {
    uint32_t vtf;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    struct in6_addr source, destination;
};

uint32_t ipv6_version(const struct ipv6_packet *ip);
uint32_t ipv6_traffic_class(const struct ipv6_packet *ip);
uint32_t ipv6_flow_label(const struct ipv6_packet *ip);
uint16_t ipv6_payload_length(const struct ipv6_packet *ip);
void ipv6_inetaddress_to_string(const struct in6_addr *address, char *buffer);
