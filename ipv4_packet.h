/*
struct ipv4_packet matches the layout of the IPv4 header according to RFC 791.
Note that "type_of_service" was redefined in RFC 3168 and RFC 3260 as DSCP and
ECN. The functions ipv4_dscp() and ipv4_ecn() return the respective header
values in the modern interpretation.

With the exception of time_to_live and protocol, all values must be accessed by
passing the struct to the provided fucntions prefixed with "ipv4_"!
The two reasons for this are:
- a header field has a length other than 8, 16 or 32 bits and the true value has
  to be determined by masking and/or shifting
- a header field has a length higher than 8 and endianness needs to corrected
  from big endian (network byte order) to little endian (x86)
*/

#pragma once
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

struct ipv4_packet {
    uint8_t vhl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr source, destination;
};

uint8_t ipv4_version(const struct ipv4_packet *ip);
uint8_t ipv4_header_length(const struct ipv4_packet *ip);
uint16_t ipv4_dscp(const struct ipv4_packet *ip);
uint16_t ipv4_ecn(const struct ipv4_packet *ip);
uint16_t ipv4_total_length(const struct ipv4_packet *ip);
uint16_t ipv4_identification(const struct ipv4_packet *ip);
uint16_t ipv4_offset(const struct ipv4_packet *ip);
bool ipv4_dont_fragment(const struct ipv4_packet *ip);
bool ipv4_more_fragments(const struct ipv4_packet *ip);
uint16_t ipv4_checksum(const struct ipv4_packet *ip);
void ipv4_inetaddress_to_string(const struct in_addr *address, char *buffer);
