#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

struct ipv4_packet {
    uint8_t vhl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr source, destination; /* source and dest address */
};

uint8_t ipv4_version(const struct ipv4_packet* ip);
uint8_t ipv4_header_length(const struct ipv4_packet* ip);
uint16_t ipv4_dscp(const struct ipv4_packet* ip);
uint16_t ipv4_ecn(const struct ipv4_packet* ip);
uint16_t ipv4_total_length(const struct ipv4_packet* ip);
uint16_t ipv4_identification(const struct ipv4_packet* ip);
uint16_t ipv4_offset(const struct ipv4_packet* ip);
bool ipv4_dont_fragment(const struct ipv4_packet* ip);
bool ipv4_more_fragments(const struct ipv4_packet* ip);
uint16_t ipv4_checksum(const struct ipv4_packet* ip);
void ipv4_inetaddress_to_string(const struct in_addr* address, char* buffer);