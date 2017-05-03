#include "ipv4_packet.h"
#include <byteswap.h>

uint8_t ipv4_version(const struct ipv4_packet* ip) {
    return ip->vhl >> 4;
}

uint8_t ipv4_header_length(const struct ipv4_packet* ip) {
    return ip->vhl & 0x0f;
}

uint16_t ipv4_dscp(const struct ipv4_packet* ip) {
    return ip->type_of_service >> 2;
}

uint16_t ipv4_ecn(const struct ipv4_packet* ip) {
    return ip->type_of_service & 0x03;
}

uint16_t ipv4_total_length(const struct ipv4_packet* ip) {
    return bswap_16(ip->total_length);
}

uint16_t ipv4_identification(const struct ipv4_packet* ip) {
    return bswap_16(ip->identification);
}

uint16_t ipv4_offset(const struct ipv4_packet* ip) {
    return bswap_16(ip->offset) & 0x1fff;
}

bool ipv4_dont_fragment(const struct ipv4_packet* ip) {
    return bswap_16(ip->offset) & 0x4000; // TODO simplify to function without bswap
}

bool ipv4_more_fragments(const struct ipv4_packet* ip) {
    return bswap_16(ip->offset) & 0x2000; // TODO simplify to function without bswap
}

uint16_t ipv4_checksum(const struct ipv4_packet* ip) {
    return bswap_16(ip->checksum);
}

void ipv4_inetaddress_to_string(const struct in_addr* address, char* buffer) {
    inet_ntop(AF_INET, address, buffer, sizeof(char)*INET_ADDRSTRLEN);
}
