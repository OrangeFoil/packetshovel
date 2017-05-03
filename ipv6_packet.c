#include "ipv6_packet.h"
#include <byteswap.h>

uint32_t ipv6_version(const struct ipv6_packet *ip) {
    return ip->vtf >> 28;
}

uint32_t ipv6_traffic_class(const struct ipv6_packet *ip) {
    return (ip->vtf & 0x0FF0000) >> 20;
}

uint32_t ipv6_flow_label(const struct ipv6_packet *ip) {
    return ip->vtf & 0x000FFFFF;
}

uint16_t ipv6_payload_length(const struct ipv6_packet *ip) {
    return bswap_16(ip->payload_length);
}

void ipv6_inetaddress_to_string(const struct in6_addr *address, char *buffer) {
    inet_ntop(AF_INET6, address, buffer, sizeof(char) * INET6_ADDRSTRLEN);
}
