#include "ethernet_frame.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

uint16_t ethernet_priority_code_point(const struct ethernet_frame_tagged *eth) {
    return ntohs(eth->tag_control_information) >> 13;
}

bool ethernet_drop_eligible_indicator(const struct ethernet_frame_tagged *eth) {
    return ntohs(eth->tag_control_information) & 0x1000;
}

uint16_t ethernet_vlan_identifier(const struct ethernet_frame_tagged *eth) {
    return ntohs(eth->tag_control_information) & 0x0fff;
}
