#pragma once
#include <stdbool.h>
#include <stdint.h>

#define ETHERNET_ADDRESS_LENGTH 6

struct ethernet_frame {
    uint8_t destination[ETHERNET_ADDRESS_LENGTH];
    uint8_t source[ETHERNET_ADDRESS_LENGTH];
    uint16_t type;
};

struct ethernet_frame_tagged {
    uint8_t destination[ETHERNET_ADDRESS_LENGTH];
    uint8_t source[ETHERNET_ADDRESS_LENGTH];
    uint16_t tag_protocol_identifier;
    uint16_t tag_control_information;
    uint16_t type;
};

uint16_t ethernet_priority_code_point(const struct ethernet_frame_tagged *eth);
bool ethernet_drop_eligible_indicator(const struct ethernet_frame_tagged *eth);
uint16_t ethernet_vlan_identifier(const struct ethernet_frame_tagged *eth);