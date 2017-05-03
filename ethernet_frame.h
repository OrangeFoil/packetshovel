#pragma once
#include <stdint.h>

#define ETHERNET_ADDRESS_LENGTH 6

struct ethernet_frame {
    uint8_t destination[ETHERNET_ADDRESS_LENGTH];
    uint8_t source[ETHERNET_ADDRESS_LENGTH];
    uint16_t type;
};
