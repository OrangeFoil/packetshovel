#pragma once
#include <stdint.h>

struct udp_segment {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
}