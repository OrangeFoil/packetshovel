#pragma once
#include <stdbool.h>
#include <stdint.h>

struct tcp_segment {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    uint16_t drf;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

uint8_t tcp_data_offset(const struct tcp_segment *s);
uint8_t tcp_reserved(const struct tcp_segment *s);
bool tcp_flag_urg(const struct tcp_segment *s);
bool tcp_flag_ack(const struct tcp_segment *s);
bool tcp_flag_psh(const struct tcp_segment *s);
bool tcp_flag_rst(const struct tcp_segment *s);
bool tcp_flag_syn(const struct tcp_segment *s);
bool tcp_flag_fin(const struct tcp_segment *s);