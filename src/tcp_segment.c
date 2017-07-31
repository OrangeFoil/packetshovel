#include "tcp_segment.h"
#include <netinet/in.h>

uint8_t tcp_data_offset(const struct tcp_segment *s) {
    return ntohs(s->drf) >> 16;
}

uint8_t tcp_reserved(const struct tcp_segment *s) {
    return (ntohs(s->drf) >> 12) & 0x003F;
}

bool tcp_flag_urg(const struct tcp_segment *s) {
    return ntohs(s->drf) & 0x0020;
}

bool tcp_flag_ack(const struct tcp_segment *s) {
    return ntohs(s->drf) & 0x0010;
}

bool tcp_flag_psh(const struct tcp_segment *s) {
    return ntohs(s->drf) & 0x0008;
}

bool tcp_flag_rst(const struct tcp_segment *s) {
    return ntohs(s->drf) & 0x0004;
}

bool tcp_flag_syn(const struct tcp_segment *s) {
    return ntohs(s->drf) & 0x0002;
}

bool tcp_flag_fin(const struct tcp_segment *s) {
    return ntohs(s->drf) & 0x0001;
}
