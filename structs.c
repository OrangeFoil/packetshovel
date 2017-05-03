#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
    uint8_t dhost[ETHER_ADDR_LEN]; /* Destination host address */
    uint8_t shost[ETHER_ADDR_LEN]; /* Source host address */
    uint16_t type;                 /* IP? ARP? RARP? etc */
};

/* IPv4 header */
struct sniff_ipv4 {
    uint8_t vhl;                  /* version << 4 | header length >> 2 */
    uint8_t tos;                  /* type of service */
    uint16_t len;                 /* total length */
    uint16_t id;                  /* identification */
    uint16_t off;                 /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    uint8_t ttl;                  /* time to live */
    uint8_t protocol;             /* protocol */
    uint16_t checksum;            /* checksum */
    struct in_addr source, destination; /* source and dest address */
};
#define IP_HL(ip) (((ip)->vhl) & 0x0f)
#define IP_V(ip) (((ip)->vhl) >> 4)
#define IP_DSCP(ip) (((ip)->tos) >> 2)
#define IP_ECN(ip) (((ip)->tos) & 0x03)