#include "base64encode.c"
#include "structs.c"
#include <arpa/inet.h>
#include <byteswap.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SIZE_ETHERNET_HEADER 14

int esper_socket;
char errbuf[PCAP_ERRBUF_SIZE];

int connect_esper();
void packet_callback(uint8_t *args, const struct pcap_pkthdr *header,
                     const uint8_t *packet);
int start_sniffing(char *dev);
void dissect_ipv4(const struct sniff_ethernet *ethernet,
                  const struct pcap_pkthdr *header,
                  const uint8_t *packet);
void dissect_ipv6(const struct sniff_ethernet *ethernet,
                  const struct pcap_pkthdr *header,
                  const uint8_t *packet);

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) {
        printf("Syntax is: %s IP-Address Port [Interface]\n", argv[0]);
        return -1;
    }

    // connect to EsperCEP
    int port;
    sscanf(argv[2], "%d", &port);
    esper_socket = connect_esper(argv[1], port);

    // sniffing
    char *dev;
    if (argc != 4) {
        // find default device
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return 2;
        }
    } else {
        dev = argv[3];
    }
    int sniffer_return = start_sniffing(dev);

    // disconnect EsperCEP
    close(esper_socket);
    return sniffer_return;
}

int connect_esper(char *ip, int port) {
    int socket_desc;
    struct sockaddr_in server;

    // Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        printf("Unable to create socket\n");
    }

    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // Connect to remote server
    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Connection to EsperCEP failed\n");
        exit(-1);
        return 1;
    }

    printf("Connected to EsperCEP (%s:%i)\n", ip, port);
    return socket_desc;
}

int start_sniffing(char *dev) {
    pcap_t *handle;

    // open device
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open capture device %s: %s\n", dev, errbuf);
        return 2;
    }

    // determine the type of link-layer headers
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Capture device %s doesn't provide Ethernet headers - "
                        "not supported\n",
                dev);
        return 2;
    }

    // the actual sniffing
    pcap_loop(handle, -1, packet_callback, NULL);

    // stop sniffing and close connection to EsperCEP
    pcap_close(handle);
    return 0;
}

void packet_callback(uint8_t *args, const struct pcap_pkthdr *header,
                     const uint8_t *packet) {
    const struct sniff_ethernet *ethernet = (struct sniff_ethernet *)(packet);

    // analyse network layer
    if (bswap_16(ethernet->type) == 0x0800) {
        dissect_ipv4(ethernet, header, packet);
    } else if (bswap_16(ethernet->type) == 0x86DD) {
        dissect_ipv6(ethernet, header, packet);
    } else {
        printf("   * Ignored frame with ethertype 0x%x\n", bswap_16(ethernet->type));
    }
}

void dissect_ipv4(const struct sniff_ethernet *ethernet,
                  const struct pcap_pkthdr *header,
                  const uint8_t *packet) {
    const struct sniff_ipv4 *ip = (struct sniff_ipv4 *)(packet + SIZE_ETHERNET_HEADER);
    const uint8_t *payload; /* Packet payload */
    const uint32_t size_ip_header = IP_HL(ip) * 4;

    if (size_ip_header < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip_header);
        return;
    }

    const uint16_t offset = bswap_16(ip->off);

    char ip_source[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->source, ip_source, sizeof(ip_source));
    char ip_destination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->destination, ip_destination,
              sizeof(ip_destination));

    // encode payload in base64
    payload = (uint8_t *)(packet + SIZE_ETHERNET_HEADER + size_ip_header);
    const uint16_t payload_length = bswap_16(ip->len) - size_ip_header;
    char *const payload_encoded = malloc(payload_length * 1.6);
    const size_t payload_encoded_length = payload_length * 1.6;
    base64encode(payload, payload_length, payload_encoded,
                 payload_encoded_length);

    // create csv string
    char *const csv_buffer = malloc(sizeof(char) * (200 + payload_encoded_length));
    sprintf(csv_buffer,
            "%d,%d,%d,%d,%hu,%hu,%s,%s,%d,%hhu,%hhu,%hu,%s,%s,%s\n",
            IP_V(ip), IP_HL(ip), IP_DSCP(ip), IP_ECN(ip), bswap_16(ip->len),
            bswap_16(ip->id), offset & IP_DF ? "true" : "false",
            offset & IP_MF ? "true" : "false", offset & IP_OFFMASK, ip->ttl,
            ip->protocol, bswap_16(ip->checksum), ip_source, ip_destination,
            payload_encoded);
    // send csv to esper
    send(esper_socket, csv_buffer, strlen(csv_buffer), 0);
    printf("%s", csv_buffer);
    // free up ressouces
    free(payload_encoded);
    free(csv_buffer);
}

void dissect_ipv6(const struct sniff_ethernet *ethernet,
                  const struct pcap_pkthdr *header,
                  const uint8_t *packet) {
    const struct sniff_ipv6 *ip = (struct sniff_ipv6 *)(packet + SIZE_ETHERNET_HEADER);
    const char *payload;         /* Packet payload */
    const uint32_t size_ip_header = 40; // Note that possible IPv6 extension headers are
                                  // currently considered part of the payload

    uint32_t vtf = bswap_16(ip->vtf);
    char ip_source[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip->source, ip_source, sizeof(ip_source));
    char ip_destination[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip->destination, ip_destination,
              sizeof(ip_destination));

    char csv_buffer[1500];
    sprintf(csv_buffer, "%u, %u, %u, %hu, %hhu, %hhu, %s, %s\n",
            vtf >> 28, (vtf & 0x0FF0000) >> 20,  vtf & 0x000FFFFF,
            bswap_16(ip->payload_length),
            ip->next_header, ip->hop_limit, ip_source, ip_destination);
    // TODO teach Esper IPv6, and send IPv6 events via socket
    // send(esper_socket, csv_buffer , strlen(csv_buffer), 0);
    printf("%s", csv_buffer);
    printf("0x%x\n", ip->vtf);
}
