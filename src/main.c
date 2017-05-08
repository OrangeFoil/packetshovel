#include "main.h"
#include "base64encode.h"
#include "esper_socket.h"
#include "ethernet_frame.h"
#include "ipv4_packet.h"
#include "ipv6_packet.h"
#include <arpa/inet.h>
#include <byteswap.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE_ETHERNET_HEADER 14

char errbuf[PCAP_ERRBUF_SIZE];

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
    char *dev = NULL;
    if (argc == 4) {
        dev = argv[3];
    }
    start_sniffing(dev);

    // disconnect EsperCEP
    close(esper_socket);
    return 0;
}

void start_sniffing(char *dev) {
    pcap_t *handle;

    if (dev == NULL) {
        // find default device
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }

    // open device
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open capture device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    // determine the type of link-layer headers
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Capture device %s doesn't provide Ethernet headers - "
                        "not supported\n",
                dev);
        exit(EXIT_FAILURE);
    }

    // the actual sniffing
    printf("Sniffing on device %s\n", dev);
    pcap_loop(handle, -1, packet_callback, NULL);

    // stop sniffing and close connection to EsperCEP
    pcap_close(handle);
}

void packet_callback(uint8_t *args, const struct pcap_pkthdr *header,
                     const uint8_t *packet) {
    const struct ethernet_frame *ethernet = (struct ethernet_frame *)(packet);

    // analyse network layer
    if (bswap_16(ethernet->type) == 0x0800) {
        dissect_ipv4(ethernet, header, packet);
    } else if (bswap_16(ethernet->type) == 0x86DD) {
        dissect_ipv6(ethernet, header, packet);
    } else {
        printf("   * Ignored frame with ethertype 0x%x\n",
               bswap_16(ethernet->type));
    }
}

void dissect_ipv4(const struct ethernet_frame *ethernet,
                  const struct pcap_pkthdr *header, const uint8_t *packet) {
    const struct ipv4_packet *ip =
        (struct ipv4_packet *)(packet + SIZE_ETHERNET_HEADER);
    const uint8_t *payload; /* Packet payload */
    const uint32_t size_ip_header = ipv4_header_length(ip) * 4;

    if (size_ip_header < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip_header);
        return;
    }

    char ip_source[INET_ADDRSTRLEN];
    ipv4_inetaddress_to_string(&ip->source, ip_source);
    char ip_destination[INET_ADDRSTRLEN];
    ipv4_inetaddress_to_string(&ip->destination, ip_destination);

    // encode payload in base64
    payload = (uint8_t *)(packet + SIZE_ETHERNET_HEADER + size_ip_header);
    const uint16_t payload_length = ipv4_total_length(ip) - size_ip_header;
    char *const payload_encoded = malloc(payload_length * 1.6);
    const size_t payload_encoded_length = payload_length * 1.6;
    base64encode(payload, payload_length, payload_encoded,
                 payload_encoded_length);

    // create csv string
    char *const csv_buffer =
        malloc(sizeof(char) * (200 + payload_encoded_length));
    sprintf(csv_buffer, "%d,%d,%d,%d,%hu,%hu,%s,%s,%d,%hhu,%hhu,%hu,%s,%s,%s\n",
            ipv4_version(ip), ipv4_header_length(ip), ipv4_dscp(ip),
            ipv4_ecn(ip), ipv4_total_length(ip), ipv4_identification(ip),
            ipv4_dont_fragment(ip) ? "true" : "false",
            ipv4_more_fragments(ip) ? "true" : "false", ipv4_offset(ip),
            ip->time_to_live, ip->protocol, bswap_16(ip->checksum), ip_source,
            ip_destination, payload_encoded);
    // send csv to esper
    send(esper_socket, csv_buffer, strlen(csv_buffer), 0);
    printf("%s", csv_buffer);
    // free up ressouces
    free(payload_encoded);
    free(csv_buffer);
}

void dissect_ipv6(const struct ethernet_frame *ethernet,
                  const struct pcap_pkthdr *header, const uint8_t *packet) {
    const struct ipv6_packet *ip =
        (struct ipv6_packet *)(packet + SIZE_ETHERNET_HEADER);
    const char *payload; /* Packet payload */
    const uint32_t size_ip_header =
        40; // Note that possible IPv6 extension headers are
            // currently considered part of the payload

    char ip_source[INET6_ADDRSTRLEN];
    ipv6_inetaddress_to_string(&ip->source, ip_source);
    char ip_destination[INET6_ADDRSTRLEN];
    ipv6_inetaddress_to_string(&ip->destination, ip_destination);

    char csv_buffer[1500];
    sprintf(csv_buffer, "%u,%u,%u,%hu,%hhu,%hhu,%s,%s,\n", ipv6_version(ip),
            ipv6_traffic_class(ip), ipv6_flow_label(ip),
            ipv6_payload_length(ip), ip->next_header, ip->hop_limit, ip_source,
            ip_destination);
    // TODO teach Esper IPv6, and send IPv6 events via socket
    // send(esper_socket, csv_buffer , strlen(csv_buffer), 0);
    printf("%s", csv_buffer);
}
