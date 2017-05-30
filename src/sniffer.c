#include "sniffer.h"
#include "base64encode.h"
#include "esper_socket.h"
#include "ethernet_frame.h"
#include "ipv4_packet.h"
#include "ipv6_packet.h"
#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sniffer_start(char *dev) {
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
    pcap_loop(handle, -1, sniffer_callback, NULL);

    // stop sniffing and close connection to EsperCEP
    pcap_close(handle);
}

void sniffer_callback(uint8_t *args, const struct pcap_pkthdr *header,
                      const uint8_t *packet) {
    const struct ethernet_frame *ethernet = (struct ethernet_frame *)(packet);

    // defaults for ethernet frame without VLAN tag
    uint32_t size_ethernet_header = 14;
    uint16_t ethertype = ntohs(ethernet->type);
    uint16_t vlan_id = 0x000;

    // adjustments for ethernet frames with VLAN tag
    if (ethertype == 0x8100) {
        size_ethernet_header = 18;
        const struct ethernet_frame_tagged *ethernet_tagged =
            (struct ethernet_frame_tagged *)(packet);
        ethertype = ntohs(ethernet_tagged->type);
        vlan_id = ethernet_vlan_identifier(ethernet_tagged);
    }

    // analyse network layer
    if (ethertype == 0x0800) {
        dissect_ipv4(size_ethernet_header, header, packet, &vlan_id);
    } else if (ethertype == 0x86DD) {
        dissect_ipv6(size_ethernet_header, header, packet, &vlan_id);
    } else {
        printf("   * Ignored frame with ethertype 0x%x\n", ethertype);
    }
}

void dissect_ipv4(const uint32_t size_ethernet_header,
                  const struct pcap_pkthdr *header, const uint8_t *packet,
                  const uint16_t *vlan_id) {
    const struct ipv4_packet *ip =
        (struct ipv4_packet *)(packet + size_ethernet_header);
    const uint8_t *payload;
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
    payload = (uint8_t *)(packet + size_ethernet_header + size_ip_header);
    const uint16_t payload_length = ipv4_total_length(ip) - size_ip_header;
    char *const payload_encoded = malloc(payload_length * 1.6);
    const size_t payload_encoded_length = payload_length * 1.6;
    base64encode(payload, payload_length, payload_encoded,
                 payload_encoded_length);

    // create csv string
    char *const csv_buffer =
        malloc(sizeof(char) * (512 + payload_encoded_length));
    sprintf(csv_buffer, "stream=IPv4Packet,version=%d,IHL=%d,DSCP=%d,ECN=%d,"
                        "totalLength=%hu,identification=%hu,dontFragment=%s,"
                        "moreFragments=%s,fragmentOffset=%d,timeToLive=%hhu,"
                        "protocol=%hhu,headerChecksum=%hu,sourceIP=%s,"
                        "destinationIP=%s,payload=%s,vlanID=%hu\n",
            ipv4_version(ip), ipv4_header_length(ip), ipv4_dscp(ip),
            ipv4_ecn(ip), ipv4_total_length(ip), ipv4_identification(ip),
            ipv4_dont_fragment(ip) ? "true" : "false",
            ipv4_more_fragments(ip) ? "true" : "false", ipv4_offset(ip),
            ip->time_to_live, ip->protocol, ntohs(ip->checksum), ip_source,
            ip_destination, payload_encoded, *vlan_id);
    // send csv to esper
    send(esper_socket, csv_buffer, strlen(csv_buffer), 0);
    printf("%s", csv_buffer);
    // free up ressouces
    free(payload_encoded);
    free(csv_buffer);
}

void dissect_ipv6(const uint32_t size_ethernet_header,
                  const struct pcap_pkthdr *header, const uint8_t *packet,
                  const uint16_t *vlan_id) {
    const struct ipv6_packet *ip =
        (struct ipv6_packet *)(packet + size_ethernet_header);
    const char *payload;
    const uint32_t size_ip_header =
        40; // Note that possible IPv6 extension headers are
            // currently considered part of the payload

    char ip_source[INET6_ADDRSTRLEN];
    ipv6_inetaddress_to_string(&ip->source, ip_source);
    char ip_destination[INET6_ADDRSTRLEN];
    ipv6_inetaddress_to_string(&ip->destination, ip_destination);

    // encode payload in base64
    payload = (uint8_t *)(packet + size_ethernet_header + size_ip_header);
    const uint16_t payload_length = ipv6_payload_length(ip);
    char *const payload_encoded = malloc(payload_length * 1.6);
    const size_t payload_encoded_length = payload_length * 1.6;
    base64encode(payload, payload_length, payload_encoded,
                 payload_encoded_length);

    char *const csv_buffer =
        malloc(sizeof(char) * (512 + payload_encoded_length));
    sprintf(
        csv_buffer,
        "stream=IPv6Packet,version=%u,trafficClass=%u,"
        "flowLabel=%u,payloadLength=%hu,nextHeader=%hhu,"
        "hopLimit=%hhu,sourceIP=%s,destinationIP=%s,payload=%s,vlanID=%hu\n",
        ipv6_version(ip), ipv6_traffic_class(ip), ipv6_flow_label(ip),
        ipv6_payload_length(ip), ip->next_header, ip->hop_limit, ip_source,
        ip_destination, payload_encoded, *vlan_id);
    send(esper_socket, csv_buffer, strlen(csv_buffer), 0);
    printf("%s", csv_buffer);

    // free up ressouces
    free(payload_encoded);
    free(csv_buffer);
}
