/**
 * \file    ipv4_packet.h
 * \author  Marcus Legendre
 * \brief   Provides a struct and various functions to interpret IPv4 headers
 *
 * \details struct ipv4_packet matches the layout of the IPv4 header according
 * to RFC 791.\n
 * Note that "type_of_service" was redefined in RFC 3168 and RFC 3260 as DSCP
 * and
 * ECN. The functions ipv4_dscp() and ipv4_ecn() return the respective header
 * values in the modern interpretation.\n
 * With the exception of time_to_live and protocol, all values must be accessed
 * by
 * passing the struct to the provided fucntions prefixed with "ipv4_"!
 * The two reasons for this are:\n
 * - a header field has a length other than 8, 16 or 32 bits and the true value
 * has
 *   to be determined by masking and/or shifting
 * - a header field has a length higher than 8 and endianness needs to corrected
 *   from big endian (network byte order) to little endian (x86)
 */

#pragma once
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * \brief Matches the layout of the IPv4 header according to RFC 791
 */
struct ipv4_packet {
    /**
     * \brief Version and header length
     *
     * \see ipv4_version(const struct ipv4_packet *ip)
     * \see ipv4_header_length(const struct ipv4_packet *ip)
     */
    uint8_t vhl;
    /**
     * \brief Former Type of Service field. Redefined to ECN and DSCP in RFC
     * 3168 and RFC 3260.
     *
     * \see ipv4_dscp(const struct ipv4_packet *ip)
     * \see ipv4_ecn(const struct ipv4_packet *ip)
     */
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    /**
     * \brief Don't Fragment flag, more fragments flag and offset
     *
     * \see ipv4_dont_fragment(const struct ipv4_packet *ip)
     * \see ipv4_more_fragments(const struct ipv4_packet *ip)
     * \see ipv4_checksum(const struct ipv4_packet *ip)
     */
    uint16_t offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr source;
    struct in_addr destination;
};

/**
 * \brief Shifts the first 8 bits to in order to extract the version field
 *
 * \param ip  Pointer to struct ipv4_packet
 * \return    Should always return 4 for a valid IPv4 packet
 */
uint8_t ipv4_version(const struct ipv4_packet *ip);

/**
 * \brief Applies the a mask to get the header length field
 * \note This value needs to be multiplied by 4 to get the real header length.
 *
 * \param ip  Pointer to struct ipv4_packet
 * \return    Exact header length value as transmitted.
 */
uint8_t ipv4_header_length(const struct ipv4_packet *ip);

/**
 * \brief Shifts the type_of_service field in order to extract the DSCP field
 *
 * \param ip  Pointer to struct ipv4_packet
 * \return    DSCP field
 */
uint16_t ipv4_dscp(const struct ipv4_packet *ip);

/**
 * \brief Applies a mask to get the ECN field
 *
 * \param ip  Pointer to struct ipv4_packet
 * \return    ECN field
 */
uint16_t ipv4_ecn(const struct ipv4_packet *ip);

/**
 * \brief Corrects endianness of the total_length field
 *
 * \param ip  Pointer to struct ipv4_packet
 * \return    Total length field
 */
uint16_t ipv4_total_length(const struct ipv4_packet *ip);

/**
 * \brief Corrects endianness of the identification field
 *
 * \param ip  Pointer to struct ipv4_packet
 * \return    Identification field
 */
uint16_t ipv4_identification(const struct ipv4_packet *ip);

/**
 * \brief Applies a mask and corrects endianness to get the offset field
 *
 * \param ip  Pointer to struct ipv4_packet
 * \return    Offset field
 */
uint16_t ipv4_offset(const struct ipv4_packet *ip);

/**
 * \brief Checks the Don't Fragment flag
 *
 * \param ip  Pointer to struct ipv4_packet
 * \return    Don't Fragment flag
 */
bool ipv4_dont_fragment(const struct ipv4_packet *ip);

/**
 * \brief Checks the More Fragments flag
 *
 * \param ip  Pointer to struct ipv4_packet
 * \return    More Fragments flag
 */
bool ipv4_more_fragments(const struct ipv4_packet *ip);

/**
 * \brief Corrects endianness of the checksum field
 *
 * \param ip  Pointer to struct ipv4_packet
 * \return    Checksum field
 */
uint16_t ipv4_checksum(const struct ipv4_packet *ip);

/**
 * \brief Converts an IP from its binary representation to a more easily
 * readable string
 *
 * \param address   Pointer to a struct in_addr that should be converted.
 * \param buffer    Pointer to a string buffer the string should be written to.
 * Make sure the buffer is big enough!
 */
void ipv4_inetaddress_to_string(const struct in_addr *address, char *buffer);
