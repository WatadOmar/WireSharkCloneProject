
#ifndef FANTASTIC_OCTO_GIGGLE_WIRESHARK_SNIFFER_H
#define FANTASTIC_OCTO_GIGGLE_WIRESHARK_SNIFFER_H

#include <stdint-gcc.h>
#include <sys/types.h>

typedef struct configuration_parameters
{
    bool enable_TCP_header_parsing;
    bool enable_UDP_header_parsing;
    bool enable_ICMP_header_parsing;
    bool enable_IPv6_header_parsing;
    bool enable_IPv4_header_parsing;
    bool enable_SCTP_header_parsing;
    bool enable_IGMP_header_parsing;
    char *output_file;
} configuration_parameters_t;

typedef struct statistics
{
    unsigned long long total_packets;
    unsigned long long total_bytes;
    unsigned long long total_TCP_packets;
    unsigned long long total_UDP_packets;
    unsigned long long total_ICMP_packets;
    unsigned long long total_ICMPV6_packets;
    unsigned long long total_IPv6_packets;
    unsigned long long total_IPv4_packets;
    unsigned long long total_SCTP_packets;
    unsigned long long total_IGMP_packets;
} statistics_t;

/* SCTP header definition */
struct sctphdr {
    uint16_t source;
    uint16_t destination;
    u_int32_t verificationTag;
    u_int32_t adler32;
};

void print_ethernet_header(const unsigned char *buffer, configuration_parameters_t config);

void print_IPV6_header(const unsigned char *buffer, configuration_parameters_t config);

void print_IPV4_header(const unsigned char *buffer, configuration_parameters_t config);

void print_TCP_Protocol_header(const unsigned char *buffer, configuration_parameters_t config);

void print_UDP_Protocol_header(const unsigned char *buffer, configuration_parameters_t config);

void print_ICMP_Protocol_header(const unsigned char *buffer, configuration_parameters_t config);

void print_ICMPV6_Protocol_header(const unsigned char *buffer, configuration_parameters_t config);

void print_SCTP_Protocol_header(const unsigned char *buffer, configuration_parameters_t config);

void print_IGMP_Protocol_header(const unsigned char *buffer, configuration_parameters_t config);

#endif //FANTASTIC_OCTO_GIGGLE_WIRESHARK_SNIFFER_H
