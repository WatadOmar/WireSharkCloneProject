#include <stdio.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include "sniffer.h"




// Global variables
FILE *output = NULL;
statistics_t statistics = {0};

void print_usage(FILE *stream, int exit_code) {
    fprintf(stream, "Usage: main [options]\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  -h, \t\tPrint this help message\n");
    fprintf(stream, "  -v, \t\tPrint version information\n");
    fprintf(stream, "  -o, \t\tSpecify a file to write output to. If not specificed, it is writted to stdout\n");
    fprintf(stream, "  -t, \t\tParse TCP header\n");
    fprintf(stream, "  -u, \t\tParse UDP header\n");
    fprintf(stream, "  -i, \t\tParse ICMP header\n");
    fprintf(stream, "  -6, \t\tParse IPV6 header\n");
    fprintf(stream, "  -s, \t\tParse SCTP header\n");
    fprintf(stream, "  -g, \t\tParse IGMP header\n");
    fprintf(stream, "  -4, \t\tParse IPV4 header\n");
    exit(exit_code);
}

void signal_handler(int signal) {
    printf(" Signal %d received\n", signal);
    if (output != NULL && output != stdout) {
        fclose(output);
    }
    exit(0);
}

int setup_signal_handlers() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
}

int main(int argc, char *argv[]) {

    configuration_parameters_t configuration_parameters = {false, false, false, false, false, NULL};


    // use get opts to enable arguments parsing
    int c;
    while ((c = getopt(argc, argv, "tui46sgho:")) != -1) {
        switch (c) {
            case 't':
                configuration_parameters.enable_TCP_header_parsing = true;
                break;
            case 'u':
                configuration_parameters.enable_UDP_header_parsing = true;
                break;
            case 'i':
                configuration_parameters.enable_ICMP_header_parsing = true;
                break;
            case '6':
                configuration_parameters.enable_IPv6_header_parsing = true;
                break;
            case '4':
                configuration_parameters.enable_IPv4_header_parsing = true;
                break;
            case 'o':
                configuration_parameters.output_file = optarg;
                break;
            case 's':
                configuration_parameters.enable_SCTP_header_parsing = true;
                break;
            case 'g':
                configuration_parameters.enable_IGMP_header_parsing = true;
                break;
            case 'h':
                print_usage(stdout, 0);
            default:
                print_usage(stderr, 1);
                break;
        }
    }

    // open the output file
    output = stdout;
    if (configuration_parameters.output_file != NULL) {
        output = fopen(configuration_parameters.output_file, "w");
    }


    // create a raw socket and start listening to it.
    // if a packet is received, parse it and print it to the output file
    // if no output file is specified, print it to stdout
    // if no header is specified, print all headers
    // if a header is specified, print only that header
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        fprintf(output, "Error creating socket\n");
        return 1;
    }

    // create a buffer to store the packet
    unsigned char buffer[65536];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    ssize_t data_size = recvfrom(sock, buffer, 65536, 0, &saddr, (socklen_t *) &saddr_len);
    if (data_size < 0) {
        fprintf(output, "Error receiving data\n");
        return 1;
    }

    // print the packet
    fprintf(output, "Packet received\n");
    for (int i = 0; i < data_size; i++) {
        fprintf(output, "%02x ", buffer[i]);
        if ((i + 1) % 16 == 0) {
            fprintf(output, "\n");
        }
    }

    // Update the statistics
    statistics.total_packets++;
    statistics.total_bytes += data_size;

    // process the packet
    // parse the ethernet header
    print_ethernet_header(buffer, configuration_parameters);

    // parse the IP header
    struct iphdr *ip = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    fprintf(output, "  |-IP Version        : %d\n", (unsigned int) ip->version);

    // parse IPV6 or IPV4 header
    if (ip->version == 6) {
        statistics.total_IPv6_packets++;
        print_IPV6_header(buffer, configuration_parameters);

    } else if (ip->version == 4) {
        statistics.total_IPv4_packets++;
        print_IPV4_header(buffer, configuration_parameters);

    }

    // Check the protocol and do accordingly...
    switch (ip->protocol) {
        case IPPROTO_TCP: //TCP Protocol
        {
            statistics.total_TCP_packets++;
            print_TCP_Protocol_header(buffer, configuration_parameters);
        }
            break;

        case IPPROTO_UDP: //UDP Protocol
        {
            statistics.total_UDP_packets++;
            print_UDP_Protocol_header(buffer, configuration_parameters);

        }
            break;

        case IPPROTO_ICMP: //ICMP Protocol
        {
            statistics.total_ICMP_packets++;
            print_ICMP_Protocol_header(buffer, configuration_parameters);
        }
            break;

        case IPPROTO_ICMPV6: //ICMPv6 Protocol
        {
            statistics.total_ICMPV6_packets++;
            print_ICMPV6_Protocol_header(buffer, configuration_parameters);
        }
            break;

        case IPPROTO_SCTP: //SCTP Protocol
        {
            statistics.total_SCTP_packets++;
            print_SCTP_Protocol_header(buffer, configuration_parameters);

        }
            break;

        case IPPROTO_IGMP: //IGMP Protocol
        {
            statistics.total_IGMP_packets++;
            print_IGMP_Protocol_header(buffer, configuration_parameters);
        }
            break;


        default: //Some Other Protocol like ARP etc.
            fprintf(output, "  |-Protocol : %d", (unsigned int) (ip->protocol));
            break;
    }
}

void
print_IGMP_Protocol_header(const unsigned char *buffer, configuration_parameters_t config) {// parse the IGMP header
    struct igmp *igmp = (struct igmp *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if (config.enable_IGMP_header_parsing) {
        fprintf(output, "  |-Type : %d\n", (unsigned int) (igmp->igmp_type));
        fprintf(output, "  |-Max Resp Time : %d\n", (unsigned int) (igmp->igmp_code));
        fprintf(output, "  |-Checksum : %d\n", ntohs(igmp->igmp_cksum));
    }
}

void
print_SCTP_Protocol_header(const unsigned char *buffer, configuration_parameters_t config) {// parse the SCTP header
    struct sctphdr *sctp = (struct sctphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if (config.enable_SCTP_header_parsing) {
        fprintf(output, "  |-Source Port      : %d\n", ntohs(sctp->source));
        fprintf(output, "  |-Destination Port : %d\n", ntohs(sctp->destination));
        fprintf(output, "  |-Verification Tag : %d\n", ntohl(sctp->verificationTag));
        fprintf(output, "  |-Checksum         : %d\n", ntohs(sctp->adler32));
    }
}

void
print_ICMPV6_Protocol_header(const unsigned char *buffer, configuration_parameters_t config) {// parse the ICMPv6 header
    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
    if (config.enable_ICMP_header_parsing) {
        fprintf(output, "  |-Type : %d", (unsigned int) (icmp6->icmp6_type));
        fprintf(output, "  |-Code : %d", (unsigned int) (icmp6->icmp6_code));
        fprintf(output, "  |-Checksum : %d", ntohs(icmp6->icmp6_cksum));
    }
}

void
print_ICMP_Protocol_header(const unsigned char *buffer, configuration_parameters_t config) {// parse the ICMP header
    struct icmphdr *icmp = (struct icmphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if (config.enable_ICMP_header_parsing) {
        fprintf(output, "  |-Type : %d\n", (unsigned int) (icmp->type));
        fprintf(output, "  |-Code : %d\n", (unsigned int) (icmp->code));
        fprintf(output, "  |-Checksum : %d\n", ntohs(icmp->checksum));
    }
}

void print_UDP_Protocol_header(const unsigned char *buffer, configuration_parameters_t config) {// parse the UDP header
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if (config.enable_UDP_header_parsing) {
        fprintf(output, "  |-Source Port      : %d\n", ntohs(udp->source));
        fprintf(output, "  |-Destination Port : %d\n", ntohs(udp->dest));
        fprintf(output, "  |-UDP Length       : %d\n", ntohs(udp->len));
        fprintf(output, "  |-UDP Checksum     : %d\n", ntohs(udp->check));
    }
}

void print_TCP_Protocol_header(const unsigned char *buffer, configuration_parameters_t config) {// parse the TCP header
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if (config.enable_TCP_header_parsing) {
        fprintf(output, "  |-Source Port      : %u\n", ntohs(tcp->source));
        fprintf(output, "  |-Destination Port : %u\n", ntohs(tcp->dest));
        fprintf(output, "  |-Sequence Number    : %u\n", ntohl(tcp->seq));
        fprintf(output, "  |-Acknowledge Number : %u\n", ntohl(tcp->ack_seq));
        fprintf(output, "  |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int) tcp->doff,
                (unsigned int) tcp->doff * 4);
        fprintf(output, "  |-Urgent Flag          : %d\n", (unsigned int) tcp->urg);
        fprintf(output, "  |-Acknowledgement Flag : %d\n", (unsigned int) tcp->ack);
        fprintf(output, "  |-Push Flag            : %d\n", (unsigned int) tcp->psh);
        fprintf(output, "  |-Reset Flag           : %d\n", (unsigned int) tcp->rst);
        fprintf(output, "  |-Synchronise Flag     : %d\n", (unsigned int) tcp->syn);
        fprintf(output, "  |-Finish Flag          : %d\n", (unsigned int) tcp->fin);
        fprintf(output, "  |-Window         : %d\n", ntohs(tcp->window));
        fprintf(output, "  |-Checksum       : %d\n", ntohs(tcp->check));
        fprintf(output, "  |-Urgent Pointer : %d\n", tcp->urg_ptr);
    }
}

void print_IPV4_header(const unsigned char *buffer, configuration_parameters_t config) {

    const struct iphdr *ip = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    if (config.enable_IPv4_header_parsing) {    // declare local address variables for storing the source and destination addresses
        struct in_addr source, dest;
        memset(&source, 0, sizeof(source));
        memset(&dest, 0, sizeof(dest));

        // copy the source and destination addresses from the ip header
        source.s_addr = ip->saddr;
        dest.s_addr = ip->daddr;
        fprintf(output, "  |-IPV4 Header\n");
        fprintf(output, "  |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int) ip->ihl,
                ((unsigned int) (ip->ihl)) * 4);
        fprintf(output, "  |-Type Of Service   : %d\n", (unsigned int) ip->tos);
        fprintf(output, "  |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(ip->tot_len));
        fprintf(output, "  |-Identification    : %d\n", ntohs(ip->id));
        fprintf(output, "  |-TTL      : %d\n", (unsigned int) ip->ttl);
        fprintf(output, "  |-Protocol : %d\n", (unsigned int) ip->protocol);
        fprintf(output, "  |-Checksum : %d\n", ntohs(ip->check));
        fprintf(output, "  |-Source IP        : %s\n", inet_ntoa(source));
        fprintf(output, "  |-Destination IP   : %s\n", inet_ntoa(dest));
    }
}

void print_IPV6_header(const unsigned char *buffer, configuration_parameters_t config) {
    if (config.enable_IPv6_header_parsing) {
        fprintf(output, "  |-IPV6 Header\n");

        char address[INET6_ADDRSTRLEN];
        // parse the IPV6 header
        struct ip6_hdr *ip6 = (struct ip6_hdr *) (buffer + sizeof(struct ethhdr));
        fprintf(output, "  |-IPV6 Version        : %d\n", (unsigned int) ip6->ip6_ctlun.ip6_un2_vfc);
        fprintf(output, "  |-IPV6 Traffic Class  : %d\n", (unsigned int) ip6->ip6_ctlun.ip6_un1.ip6_un1_flow);
        fprintf(output, "  |-IPV6 Flow Label     : %d\n", (unsigned int) ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
        fprintf(output, "  |-IPV6 Payload Length : %d\n", (unsigned int) ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
        fprintf(output, "  |-IPV6 Next Header    : %d\n", (unsigned int) ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
        fprintf(output, "  |-IPV6 Hop Limit      : %d\n", (unsigned int) ip6->ip6_ctlun.ip6_un2_vfc);
        fprintf(output, "  |-IPV6 Source Address : %s\n", inet_ntop(AF_INET6, &ip6->ip6_src, address, sizeof(address)));
        fprintf(output, "  |-IPV6 Destination Address : %s\n",
                inet_ntop(AF_INET6, &ip6->ip6_dst, address, sizeof(address)));
    }
}

void print_ethernet_header(const unsigned char *buffer, configuration_parameters_t config) {
    struct ethhdr *eth = (struct ethhdr *) buffer;
    fprintf(output, "Ethernet Header Details:    \n");
    fprintf(output, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1],
            eth->h_dest[2],
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(output, "  |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1],
            eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(output, "  |-Protocol            : %u\n", (unsigned short) eth->h_proto);
}

