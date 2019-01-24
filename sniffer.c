#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "sniffer.h"
#include "inet_hdr.h"
#include "traffic.h"
#include "help.h"

/* Buffer for hardware address. */
static char hw_addr_str[32] = {0};

/* Create a raw socket. */
int rsock_create(const int protocol)
{
    int sockfd = socket(AF_PACKET, SOCK_RAW, protocol);
    if (sockfd < 0)
    {
        perror("socket error: ");
        exit(1);
    }
    return sockfd;
}

void rsock_close(int sockfd)
{
    close(sockfd);
}

/* Set the network interface to promiscuous mode. */
bool rsock_do_promisc(int sockfd, const char *nif)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, nif, strlen(nif) + 1);
    if ((ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1))
    {
        perror("ioctl get: ");
        //return false;
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1)
    {
        perror("ioctl set: ");
        return false;
    }
    return true;
}

/* Receive packets from raw socket. */
int rsock_receive(int sockfd, char *recvbuf, int buflen, struct sockaddr_in *from, int *addrlen)
{
    int recvlen;
    recvlen = recvfrom(sockfd, recvbuf, buflen, 0, (struct sockaddr *) from, (socklen_t *) addrlen);
    recvbuf[recvlen] = '\0';
    return recvlen;
}

/* Create sniffer. */
sniffer *sniffer_create(int protocol)
{
    sniffer *sniffer = malloc(sizeof (*sniffer));
    if (!sniffer)
    {
        write_log("malloc failed!");
        exit(EXIT_FAILURE);
    }
    sniffer->max_packet_len = 2048;
    sniffer->sockfd = rsock_create(protocol);
    sniffer->packet = malloc(sizeof (*sniffer->packet) * sniffer->max_packet_len);
    if (!sniffer->packet)
    {
        free(sniffer);
        write_log("malloc failed!");
        exit(EXIT_FAILURE);
    }
    memset(&sniffer->filter, 0, sizeof (sniffer->filter));

    return sniffer;
}

void sniffer_free(sniffer *sniffer)
{
    free(sniffer->packet);
    free(sniffer);
}

/* set the socket to promiscuous mode to capture all packets. */
bool sniffer_init(sniffer *sniffer, const char *iface)
{
    return rsock_do_promisc(sniffer->sockfd, iface);
}

/* Capture packets; */
void sniffer_sniff(sniffer *sniffer)
{
    struct sockaddr_in from;
    int sockaddr_len = sizeof (struct sockaddr_in);
    int recvlen = 0;

    while (true)
    {
        recvlen = rsock_receive(sniffer->sockfd, sniffer->packet, sniffer->max_packet_len, &from, &sockaddr_len);
        if (recvlen > 0)
        {
            sniffer_analyze(sniffer);
        }
        else
        {
            continue;
        }
    }
}

/* Analyze packets. */
void sniffer_analyze(sniffer *sniffer)
{
    ether_header_t *etherpacket = (ether_header_t *) sniffer->packet;
    if (sniffer->filter.protocol == 0)
        sniffer->filter.protocol = 0xff;
    switch (ntohs(etherpacket->frametype))
    {
        case 0x0800:
            if (((sniffer->filter.protocol) >> 1))
            {
                write_log("\n/*---------------ip packet--------------------*/\n");
                parse_ip_packet(sniffer);
            }
            break;
        case 0x0806:
            //if (sniffer_test_bit(sniffer->filter.protocol, ARP_BIT))
            //{
                write_log("\n/*--------------arp packet--------------------*/\n");
                //parse_arp_packet(sniffer);
            //}
            break;
        default:
            write_log("\n/*--------------Unknown packet----------------*/\n");
            write_log("Unknown ethernet frametype!\n");
            break;
    }
}

/* Analyze IP packets. */
void parse_ip_packet(sniffer *sniffer)
{
    ip_packet_t *ippacket = (ip_packet_t *) sniffer->packet;

    write_log("IP header->protocol: %d\n", ippacket->ipheader.protocol);

    if (sniffer->filter.sip != 0)
    {
        if (sniffer->filter.sip != (ippacket->ipheader.src_ip))
            return;
    }
    if (sniffer->filter.dip != 0)
    {
        if (sniffer->filter.dip != (ippacket->ipheader.des_ip))
            return;
    }

    switch ((int) ippacket->ipheader.protocol)
    {
        case IPPROTO_ICMP:
            //if (sniffer_test_bit(sniffer->filter.protocol, ICMP_BIT))
            //{
                write_log("Received an ICMP packet\n");
                parse_icmp_packet(sniffer);
            //}
            break;
        case IPPROTO_TCP:
            //if (sniffer_test_bit(sniffer->filter.protocol, TCP_BIT))
            //{
                write_log("Received an TCP packet\n");
                parse_tcp_packet(sniffer);
            //}
            break;
        case IPPROTO_UDP:
            //if (sniffer_test_bit(sniffer->filter.protocol, UDP_BIT))
            //{
                write_log("Received an UDP packet");
                parse_udp_packet(sniffer);
            //}
            break;
        default:
            write_log("Unknown ip protocol type.\n");
            break;
    }
}

/* Analyze UDP packets. */
void parse_udp_packet(sniffer *sniffer)
{
    udp_packet_t *udppacket = (udp_packet_t *) sniffer->packet;
    traffic_add(udppacket->ipheader.src_ip);

    write_log("MAC address: from %s to %s\n",
           get_hw_addr_str(hw_addr_str, udppacket->etherheader.src_hw_addr),
           get_hw_addr_str(hw_addr_str, udppacket->etherheader.des_hw_addr));

    write_log("IP address: from %s to %s\n",
           get_ip_addr_str(udppacket->ipheader.src_ip),
           get_ip_addr_str(udppacket->ipheader.des_ip));

    write_log("Source port: %d\nDestination port: %d\n"
           "Total length: %d\n",
           udppacket->udpheader.src_port,
           udppacket->udpheader.des_port,
           ntohs(udppacket->udpheader.len));
}

/* Analyze TCP packets. */
void parse_tcp_packet(sniffer *sniffer)
{
    tcp_packet_t *tcppacket = (tcp_packet_t *) sniffer->packet;
    traffic_add(tcppacket->ipheader.src_ip);

    write_log("MAC address: from %s to %s\n",
           get_hw_addr_str(hw_addr_str, tcppacket->etherheader.src_hw_addr),
           get_hw_addr_str(hw_addr_str, tcppacket->etherheader.des_hw_addr));

    write_log("IP address: from %s to %s\n",
           get_ip_addr_str(tcppacket->ipheader.src_ip),
           get_ip_addr_str(tcppacket->ipheader.des_ip));

    write_log("Source port: %d\nDestination port: %d\n"
           "Sequence number: %d\n Acknowledge number: %d\n",
           tcppacket->tcpheader.src_port,
           tcppacket->tcpheader.des_port,
           ntohl(tcppacket->tcpheader.seq),
           ntohl(tcppacket->tcpheader.ack));
}

/* Analyze ICMP packets. */
void parse_icmp_packet(sniffer *sniffer)
{
    icmp_packet_t *icmppacket = (icmp_packet_t *) sniffer->packet;
    traffic_add(icmppacket->ipheader.src_ip);

    write_log("MAC address: from %s to %s\n",
           get_hw_addr_str(hw_addr_str, icmppacket->etherheader.src_hw_addr),
           get_hw_addr_str(hw_addr_str, icmppacket->etherheader.des_hw_addr));

    write_log("IP address: from %s to %s\n",
           get_ip_addr_str(icmppacket->ipheader.src_ip),
           get_ip_addr_str(icmppacket->ipheader.des_ip));

    write_log("icmp type: %d\nicmp code: %d\n"
           "icmp id: %d\nicmp seq: %d.\n",
           icmppacket->icmpheader.type,
           icmppacket->icmpheader.code,
           ntohs(icmppacket->icmpheader.id),
           ntohs(icmppacket->icmpheader.seq));
}

char *get_hw_addr_str(char *hw_addr_str, const unsigned char *ptr)
{
    sprintf(hw_addr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
    return hw_addr_str;
}

char *get_ip_addr_str(const unsigned long ip)
{
    return inet_ntoa(*(struct in_addr *) &(ip));
}
