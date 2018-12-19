#include <sys/socket.h>
//#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
//#include "projet0.h"

#include "net_ipv6.h"

int f_ipv6(const u_char* packet, int* size){
    int i;
    char str[INET6_ADDRSTRLEN];
    struct ipv6hdr* ip6head=(struct ipv6hdr*)(packet+*size);

    *size+=sizeof(struct ipv6hdr);

    printf("\033[33m    IPv%u\n", ip6head->ipv6_version);
    printf("    Flow label : 0x");
    for(i=0;i<3;i++)
        printf("%.2x",ip6head->ipv6_flow_lbl[i]);
    printf("\n");
    printf("    Payload length : %u\n", ntohs(ip6head->ipv6_len));
    printf("    Next header : ");
    switch(ip6head->ipv6_nextheader){
        case NEXTHDR_TCP :
        printf("TCP segment");
        break;
        case NEXTHDR_UDP :
            printf("UDP message");
        break;
        case NEXTHDR_IPV6:
            printf("IPv6 in IPv6");
        break;
        case NEXTHDR_ICMP:
            printf("ICMP for IPv6");
        break;
    }
    printf(" (%u)\n", ip6head->ipv6_nextheader);
    printf("    Hop limit : %u\n", ip6head->ipv6_hoplimit);
    inet_ntop(AF_INET6, &(ip6head->ipv6_src), str, INET6_ADDRSTRLEN);
    printf("    Source : %s\n", str);
    inet_ntop(AF_INET6, &(ip6head->ipv6_dst), str, INET6_ADDRSTRLEN);
    printf("    Destination : %s\n", str);
    printf("\n");
    printf("\033[00m");
    return(0);
}
