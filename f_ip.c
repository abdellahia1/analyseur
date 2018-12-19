//#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#define NOFRAG 0x4000
#define MOREFRAG 0x2000

//#include "projet0.h"


int f_ip(const u_char* packet, int* size){

    struct ip* iphead=(struct ip*)(packet+*size);
    int pro;

    *size+=sizeof(struct ip);

    printf("    \033[33mIPv%u\n", iphead->ip_v);
    printf("    Header length : %i bytes\n", (iphead->ip_hl)*4);
    printf("    Type of Service : 0x%.2x\n", iphead->ip_tos);
    printf("    Total lenght : %i octets\n", ntohs(iphead->ip_len));
    printf("    Identification : 0x%.4x\n", ntohs(iphead->ip_id));
    printf("    Fragment offset field : 0x%.4x", ntohs(iphead->ip_off));
    switch(ntohs(iphead->ip_off)){
        case NOFRAG:
            printf("    (Dont't fagment flag)\n");
            break;
        case MOREFRAG:
            printf("    (More fragments flag)\n");
            break;
        default:
            printf("\n");
            break;
    }
    printf("    Time to live : %i\n", iphead->ip_ttl);
    printf("    Prot : %i\n", iphead->ip_p);
    switch(iphead->ip_p){
        case IS_TCP:
            printf("    Protocol : TCP\n");
            pro=IS_TCP;
            break;
        case IS_UDP:
            printf("    Protocol : UDP\n");
            pro=IS_UDP;
            break;
        case IS_ICMP:
            printf("    Protocol : ICMP\n");
            pro=IS_ICMP;
            break;
        case IS_SCTP:
            printf("    Protocol : SCTP\n");
            pro=IS_SCTP;
            break;
        default:
            printf("\n");
            break;
    }
    printf("    Checksum : 0x%.4x\n", ntohs(iphead->ip_sum));
    printf("    IP source : %s\n", inet_ntoa(iphead->ip_src));
    printf("    IP destination : %s\n", inet_ntoa(iphead->ip_dst));
    printf("\033[00m");
    printf("\n");

    switch(pro){
        case IS_TCP:
            return IS_TCP;
        case IS_UDP:
            return IS_UDP;
        case IS_ICMP:
            return IS_ICMP;
        case IS_SCTP:
            return IS_SCTP;
    }

    return(0);
}



