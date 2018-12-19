#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "icmp.h"
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>


void PrintData(const u_char* data, int* size) {
    int i; int j;
    for (i = 0; i < *size; i++) {
        if (i != 0 && i % 16 == 0)
        {
            printf("         ");
            for (j = i - 16; j < i; j++) {
                if (data[j] >= 32 && data[j] <= 128)
                    printf("%c", (unsigned char) data[j]);

                else printf(".");
            }
            printf("\n");
        }

        if (i % 16 == 0) printf("   ");
        printf(" %02X", (unsigned int) data[i]);

        if (i == *size - 1)
        {
            for (j = 0; j < 15 - i % 16; j++) printf("   ");

            printf("         ");

            for (j = i - i % 16; j <= i; j++) {
                if (data[j] > 31 && data[j] < 128) printf("%c", (unsigned char) data[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
}


int f_icmp(const u_char* packet, int* size){
    unsigned short iphdrlen;

    struct ip* iphead = (struct ip *) packet;
    iphdrlen = iphead->ip_hl * 4;
    struct icmphdr *icmph = (struct icmphdr *) (packet +*size);

    *size+=sizeof(struct icmphdr);

    printf("\033[36m");
    printf("        Type : ");
    switch(icmph->type) {
        case ICMP_ECHOREPLY:
            printf("Echo Reply");
            break;
        case ICMP_DEST_UNREACH:
            printf("Destination Unreachable");
            break;
        case ICMP_SOURCE_QUENCH:
            printf("Source Quench");
            break;
        case ICMP_REDIRECT:
            printf("Redirect (change route)");
            break;
        case ICMP_ECHO:
            printf("Echo Request");
            break;
        case ICMP_TIME_EXCEEDED:
            printf("Time Exceeded");
            break;
        case ICMP_PARAMETERPROB:
            printf("Parameter Problem");
            break;
        case ICMP_TIMESTAMP:
            printf("Timestamp Request");
            break;
        case ICMP_TIMESTAMPREPLY:
            printf("Timestamp Reply");
            break;
        case ICMP_INFO_REQUEST:
            printf("Information Request");
            break;
        case ICMP_INFO_REPLY:
            printf("/* Information Reply");
            break;
        case ICMP_ADDRESS:
            printf("Address Mask Request");
            break;
        case ICMP_ADDRESSREPLY:
            printf("Address Mask Reply");
            break;
        default:
            printf("Unknown type");
    }

    printf(" (%u)\n", icmph->type);

    printf("        Code : %d\n", (unsigned int) (icmph->code));
    printf("        Checksum : 0x%.4x\n", ntohs(icmph->checksum));
    //printf("        Identifier : %d (0x%.4x)\n", ntohs(icmph->id), ntohs(icmph->id));
    printf("        Data Payload\n");
    printf("\033[00m");
    //PrintData(packet, size);
    return(0);
}


