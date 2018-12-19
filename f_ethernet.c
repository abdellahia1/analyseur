
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


int f_ethernet(const u_char* packet, int* size){
    int i; int pro;

    struct ether_header* ehead = (struct ether_header *) packet;
    *size+=sizeof(struct ether_header);

    printf("\033[31m@MAC Dest : ");
    for(i=0;i<6;i++){
        printf("%.2x:",ehead->ether_dhost[i]);
    }
    printf("\n");
    printf("@MAC Src : ");
    for(i=0;i<6;i++){
        printf("%.2x:",ehead->ether_shost[i]);
    }
    printf("\n");
    printf("Type :");
    switch(ntohs(ehead->ether_type)){
        case IS_IP:
            printf(" IPv4");
            pro=IS_IP;
            break;
        case IS_IP6:
            printf(" IPv6");
            pro=IS_IP6;
            break;
        case IS_ARP:
            printf(" ARP");
            pro=IS_ARP;
            break;
    }
    printf(" (0x%.4x)\n\n",ntohs(ehead->ether_type));
    printf("\033[00m");
    switch(pro){
        case IS_IP:
            return IS_IP;
        case IS_IP6:
            return IS_IP6;
        case IS_ARP:
            return IS_ARP;
        default :
            return 0;
    }


    return(0);
}

