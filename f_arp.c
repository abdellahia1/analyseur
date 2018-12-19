#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>

#define ARP_MAC_LENGTH				  6
#define ARP_IPv4_LENGTH				  4

//#include "projet0.h"

int f_arp(const u_char* packet, int* size){
    int i;

    struct arphdr* arphead=(struct arphdr*)(packet+*size);
    struct ether_arp* arphead2=(struct ether_arp*)(packet+*size);

    *size+=sizeof(struct ether_arp);

     /*char *op[] = {"ARP REQUEST",
				   "ARP REPLY",
				   "RARP REQUEST",
				   "RARP RAPLY",
				   "DRARP REQUEST",
				   "DRARP REPLY",
				   "DRARP ERROR",
				   "INARP REQUEST",
                   "INARP REPLY"};*/

    printf("\033[33m    Hardware type: (%d) ",ntohs(arphead2->arp_hrd));
    switch(ntohs(arphead2->arp_hrd)){
        case ARPHRD_ETHER:
            printf("Ethernet\n");
            break;
        /*case ARPHRD_FRELAY:
            printf("Frame relay\n");
        break;*/
    }
    printf("    Protocol type: (0x%u) ",arphead2->arp_pro);
    switch(ntohs(arphead2->arp_pro)){
        case ETHERTYPE_PUP:
            printf("Xerox POP\n");
            break;
        case ETHERTYPE_IP:
            printf("IPv4\n");
            break;
        case ETHERTYPE_ARP:
            printf("Address resolution \n");
            break;
        case ETHERTYPE_REVARP:
            printf("Reserve ARP\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }
    printf("    Hardware size: %u\n", arphead2->arp_hln);
    printf("    Protocol size: %u\n", arphead2->arp_pln);
    printf("    Opcode: ");
    /*if(ntohs(arphead2->arp_op)>=1 && ntohs(arphead2->arp_op)<=9 ){
        printf("(%s)\n", op[ntohs(arphead2->arp_op)]);
    }
    else{
        printf("(Undefined)\n");
    }*/
    switch(ntohs(arphead2->arp_op)){
        case ARPOP_REQUEST:
            printf("Request (1)\n");
        break;
        case ARPOP_REPLY:
            printf("Reply (2)\n");
        break;
    }

    printf("    Sender MAC address : ");
    for(i=0;i<ARP_MAC_LENGTH;i++){
        if(i!=0)
            printf(":");
        printf("%.2x",arphead2->arp_sha[i]);
    }
    printf("\n");
    printf("    Sender IP address : ");
    for(i=0;i<ARP_IPv4_LENGTH;i++){
        if(i!=0)
            printf(".");
        printf("%u",arphead2->arp_spa[i]);
    }
    printf("\n");
    printf("    Target MAC address : ");
    for(i=0;i<ARP_MAC_LENGTH;i++){
        if(i!=0)
            printf(":");
        printf("%.2x",arphead2->arp_tha[i]);
    }
    printf("\n");
    printf("    Target IP address : ");
    for(i=0;i<ARP_IPv4_LENGTH;i++){
        if(i!=0)
            printf(".");
        printf("%u",arphead2->arp_tpa[i]);
    }
    printf("\n\n");
    printf("\033[00m");
    return(0);

}


//https://books.google.fr/books?id=iveOHSyFCa0C&pg=PA291&lpg=PA291&dq=printf+arp_sha&source=bl&ots=gbMWPgEhvM&sig=uclb6xuE5hnA8Rf37kjZSQXreeA&hl=fr&sa=X&ved=2ahUKEwjV_bDm1ovfAhVSyhoKHRuIAVgQ6AEwAHoECAAQAQ#v=onepage&q=printf%20arp_sha&f=false
