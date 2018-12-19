//#include "projet0.h"

#include "net_sock_dns.h"

//#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

//DNS Flags
#define IS_QR        ((ntohs(dnshead->flags) << 1) & 1)
#define IS_OPCODE  ((ntohs(dnshead->flags) << 11) & 15)
#define IS_A        ((ntohs(dnshead->flags) >> 10) & 1)
#define IS_TC        ((ntohs(dnshead->flags) << 9) & 1)
#define IS_RD        ((ntohs(dnshead->flags) >> 8) & 1)
#define IS_RA        ((ntohs(dnshead->flags) << 7) & 1)
#define IS_ZR        ((ntohs(dnshead->flags) << 6) & 1)
#define IS_AA        ((ntohs(dnshead->flags) << 5) & 1)
#define IS_NAD       ((ntohs(dnshead->flags) << 4) & 1)



void f_dns(const u_char* packet, int* size){

    struct sock_dns_hdr_t* dnshead=(struct sock_dns_hdr_t*)(packet+*size);

    *size+=sizeof(struct sock_dns_hdr_t);

    printf("\033[35m            Transaction ID : 0x%4.x\n", ntohs(dnshead->id));
    printf("            Flags : (0x%.4x) \n",ntohs(dnshead->flags));
    if(!IS_QR)
        printf("                =Response: Message is a response\n");
    if(IS_QR)
        printf("                =Response: Message is a querry\n");
    if(!IS_OPCODE)
        printf("                =Opcode: Standard query (0)\n");
    if(IS_A)
        printf("                =Authorative: Server is an authority for domain\n");
    if(!IS_TC)
        printf("                =Truncated: Message is not truncated\n");
    if(IS_RD)
        printf("                =Recursion desired: Do query recursively\n");
    if(!IS_RA)
        printf("                =Recursion available: Server can do recursive queries\n");
    if(!IS_ZR)
        printf("                =Z: reserved (0)\n");
    if(!IS_AA)
        printf("                =Answer authenticated: Answer/authority protion was not\n");
        printf("                            authenticated by the server\n");
    if(!IS_NAD)
        printf("                =Non-authenticated data: Unacceptable\n");
    printf("            Questions : %i\n",ntohs(dnshead->qdcount));
    printf("            Answer RRs : %i\n",ntohs(dnshead->ancount));
    printf("            Authority RRs : %i\n",ntohs(dnshead->nscount));
    printf("            Additional RRs : %i\n",ntohs(dnshead->arcount));
    printf("\n");
    printf("\033[00m");

}

