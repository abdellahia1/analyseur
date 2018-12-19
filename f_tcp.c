//#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

//TCP FLAGS
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20

//#include "projet0.h"

void f_tcp(const u_char* packet, int* size) {
    //printf("        size before: %d\n",*size);
    u_int header_size;
    struct tcphdr* tcphead = (struct tcphdr*)( packet + *size);
    *size+=sizeof(struct tcphdr);

    header_size = 4 * tcphead->th_off;

    printf("\033[35m        Source port : %i\n", ntohs(tcphead->th_sport));
    printf("        Destination port : %i\n", ntohl(tcphead->th_dport));
    printf("        Sequence number : 0x%.4x\n", ntohs(tcphead->th_seq));
    printf("        Acknowledgment number : 0x%.4x\n", ntohs(tcphead->th_ack));
    printf("        Sequence number : 0x%.4x\n", ntohs(tcphead->th_seq));
    printf("        Data offset : %i bytes\n", tcphead->th_off*4);
    printf("        Unused : %i\n", tcphead->th_x2*4);
    printf("        Flags : (0x%.4x)", tcphead->th_flags);
    switch(tcphead->th_flags){
        case TH_FIN:
        printf(" FIN\n");
        break;
        case TH_SYN:
        printf(" SYN\n");
        break;
        case TH_RST:
        printf(" RST\n");
        break;
        case TH_PUSH:
        printf(" PSH\n");
        break;
        case TH_ACK:
        printf(" ACK\n");
        break;
        case TH_URG:
        printf(" URG\n");
        break;
    }
    printf("        Window : %i\n", ntohs(tcphead->th_win));
    printf("        Checksum : 0x%.4x\n", ntohs(tcphead->th_sum));
    printf("        Urgent pointer : %i\n", ntohs(tcphead->th_urp)); /*0x%.4x*/
    printf("        \033[00m");

    printf("\n");

    //BOOTP
    if((ntohs(tcphead->th_sport)==IS_BOOTP1 && ntohs(tcphead->th_dport)==IS_BOOTP2)
      || (ntohs(tcphead->th_sport)==IS_BOOTP2 && ntohs(tcphead->th_dport)==IS_BOOTP1))
    {
        printf("\033[36m            ==================BOOTP/DHCP==================\n\n");
        printf("\033[00m");
        f_bootp(packet,size);
    }
    //DNS
    if((ntohs(tcphead->th_sport)==IS_DNS || ntohs(tcphead->th_dport)==IS_DNS))
    {
        printf("\033[36m            ======================DNS=====================\n");
        printf("\033[00m");
        f_dns(packet,size);
    }
    //HTTP
    if((ntohs(tcphead->th_sport)==IS_HTTP || ntohs(tcphead->th_dport)==IS_HTTP))
    {
        printf("\033[36m\n            ======================HTTP=====================\n");
        printf("\033[00m");
        f_http(packet,size);
    }
    //SMTP
    if((ntohs(tcphead->th_sport)==IS_SMTP || ntohs(tcphead->th_dport)==IS_SMTP))
    {
        printf("\033[36m            ======================SMTP=====================\n");
        printf("\033[00m");
        f_smtp(packet,size);
    }
    //TELNET
    if((ntohs(tcphead->th_sport)==IS_SMTP || ntohs(tcphead->th_dport)==IS_SMTP))
    {
        printf("\033[36m            =====================TELNET====================\n");
        printf("\033[00m");
        //f_telnet(packet,size);
    }
    //FTP
    if((ntohs(tcphead->th_sport)==IS_FTP || ntohs(tcphead->th_dport)==IS_FTP))
    {
        printf("\033[36m            =======================FTP=====================\n");
        printf("\033[00m");
        f_ftp(packet,size);
    }

}
