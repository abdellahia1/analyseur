//#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>



void f_udp(const u_char* packet, int* size) {
    u_int header_size;
    struct udphdr* udphead=(struct udphdr*)(packet+*size);

    *size+=sizeof(struct udphdr);
    //header_size = 4 * tcphead->th_off;

    printf("        Source port : %d\n", ntohs(udphead->uh_sport));
    printf("        Destination port : %d\n", ntohs(udphead->uh_dport));
    printf("        Udp length : %d\n", ntohs(udphead->uh_ulen));
    printf("        Udp checksum : 0x%X\n", ntohs(udphead->uh_sum));
    printf("\n");
    //BOOTP
    if((ntohs(udphead->uh_sport)==IS_BOOTP1 && ntohs(udphead->uh_dport)==IS_BOOTP2)
      || (ntohs(udphead->uh_sport)==IS_BOOTP2 && ntohs(udphead->uh_dport)==IS_BOOTP1))
      {
        printf("\033[36m            ==================BOOTP/DHCP==================\n\n");
        f_bootp(packet,size);
      }
    //DNS
    if((ntohs(udphead->uh_sport)==IS_DNS || ntohs(udphead->uh_dport)==IS_DNS))
        {
        printf("\033[36m            ======================DNS=====================\n\n");
        f_dns(packet,size);
        }
    //HTTP
    if((ntohs(udphead->uh_sport)==IS_HTTP || ntohs(udphead->uh_dport)==IS_HTTP))
        {
        printf("\033[36m            ======================HTTP=====================\n\n");
        //f_http(packet /*+ header_size*/ ,size /*- header_size*/);
        }
    printf("\033[00m");
}

