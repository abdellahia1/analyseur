#include "bootp.h"
//#include "projet0.h"

//#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>



#define IS_BROADCAST 0x8000
#define IS_U       ((ntohs(bootphead->bp_flags) << 1) & 1)


void f_bootp(const u_char* packet, int* size){
    int i;

    struct bootp* bootphead=(struct bootp*)(packet+*size);

    *size+=sizeof(struct bootp);

    printf("\033[35m            Packet opcode type :(%i) ", bootphead->bp_op);
    switch(bootphead->bp_op){
        case BOOTREQUEST:
        printf("Request\n");
        break;
        case BOOTREPLY:
        printf("Reply\n");
        break;
    }
    printf("            Hardware addr type : (0x%.2x) ", bootphead->bp_htype);
    switch(bootphead->bp_htype){
        case HTYPE_ETHERNET:
            printf("Ethernet\n");
        break;
        case HTYPE_EXP_ETHERNET:
            printf("Experimental Ethernet\n");
        break;
        case HTYPE_AX25:
            printf("Radio amateur AX25\n");
        break;
        case HTYPE_PRONET:
            printf("Proteon ProNET Token Ring\n");
        break;
        case HTYPE_CHAOS:
            printf("Chaos\n");
        break;
        case HTYPE_IEEE802:
            printf("IEEE 802\n");
        break;
        case HTYPE_ARCNET:
            printf("Arcnet\n");
        break;
        default:
            printf("Others\n");
        break;
    }
    printf("            Hardware addr length : %i \n", bootphead->bp_hlen);
    printf("            Gateway hops : %i\n", bootphead->bp_hops);
    printf("            Transaction ID : 0x%.8x\n", ntohl(bootphead->bp_xid));
    printf("            Seconds elapsed : %i s\n", ntohs(bootphead->bp_secs));
    printf("            Bootp flags : (0x%.4x) ",ntohs(bootphead->bp_flags) );
    if(IS_U) printf(" Unicast\n");
    else printf(" Reserved\n");
    /*switch(ntohs(bootphead->bp_flags)){
        case IS_U:
            printf("(Unicast)\n");
        break;
        default:
            printf("Reserved\n");
    }*/
    printf("            Client IP address : %s\n", inet_ntoa(bootphead->bp_ciaddr));
    printf("            'Your' IP address : %s\n", inet_ntoa(bootphead->bp_yiaddr));
    printf("            Server IP address : %s\n", inet_ntoa(bootphead->bp_siaddr));
    printf("            Gateway IP address : %s\n", inet_ntoa(bootphead->bp_giaddr));
    printf("            Client MAC address : ");
    for(i=0;i<6;i++){
        printf("%.2x:",bootphead->bp_chaddr[i]);
    }
    printf("\n            Client hardware address padding: ");
    for(i=6;i<16;i++){
        printf("%.2x:",bootphead->bp_chaddr[i]);
    }
    printf("\n");
    if(bootphead->bp_file[0] != '\0')
        printf(" | File %s", bootphead->bp_file);
    printf("            Server host name : ");
    if(bootphead->bp_sname[0]==0)
        printf("not given\n");
    else
        printf("            %s\n", bootphead->bp_sname);
    printf("            Boot file name : ");
    if(bootphead->bp_file[0]==0)
        printf("not given\n");
    else
        printf("%s\n", bootphead->bp_file);


    u_int8_t *pvendor = bootphead->bp_vend;
    const u_int8_t magic_cookie[] = VM_RFC1048;

    if(memcmp(pvendor, magic_cookie, 4) == 0) {
        pvendor += 4;
        printf("                | Magic cookie 0x%02x%02x%02x%02x\n", pvendor[0], pvendor[1], pvendor[2], pvendor[3]);

        while(1) {
            u_int8_t option = *pvendor++;
            u_int8_t len = *pvendor++;

            if(option != 0) printf("                | Option %u(Len :%u): ", option, len);

            switch (option) {
                case TAG_PAD:
                    break;
                case TAG_SUBNET_MASK:
                    printf("Subnet mask: "); printf("%u",ntohl(*(int32_t *)pvendor));
                    break;
                case TAG_GATEWAY:
                    printf("Gateway: "); printf("%u",ntohl(*(int32_t *)pvendor));
                    break;
                case TAG_TIME_SERVER:
                    printf("Time server: "); printf("%u",ntohl(*(int32_t *)pvendor));
                    break;
                case TAG_DOMAIN_SERVER:
                    printf("Domain name server: "); printf("%u",ntohl(*(int32_t *)pvendor));
                    break;
                case TAG_HOSTNAME:
                    printf("Host name: ");
                    for(i = 0; i < len; i++) putchar(pvendor[i]);
                    break;
                case TAG_DOMAINNAME:
                    printf("Domain name: ");
                    for(i = 0; i < len; i++) putchar(pvendor[i]);
                    break;
                case TAG_END:
                    printf("End of options\n");
                    return;
                case TAG_BROAD_ADDR:
                    printf("Broadcast address: "); printf("%u",ntohl(*(int32_t *)pvendor));
                    break;
                case TAG_REQUESTED_IP:
                    printf("Requested IP: "); printf("%u",ntohl(*(int32_t *)pvendor));
                    break;
                case TAG_IP_LEASE:
                    printf("IP lease time: %us", ntohl(*(u_int32_t *)pvendor));
                    break;
                case TAG_DHCP_MESSAGE: {
                    u_int8_t dhcp_message = *pvendor;
                    switch (dhcp_message) {
                        case DHCPDISCOVER:
                            printf("DHCP Discover");
                            break;
                        case DHCPOFFER:
                            printf("DHCP Offer");
                            break;
                        case DHCPREQUEST:
                            printf("DHCP Request");
                            break;
                        case DHCPDECLINE:
                            printf("DHCP Decline");
                            break;
                        case DHCPACK:
                            printf("DHCP Ack");
                            break;
                        case DHCPNAK:
                            printf("DHCP N-Ack");
                            break;
                        case DHCPRELEASE:
                            printf("DHCP Release");
                            break;
                        case DHCPINFORM:
                            printf("DHCP Inform");
                            break;
                        default:
                            break;
                    }
                    break;
                }
                case TAG_SERVER_ID:
                    printf("DHCP server identifier: "); printf("%u",ntohl(*(int32_t *)pvendor));
                    break;
                case TAG_PARM_REQUEST:
                    printf("Parameter request list");
                    break;
                case TAG_RENEWAL_TIME:
                    printf("Renewal time: %us", ntohl(*(u_int32_t*)pvendor));
                    break;
                case TAG_REBIND_TIME:
                    printf("Rebinding time: %us", ntohl(*(u_int32_t*)pvendor));
                    break;
                case TAG_CLIENT_ID:
                    printf("Client identifier: "); printf("%s",pvendor + 1);
                    break;
                default:
                    break;
            }

            if(option != 0) putchar('\n');
            pvendor += len;
        }
    }
    printf("\n");
    printf("\033[00m");

}
