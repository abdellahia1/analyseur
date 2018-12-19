#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <ctype.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/in.h>

//#include "projet0.h"
//Ethernet
#define	IS_IP 0x0800
#define IS_ARP 0x0806
//Protocols

#define IS_FTP 21
#define IS_TELNET 23
#define IS_SCTP 132
#define IS_ICMP 0x01
#define IS_TCP 0x06
#define IS_UDP 0x11
#define IS_IP6 0x86DD
#define IS_BOOTP1 67
#define IS_BOOTP2 68
#define IS_DNS 53
#define IS_HTTP 80
#define IS_SMTP 25

#include "f_ftp.c"
#include "f_sctp.c"
#include "f_icmp.c"
#include "f_smtp.c"
#include "f_dns.c"
#include "f_bootp.c"
#include "f_http.c"
#include "f_udp.c"
#include "f_tcp.c"
#include "f_ipv6.c"
#include "f_arp.c"
#include "f_ip.c"
#include "f_ethernet.c"

int comp=0;
struct in_addr ip_addr;
struct in_addr ip_mask;

#define MAXBYTES 1518
#define TIMEOUT 1000



void usage(char *program_name) {
  printf("Usage : %s (-i <interface> | -o <file>) [-f <BPF filter>] [-v <1|2|3>(verbosity)>]\n", program_name);
  exit(2);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    int i;
    int size=0;
    int pack;
    int packet_size=header->len;
    //Ethernet
    printf("\033[36m===================ETHERNET===================\n\n");
    printf("\033[00m");
    pack=f_ethernet(packet,&size);
    switch(pack){
        case IS_IP:
            printf("\033[36m    ======================IP======================\n\n");
            printf("\033[00m");
            pack=f_ip(packet,&size);
            break;
        case IS_IP6:
            printf("\033[36m    =====================IPv6=====================\n\n");
            printf("\033[00m");
            pack=f_ipv6(packet,&size);
            break;
        case IS_ARP:
            printf("\033[36m    ======================ARP=====================\n\n");
            printf("\033[00m");
            pack=f_arp(packet, &size);
            break;
    }

    switch(pack){
        //TCP
        case IS_TCP:
            printf("\033[36m        ======================TCP=====================\n\n");
            printf("\033[00m");
            f_tcp(packet, &size);
            break;
        //UDP
        case IS_UDP:
            printf("\033[36m        ======================UDP=====================\n\n");
            printf("\033[00m");
            f_udp(packet, &size);
            break;
        case IS_ICMP:
            printf("\033[36m        =====================ICMP=====================\n\n");
            printf("\033[00m");
            pack=f_icmp(packet, &size);
            break;
        case IS_SCTP:
            printf("\033[36m        =====================SCTP=====================\n\n");
            printf("\033[00m");
            pack=f_sctp(packet, &size);
            break;
    }

}

int main(int argc, char *argv[])
{
		char *dev;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        bpf_u_int32 mask;
		bpf_u_int32 net;

        int opt;
        char* file = NULL;
        char* filter = NULL;
        int verbosity = 0;
        struct bpf_program fp;			// compiled filter program

        while ((opt = getopt(argc, argv, "i:o:f:v:")) != -1) {
            switch (opt) {
            case 'i':
                dev = optarg;
                break;
            case 'o':
                file = optarg;
                break;
            case 'f':
                filter = optarg;
                break;
            case 'v':
                verbosity = atoi(optarg);
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
        }

        //Define the device
        //if(!dev) {
            dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
            }
        // }
		printf("Device: %s\n", dev);

        //Find the properties for the device
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            return(1);
		}

        ip_addr.s_addr=net;
        ip_mask.s_addr=mask;

        /*if(!verbosity){
		printf("Verbosity degree by default is LOW \n");
		verbosity_user = LOW_VERBOSITY;
	    }


	    if(!dev){
	    	dev = pcap_lookupdev(errbuf);
	    	if(dev == NULL){
	    		fprintf(stderr, "pcap_lookupdev: %s", errbuf);
	    		exit(EXIT_FAILURE);
	    	}

	    }

	    printf("Sniffing on device %s\n", dev);*/

	    char filter_exp[64] = { 0 };

        //filter optio,
	    if (filter) {
	    		strncpy(filter_exp, filter, sizeof(filter_exp));
	    		printf("Filter: %s\n",filter_exp);
	    		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                    fprintf(stderr, "Couldn't parse filter %s: %s\n",
                        filter_exp, pcap_geterr(handle));
                    exit(EXIT_FAILURE);
                }

                  /* apply the compiled filter */
                if (pcap_setfilter(handle, &fp) == -1) {
                    fprintf(stderr, "Couldn't install filter %s: %s\n",
                        filter_exp, pcap_geterr(handle));
                    exit(EXIT_FAILURE);
                }
	    }

        //file option
	    if(!file){
	    	handle = pcap_open_live(dev, MAXBYTES, 1, TIMEOUT, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return(2);
            }
	    }

	    else{
	    	handle = pcap_open_offline(file, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return(2);
            }
        }

        //capture a packet
        if(pcap_loop(handle, -1, got_packet, NULL)<0){
            fprintf(stderr, "Error : no packet captured");
        }

        //deallocate the filter
        pcap_freecode(&fp);

        //close the session
        pcap_close(handle);

        printf("\n                      ===================");
        printf("\n                      ===DONE SNIFFING=== :).\n\n");
		return(0);
}

