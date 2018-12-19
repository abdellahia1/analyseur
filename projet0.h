#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "f_udp.c"
#include "f_tcp.c"
#include "f_ipv6.c"
#include "f_ip.c"
#include "f_ethernet.c"

#ifndef _PROJET0_H_
#define _PROJET0_H_

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *pack);

int getverbosity();

void live_scan(char* device,char* filter_exp);
void offline_scan(char * file, char * filter);


int f_ethernet(const u_char* packet, int* size);
int f_ip(const u_char* packet, int* size);
int f_arp(const u_char* packet, int* size);
int f_ipv6(const u_char* packet, int* size);
void f_udp(const u_char* packet, int* size) ;
void f_tcp(const u_char* packet, int* size);
void f_bootp(const u_char* packet, int* size);
void f_dns(const u_char* packet, int* size);
void f_http(const u_char* packet, int* size)

#endif