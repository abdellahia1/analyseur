#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <ctype.h>

//#include "projet0.h"

void f_http(const u_char* packet, int* size){

    int n;  //numbers of read characters
    int i=0; //index into data
    if(*size == 0){
		printf("This packet contains no more data\n");
		return;
    }
   /*if(!strncmp(packet, "GET", 3) || !strncmp(packet, "HTTP", 4))
           printf("GET or HTTP") ;*/
        i = 0;
  		n = 1;
  		printf("\t\t\t");
  		while(i < *size){
  			if(packet[i] >= 32 && packet[i] <= 126){
  				putchar(packet[i]);
  			}
  			else{
  				putchar('.');
  			}

  			//printbyte(data[i]);
  			if((n & 0x3F) == 0){
  				printf("\n\t\t\t");
  			}
  			n++;
  			i++;
  		}
  		putchar('\n');
  		printf("\n");

}


/*
if(strncmp("HTTP", packet, 5) == 0
       || strncmp("GET", packet, 3) == 0
       || strncmp("POST", packet, 4) == 0
       || strncmp("PUT", packet, 4) == 0
       || strncmp("DELETE", packet, 6) == 0
       || strncmp("HEAD", packet, 4) == 0) {

        while(*packet != '\n')
            putchar(*packet++);

        putchar('\n');
        packet++;

        while(strncmp("\r\n", packet, 2) != 0) { // print headers (<==> until we have double \n)
            printf("        ");

            while(*packet != '\n')
                putchar(*packet++);

            putchar('\n');
            packet++;
        }
    }
    else {
        printf("               [... HTTP(S) Content...]\n");
    }
*/
