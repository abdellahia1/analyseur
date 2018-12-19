
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>

#include <netinet/in.h>
#include <ctype.h>

//extern int packet_size;


void f_smtp(const u_char* packet, int* size){

    printf("\033[34m");

/*    if(strncmp("SMTP", packet, 5) == 0
       || strncmp("MAIL", packet, 4) == 0
       || strncmp("RCPT", packet, 4) == 0
       || strncmp("DATA", packet, 4) == 0
       || strncmp("HELO", packet, 4) == 0
       || strncmp("AUTH", packet, 4) == 0
       || strncmp("STARTTLS", packet, 9) == 0
       || strncmp("QUIT", packet, 4) == 0) {

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
        printf("                [... SMTP Content...]\n");
    }

*/
    int i=0; //index into data
    if(*size == 0){
		printf("This packet contains no more data\n");
		return;
    }

    while (i<*size){
  		if (i%47==0)
  			printf("\n\t\t\t");
  		if(isprint(packet[i]))
  			 printf("%c", packet[i]);
  		else
  			printf(".");
  		i++;
  	}
    printf("\n\n");
    printf("\033[00m");
}
