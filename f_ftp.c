
#include <string.h>





void f_ftp(const u_char* packet, int* size){
    if(strncmp("FTP", packet, 3) == 0
       || strncmp("USER", packet, 4) == 0
       || strncmp("PASS", packet, 4) == 0
       || strncmp("ACCT", packet, 4) == 0
       || strncmp("PORT", packet, 4) == 0
       || strncmp("PASV", packet, 4) == 0
       || strncmp("DELE", packet, 4) == 0
       || strncmp("LIST", packet, 4) == 0
       || strncmp("HELP", packet, 4) == 0
       || strncmp("NOOP", packet, 4) == 0
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
        printf("                [... FTP Content...]\n");
    }
}
