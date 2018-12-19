#include <sys/socket.h>
#include <netinet/in.h>
#include "sctp.h"

#define IS_DATA     0x00
#define IS_INIT     0x01
#define IS_INITA    0x02
#define IS_SACK     0x03
#define IS_HB       0x04
#define IS_HBA      0x05
#define IS_ABORT    0x06
#define IS_SHUT     0x07
#define IS_SHUTA    0x08
#define IS_ERR      0x09


int f_sctp(const u_char* packet, int* size) {
    struct sctphdr* sctphead=(struct sctphdr*)(packet+*size);
    *size+=sizeof(struct sctphdr);
    //header_size = 4 * tcphead->th_off;

    printf("        Source port : %d\n", ntohs(sctphead->src_port));
    printf("        Destination port : %d\n", ntohs(sctphead->dest_port));
    printf("        Verification tag of packet : 0x%2x\n", ntohl(sctphead->v_tag));
    printf("        SCTP checksum : 0x%2x\n", ntohl(sctphead->checksum));
    printf("        DATA chunk:\n");

    struct sctp_chunkhdr* sctphead2=(struct sctp_chunkhdr*)(packet+*size);
    *size+=sizeof(struct sctp_chunkhdr);

    printf("            Chunk type : ");
    switch(ntohs(sctphead2->chunk_type)){
        case IS_DATA:
            printf("Payload Data (DATA)");
            break;
        case IS_INIT:
            printf("Initiation (INIT)");
            break;
        case IS_INITA:
            printf("Initiation Acknowledgment (INIT ACK)");
            break;
        case IS_SACK:
            printf("Selective Acknowledgment (SACK)");
            break;
        case IS_HB:
            printf("Hearbeat Request (HEARTBEAT)");
            break;
        case IS_HBA:
            printf("Hearbeat Acknowledgment (HEARTBEAT ACK)");
            break;
        case IS_ABORT:
            printf("Abort (ABORT)");
            break;
        case IS_SHUT:
            printf("Shutdown (SHUTDOWN)");
            break;
        case IS_SHUTA:
            printf("Shutdown Acknowledgment (SHUTDOWN ACK)");
            break;
        case IS_ERR:
            printf("Operation Error (ERROR)");
            break;
    }
    printf(" (%i)\n", ntohs(sctphead2->chunk_type));
    printf("            Chunk flags : 0x%x\n", ntohs(sctphead2->chunk_flags));
    printf("            Chunk length : %i\n", ntohs(sctphead2->chunk_length));
    printf("\n");
    return(0);
}
