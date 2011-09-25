/*  Have to change the device type.  */


#include <netinet/ip.h>   /* Internet Protocol             */ 
#define __FAVOR_BSD       /* Using BSD TCP header          */ 
#include <netinet/tcp.h>  /* Transmission Control Protocol */ 
#include <stdio.h>
#include <string.h>       /* String operations             */ 
#include <stdlib.h>       /* Standard library definitions  */ 

#define TCPSYN_LEN 20
#define MAXBYTES2CAPTURE 2048

int VERBOSE = 0 ; 
char DEV[5]="wlan0";
/* Pseudoheader (Used to compute TCP checksum. Check RFC 793) */
typedef struct pseudoheader {
  u_int32_t src;
  u_int32_t dst;
  u_char zero;
  u_char protocol;
  u_int16_t tcplen;
} tcp_phdr_t;

typedef unsigned short u_int16;
typedef unsigned long u_int32;
typedef signed short int8;


/* Function Prototypes */

int tcp_send(u_int32 source_ip, u_int32 destination_ip, u_int16 source_port, u_int16 destination_port,u_int32 sequence_number , u_int32 ack_number , int8 flags);

unsigned short in_cksum(unsigned short *addr,int len);





/* TCP_SYN_send(): Crafts a TCP packet with the SYN flag set using the supplied */
/* values and sends the packet through a raw socket.                            */
int tcp_send(u_int32 source_ip, u_int32 destination_ip, u_int16 source_port, u_int16 destination_port,u_int32 sequence_number, u_int32 ack_number,int8 flags){

  
  int one=1; /* R.Stevens says we need this variable for the setsockopt call */ 

  /* Raw socket file descriptor */ 
  int rawsocket=0;  
  
  /* Buffer for the TCP/IP SYN Packets */
  char packet[ sizeof(struct tcphdr) + sizeof(struct ip) +1 ];    // +1 ? ? WHY ? :P , paranoid !

  /* It will point to start of the packet buffer */  
  struct ip *ipheader = (struct ip *)packet;   
  
  /* It will point to the end of the IP header in packet buffer */  
  struct tcphdr *tcpheader = (struct tcphdr *) (packet + sizeof(struct ip)); 
  
  /* TPC Pseudoheader (used in checksum)    */
  tcp_phdr_t pseudohdr;            

  /* TCP Pseudoheader + TCP actual header used for computing the checksum */
  char tcpcsumblock[ sizeof(tcp_phdr_t) + TCPSYN_LEN ];

  /* Although we are creating our own IP packet with the destination address */
  /* on it, the sendto() system call requires the sockaddr_in structure */
  struct sockaddr_in dstaddr;  
  
  memset(&pseudohdr,0,sizeof(tcp_phdr_t));
  memset(&packet, 0, sizeof(packet));
  memset(&dstaddr, 0, sizeof(dstaddr));   
    
  dstaddr.sin_family = AF_INET;     /* Address family: Internet protocols */
  dstaddr.sin_port = destination_port;      /* Leave it empty */
  dstaddr.sin_addr.s_addr = destination_ip; /* Destination IP */



  /* Get a raw socket to send TCP packets */   
 if ( (rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
        perror("TCP_RST_send():socket()"); 
        exit(1);
  }
  
  /* We need to tell the kernel that we'll be adding our own IP header */
  /* Otherwise the kernel will create its own. The ugly "one" variable */
  /* is a bit obscure but R.Stevens says we have to do it this way ;-) */
  if( setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        perror("TCP_RST_send():setsockopt()"); 
        exit(1);
   }
 
	
  /* IP Header */
  ipheader->ip_hl = 5;     /* Header lenght in octects                       */
  ipheader->ip_v = 4;      /* Ip protocol version (IPv4)                     */
  ipheader->ip_tos = 0;    /* Type of Service (Usually zero)                 */
  ipheader->ip_len = htons( sizeof (struct ip) + sizeof (struct tcphdr) );         
  ipheader->ip_off = 0;    /* Fragment offset. We'll not use this            */
  ipheader->ip_ttl = 64;   /* Time to live: 64 in Linux, 128 in Windows...   */
  ipheader->ip_p = 6;      /* Transport layer prot. TCP=6, UDP=17, ICMP=1... */
  ipheader->ip_sum = 0;    /* Checksum. It has to be zero for the moment     */
  ipheader->ip_id = htons( 1337 ); 
  ipheader->ip_src.s_addr = source_ip;  /* Source IP address                    */
  ipheader->ip_dst.s_addr = destination_ip;  /* Destination IP address               */

  /* TCP Header */   
  tcpheader->th_seq = sequence_number;        /* Sequence Number                         */
  tcpheader->th_ack = ack_number;   /* Acknowledgement Number                  */
  tcpheader->th_x2 = 0;           /* Variable in 4 byte blocks. (Deprecated) */
  tcpheader->th_off = 5;	  /* Segment offset (Lenght of the header)   */
  tcpheader->th_flags = flags;   /* TCP Flags. We set the Reset Flag        */
  tcpheader->th_win = htons(4500) + rand()%1000;/* Window size               */
  tcpheader->th_urp = 0;          /* Urgent pointer.                         */
  tcpheader->th_sport = source_port;  /* Source Port                             */
  tcpheader->th_dport = destination_port;  /* Destination Port                        */
  tcpheader->th_sum=0;            /* Checksum. (Zero until computed)         */
  
  /* Fill the pseudoheader so we can compute the TCP checksum*/
  pseudohdr.src = ipheader->ip_src.s_addr;
  pseudohdr.dst = ipheader->ip_dst.s_addr;
  pseudohdr.zero = 0;
  pseudohdr.protocol = ipheader->ip_p;
  pseudohdr.tcplen = htons( sizeof(struct tcphdr) );

  /* Copy header and pseudoheader to a buffer to compute the checksum */  
  memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));   
  memcpy(tcpcsumblock+sizeof(tcp_phdr_t),tcpheader, sizeof(struct tcphdr));
    
  /* Compute the TCP checksum as the standard says (RFC 793) */
  tcpheader->th_sum = in_cksum((unsigned short *)(tcpcsumblock), sizeof(tcpcsumblock)); 

  /* Compute the IP checksum as the standard says (RFC 791) */
  ipheader->ip_sum = in_cksum((unsigned short *)ipheader, sizeof(struct ip));
    
  /* Send it through the raw socket */    
  if ( sendto(rawsocket, packet, ntohs(ipheader->ip_len), 0,
                  (struct sockaddr *) &dstaddr, sizeof (dstaddr)) < 0){		
        printf("\nfailed sendto \n");
        return -1;                     
    }

  printf("Sent  Packet:\n");
  printf("   SRC: %s:%d\n", (char *)inet_ntoa(ipheader->ip_src), ntohs(tcpheader->th_sport));
  printf("   DST: %s:%d\n",(char *) inet_ntoa(ipheader->ip_dst), ntohs(tcpheader->th_dport));
  printf("   Seq=%u\n", ntohl(tcpheader->th_seq));
  printf("   Ack=%d\n", ntohl(tcpheader->th_ack));
  printf("   Flags=0x%X\n", tcpheader->th_flags);


  printf("   TCPsum: %02x\n",  tcpheader->th_sum);
  printf("   IPsum: %02x\n", ipheader->ip_sum);
    
  close(rawsocket);

return 0;
  
  
} /* End of IP_Id_send() */













/* CHECKSUM */

/* This piece of code has been used many times in a lot of differents tools. */
/* I haven't been able to determine the author of the code but it looks like */
/* this is a public domain implementation of the checksum algorithm */
unsigned short in_cksum(unsigned short *addr,int len){
    
register int sum = 0;
u_short answer = 0;
register u_short *w = addr;
register int nleft = len;
/*
* Our algorithm is simple, using a 32-bit accumulator (sum),
* we add sequential 16-bit words to it, and at the end, fold back 
* all the carry bits from the top 16 bits into the lower 16 bits. 
*/
    
while (nleft > 1) {
sum += *w++;
nleft -= 2;
}

/* mop up an odd byte, if necessary */
if (nleft == 1) {
*(u_char *)(&answer) = *(u_char *)w ;
sum += answer;
}

/* add back carry outs from top 16 bits to low 16 bits */
sum = (sum >> 16) + (sum &0xffff); /* add hi 16 to low 16 */
sum += (sum >> 16); /* add carry */
answer = ~sum; /* truncate to 16 bits */
return(answer);

} /* End of in_cksum() */

