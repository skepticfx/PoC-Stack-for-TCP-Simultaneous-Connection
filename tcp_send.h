/*  TCP_SEND.h , Craft and Send custom TCP Packets*/
#include <netinet/ip.h>   
#define __FAVOR_BSD       
#include <netinet/tcp.h>  
#include <stdio.h>
#include <string.h>       
#include <stdlib.h>       

#define TCPSYN_LEN 20
#define MAXBYTES2CAPTURE 2048

int VERBOSE = 0 ; 

/* Pseudoheader (Used to compute TCP checksum ) */
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


int tcp_send(u_int32 source_ip, u_int32 destination_ip, u_int16 source_port, u_int16 destination_port,u_int32 sequence_number , u_int32 ack_number , int8 flags);

unsigned short in_cksum(unsigned short *addr,int len);


/* TCP_SYN_send(): Crafts a TCP packet with the required parameters */
int tcp_send(u_int32 source_ip, u_int32 destination_ip, u_int16 source_port, u_int16 destination_port,u_int32 sequence_number, u_int32 ack_number,int8 flags){

  
  int one=1;
  int rawsocket=0;  
  char packet[ sizeof(struct tcphdr) + sizeof(struct ip) +1 ];
  struct ip *ipheader = (struct ip *)packet;   
  struct tcphdr *tcpheader = (struct tcphdr *) (packet + sizeof(struct ip)); 
  
  tcp_phdr_t pseudohdr;            

  char tcpcsumblock[ sizeof(tcp_phdr_t) + TCPSYN_LEN ];

  struct sockaddr_in dstaddr;  
  
  memset(&pseudohdr,0,sizeof(tcp_phdr_t));
  memset(&packet, 0, sizeof(packet));
  memset(&dstaddr, 0, sizeof(dstaddr));   
    
  dstaddr.sin_family = AF_INET;    
  dstaddr.sin_port = destination_port;      
  dstaddr.sin_addr.s_addr = destination_ip; 


 if ( (rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
        perror("TCP_RST_send():socket()"); 
        exit(1);
  }
  
  if( setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        perror("TCP_RST_send():setsockopt()"); 
        exit(1);
   }
 
	

  ipheader->ip_hl = 5;    
  ipheader->ip_v = 4;      
  ipheader->ip_tos = 0;    
  ipheader->ip_len = htons( sizeof (struct ip) + sizeof (struct tcphdr) );         
  ipheader->ip_off = 0;   
  ipheader->ip_ttl = 64;  
  ipheader->ip_p = 6;      
  ipheader->ip_sum = 0;    
  ipheader->ip_id = htons( 1337 ); 
  ipheader->ip_src.s_addr = source_ip;  
  ipheader->ip_dst.s_addr = destination_ip; 

 
  tcpheader->th_seq = sequence_number;        
  tcpheader->th_ack = ack_number;  
  tcpheader->th_x2 = 0;           
  tcpheader->th_off = 5;	  
  tcpheader->th_flags = flags;   
  tcpheader->th_win = htons(4500) + rand()%1000;
  tcpheader->th_urp = 0;          
  tcpheader->th_sport = source_port; 
  tcpheader->th_dport = destination_port;  
  tcpheader->th_sum=0;            
  
  /* pseudoheader before doing the checksum */
  pseudohdr.src = ipheader->ip_src.s_addr;
  pseudohdr.dst = ipheader->ip_dst.s_addr;
  pseudohdr.zero = 0;
  pseudohdr.protocol = ipheader->ip_p;
  pseudohdr.tcplen = htons( sizeof(struct tcphdr) );


  memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));   
  memcpy(tcpcsumblock+sizeof(tcp_phdr_t),tcpheader, sizeof(struct tcphdr));
    

  tcpheader->th_sum = in_cksum((unsigned short *)(tcpcsumblock), sizeof(tcpcsumblock)); 


  ipheader->ip_sum = in_cksum((unsigned short *)ipheader, sizeof(struct ip));
    

  if ( sendto(rawsocket, packet, ntohs(ipheader->ip_len), 0,
                  (struct sockaddr *) &dstaddr, sizeof (dstaddr)) < 0){		
        printf("\nfailed sendto \n");
        return -1;                     
    }

  printf("Sent  Packet:\n");
  printf("SRC: %s:%d\n", (char *)inet_ntoa(ipheader->ip_src), ntohs(tcpheader->th_sport));
  printf("DST: %s:%d\n",(char *) inet_ntoa(ipheader->ip_dst), ntohs(tcpheader->th_dport));
  printf("Seq=%u\n", ntohl(tcpheader->th_seq));
  printf("Ack=%d\n", ntohl(tcpheader->th_ack));
  printf("Flags=0x%X\n", tcpheader->th_flags);
  printf("   TCPsum: %02x\n",  tcpheader->th_sum);
  printf("   IPsum: %02x\n", ipheader->ip_sum);


return 0;
  
  
} 

/* Checksum Module */
/* Shamelessly copied from the Internet */
/* As this piece of code is the defacto module for Checksum Calculations found on the internet*/


unsigned short in_cksum(unsigned short *addr,int len){
    
register int sum = 0;
u_short answer = 0;
register u_short *w = addr;
register int nleft = len;
    
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

