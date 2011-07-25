#include <pcap.h> 
#include <stdlib.h> 
#include <string.h> 
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "tcp_send.h"

#define MAXBYTES2CAPTURE 2048 



int main(int argc, char *argv[]){
 int syn_received = 0 , syn_sent = 0 , established = 0;
 int i=0; 
 bpf_u_int32 netaddr=0, mask=0;    /* To Store network address and netmask   */ 
 struct bpf_program filter;        /* Place to store the BPF filter program  */ 
 char errbuf[PCAP_ERRBUF_SIZE];    /* Error buffer                           */ 
 pcap_t *descr = NULL;             /* Network interface handler              */ 
 struct pcap_pkthdr pkthdr;        /* Packet information (timestamp,size...) */ 
 const unsigned char *packet=NULL; /* Received raw data                      */ 
 memset(errbuf,0,PCAP_ERRBUF_SIZE); 
 
 struct ip *iphdr = NULL;
 struct tcphdr *tcphdr = NULL;

if (argc != 2){ 
    printf("USAGE: %s <interface>\n",argv[0]); 
    exit(1); 
} 
 /* Open network device for packet capture */ 
 if ((descr = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 0,  0, errbuf))==NULL){
    fprintf(stderr, "ERROR: %s\n", errbuf);
    exit(1);
 }
    
 /* Look up info from the capture device. */ 
 if( pcap_lookupnet( argv[1] , &netaddr, &mask, errbuf) == -1){
     fprintf(stderr, "ERROR: %s\n", errbuf);
    exit(1);
 }

 /* Compiles the filter expression into a BPF filter program */ 
 if ( pcap_compile(descr, &filter, "(tcp[tcpflags] & (tcp-syn) != 0) ||  (tcp[tcpflags] & (tcp-ack & tcp-syn) != 0)", 1, mask) == -1){
    fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
    exit(1);
 }

 /* Load the filter program into the packet capture device. */ 
 if (pcap_setfilter(descr,&filter) == -1){
    fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
    exit(1);
 }


 while(1){ 
 
  if ( (packet = pcap_next(descr,&pkthdr)) == NULL){  /* Get one packet */ 
    fprintf(stderr, "ERROR: Error getting the packet.\n", errbuf);
    exit(1);
 }
 
  iphdr = (struct ip *)(packet+14);
  tcphdr = (struct tcphdr *)(packet+14+20);
  
  if(!established){
  printf("\n\n---------------------------------------------------------------------------------------------------------------------------------\n"); 
  printf("\nReceived Packet (%d) of Size: %d bytes\n", ++i, pkthdr.len);
   
   
   printf("\n%s : %d -->", inet_ntoa(iphdr->ip_src) , ntohs(tcphdr->th_sport));
   
   printf("%s : %d -->", inet_ntoa(iphdr->ip_dst) , ntohs(tcphdr->th_dport));
   
  printf("\t Flags -- 0x%X  (%s)\n", tcphdr->th_flags, (tcphdr->th_flags == 0x02)?"SYN":"SYN-ACK"); // 0x12 is syn-ack
  
  

  
  
  // Now that the sniffing is done for syn or syn-acks , lets process them.
  
  /* If a new SYN is received */
  

  
  
  if(tcphdr->th_flags == 0x02 && !syn_received && tcphdr->th_ack == htonl(0))
 	
  {
  syn_received++;
  printf("\nSYN_RECEIVED\n");
  
  tcp_send(iphdr->ip_dst.s_addr,iphdr->ip_src.s_addr, tcphdr->th_dport, tcphdr->th_sport , htonl(1000), htonl(0) , 0x02);
  syn_sent++;
  
   printf("\nSYN_SENT\n");
  }
  
  if(syn_sent && tcphdr->th_flags == 0x12 && tcphdr->th_ack == htonl(1001))
  {
   printf("\nSYN_received\n");
   
  tcp_send(iphdr->ip_dst.s_addr,iphdr->ip_src.s_addr, tcphdr->th_dport, tcphdr->th_sport , htonl(1000),
  htonl(ntohl(tcphdr->th_seq) + 1), 0x12  );
  
  printf("\nSYN_SENT (SYN-ACK)\n");
  
  established++;  
  printf("\nThe Connection has been Established !\n"); 
  
  }
  
  
}
  
 } 

return 0; 

}
/* EOF */
