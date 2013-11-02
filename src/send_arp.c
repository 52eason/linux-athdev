/*
 * I have turned this program from the hacking tool into simple utility
 * that allows you to send gratuitous arp requests for the interface.
 * It will pick up the MAC and IP from the given interface and advertise
 * it to the network. It works with alias interfaces as well.
 * This is useful in all sorts of failover situations where
 * - One interface completely takes over the MAC of another
 * - Alias IP is assigned to a different interface and has to be
 *   advertised as such.
 * 
 * I didn't do much - just added a couple of lines of code. It only
 * works verifiably on Linux.
 * Questions probably should go to original author, but if you really
 * want you can talk to me as well. Ths program comes as a free software
 * to be distributed in any form, binary or source without warranty
 * of any kind. Use at your own risk.
 *
 * To compile:
 * 	gcc -o send_arp send_arp.c
 *
 * 2001 (c) Ugen ugen@xonix.com
 */ 

/* send_arp.c

This program sends out one ARP packet with source/target IP and Ethernet
hardware addresses suuplied by the user.  It compiles and works on Linux
and will probably work on any Unix that has SOCK_PACKET.

The idea behind this program is a proof of a concept, nothing more.  It
comes as is, no warranty.  However, you're allowed to use it under one
condition: you must use your brain simultaneously.  If this condition is
not met, you shall forget about this program and go RTFM immediately.

yuri volobuev'97
volobuev@t1.chem.umn.edu

*/

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#if 0
#	include <linux/in.h>
#endif
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/filter.h>

#include "utils.h"

/** DEFINE REGION **/

#ifdef linux
#	define	NEWSOCKET()	socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP))
#else
#	define	NEWSOCKET()	socket(SOL_SOCKET, SOCK_RAW, ETHERTYPE_REVARP)
#endif

#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_FRAME_TYPE 0x0806
#define RARP_FRAME_TYPE 0x8035
#define ETHER_HW_TYPE 1
#define IP_PROTO_TYPE 0x0800

#define OP_ARP_REQUEST	1
#define OP_ARP_REPLY	2
#define OP_RARP_REQUEST	3
#define OP_RARP_REPLY	4


#define ETH_HW_ADDR_LEN 6
#define DEFAULT_DEVICE "br0"

#define BUFF_SIZE 2048
#define ETH_HDR_LEN 14

/** STRUCTURE **/

struct ethernet {
    unsigned char dest[6];
    unsigned char source[6];
    uint16_t eth_type;
};

struct arp {
    uint16_t htype;
    uint16_t ptype;
    unsigned char hlen;
    unsigned char plen;
    uint16_t oper;
    /* addresses */
    unsigned char sender_ha[6];
    unsigned char sender_pa[4];
    unsigned char target_ha[6];
    unsigned char target_pa[4];
};

/* CHANGE
   Linux socket filters use the Berkeley packet filter syntax. 
   This was adapted from BSDs "man 4 bpf" example for RARP.
*/
struct sock_filter arpfilter[] = {
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12), /* Skip 12 bytes */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETH_P_ARP, 0, 1), /* if eth type != ARP
                                                         skip next instr. */
    BPF_STMT(BPF_RET+BPF_K, sizeof(struct arp) +
                 sizeof(struct ethernet)),
    BPF_STMT(BPF_RET+BPF_K, 0), /* Return, either the ARP packet or nil */
};

struct arp_packet {
        u_char targ_hw_addr[MAC_ADDR_LEN];
        u_char src_hw_addr[MAC_ADDR_LEN];
        u_short frame_type;
        u_short hw_type;
        u_short prot_type;
        u_char hw_addr_size;
        u_char prot_addr_size;
        u_short op;
        u_char sndr_hw_addr[MAC_ADDR_LEN];
        u_char sndr_ip_addr[IP_ADDR_LEN];
        u_char rcpt_hw_addr[MAC_ADDR_LEN];
        u_char rcpt_ip_addr[IP_ADDR_LEN];
        u_char padding[18];
};

void die(const char *);
void get_ip_addr(struct in_addr*,char*);
void get_hw_addr(u_char*,char*);

static void dump_arp(struct arp *arp_hdr);
int	ioctl_sock;
int arp_reply = -1;
int rarp_reply = -1;

void rev_arp_reply()
{
   int sock;
    void *buffer = NULL;
    ssize_t recvd_size;
    struct ethernet *eth_hdr = NULL;
    struct arp *arp_hdr = NULL;
    struct sock_filter *filter;
    struct sock_fprog  fprog;

    if( (sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
        perror("socket(): ");
        exit(-1);
    }

    /* CHANGE prepare linux packet filter */
    if ((filter = malloc(sizeof(arpfilter))) == NULL) {
        perror("malloc");
        close(sock);
        exit(1);
    }
    memcpy(filter, &arpfilter, sizeof(arpfilter));
    fprog.filter = filter;
    fprog.len = sizeof(arpfilter)/sizeof(struct sock_filter);

    /* CHANGE add filter */
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) == -1) {
        perror("setsockopt");
        close(sock);
        exit(1);
    }

    buffer = malloc(BUFF_SIZE);
    while(1)
    {
        if( (recvd_size = recv(sock, buffer, BUFF_SIZE, 0)) < 0)
        {
            perror("recv(): ");
            free(buffer);
            close(sock);
        }
        if((size_t)recvd_size < (sizeof(struct ethernet) + sizeof(struct arp)))
        {
            printf("Short packet. Packet len: %ld\n", recvd_size);
            continue;
        }
        eth_hdr = (struct ethernet *)buffer;
        if(ntohs(eth_hdr->eth_type) != ETH_P_ARP) {
            printf("Received wrong ethernet type: %X\n", eth_hdr->eth_type);
        }          
        arp_hdr = (struct arp *)(buffer+ETH_HDR_LEN);
   		dump_arp(arp_hdr);
    }
    free(buffer);
    close(sock);
}

void rev_rarp_reply()
{
   int sock;
    void *buffer = NULL;
    ssize_t recvd_size;
    struct ethernet *eth_hdr = NULL;
    struct arp *arp_hdr = NULL;
    struct sock_filter *filter;
    struct sock_fprog  fprog;

    if( (sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
        perror("socket(): ");
        exit(-1);
    }

    /* CHANGE prepare linux packet filter */
    if ((filter = malloc(sizeof(arpfilter))) == NULL) {
        perror("malloc");
        close(sock);
        exit(1);
    }
    memcpy(filter, &arpfilter, sizeof(arpfilter));
    fprog.filter = filter;
    fprog.len = sizeof(arpfilter)/sizeof(struct sock_filter);

    /* CHANGE add filter */
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) == -1) {
        perror("setsockopt");
        close(sock);
        exit(1);
    }

    buffer = malloc(BUFF_SIZE);
    while(1)
    {
        if( (recvd_size = recv(sock, buffer, BUFF_SIZE, 0)) < 0)
        {
            perror("recv(): ");
            free(buffer);
            close(sock);
        }
        if((size_t)recvd_size < (sizeof(struct ethernet) + sizeof(struct arp)))
        {
            printf("Short packet. Packet len: %ld\n", recvd_size);
            continue;
        }
        eth_hdr = (struct ethernet *)buffer;
        if(ntohs(eth_hdr->eth_type) != ETH_P_ARP) {
            printf("Received wrong ethernet type: %X\n", eth_hdr->eth_type);
        }          
        arp_hdr = (struct arp *)(buffer+ETH_HDR_LEN);
   		dump_arp(arp_hdr);
    }
    free(buffer);
    close(sock);
}

int
send_arp_request(char * sip, char * smac, char * tip, char * tmac, int number)
{
	struct in_addr src_in_addr, targ_in_addr;
	struct arp_packet pkt;
	struct sockaddr sa;
	int sock, err;
 	int i=0, j=0;
 	int recvd_size=0;
 	/* buf is buffer containing the ethernet frame */
	char buf[65535];
	struct ethernet *eth_hdr = NULL;
	struct arp *arp_hdr = NULL;
	arp_reply = -1;

	// create a thread to handle receive ARP reply
	struct platformThread_t Platform;
	Platform.pfFnStartRoutine = (void*) rev_arp_reply;
	PLATFORM_ThreadCreate(&Platform);	

	PLATFORM_SleepMSec(100);

	sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP));
	if (sock < 0)        
		{                 
		perror("socket");                
		return -1;        
		}
      
 	pkt.frame_type = htons(ARP_FRAME_TYPE);        
 	pkt.hw_type = htons(ETHER_HW_TYPE);        
 	pkt.prot_type = htons(IP_PROTO_TYPE);        
 	pkt.hw_addr_size = MAC_ADDR_LEN;        
 	pkt.prot_addr_size = IP_ADDR_LEN;        
 	pkt.op = htons(OP_ARP_REQUEST);         
 	get_hw_addr(pkt.targ_hw_addr, tmac);        
 	get_hw_addr(pkt.rcpt_hw_addr, tmac);        
 	get_hw_addr(pkt.src_hw_addr, smac);        
 	get_hw_addr(pkt.sndr_hw_addr, smac);        
 	get_ip_addr(&src_in_addr, sip);        
 	get_ip_addr(&targ_in_addr, tip);        
 	memcpy(pkt.sndr_ip_addr, &src_in_addr, IP_ADDR_LEN);        
 	memcpy(pkt.rcpt_ip_addr, &targ_in_addr, IP_ADDR_LEN);        
 	bzero(pkt.padding, 18);         
 	strcpy(sa.sa_data, DEFAULT_DEVICE); 

 	for (j = 0; j < number; j++)        
 		{                 
 		if (sendto(sock, &pkt, sizeof(pkt), 0, &sa, sizeof(sa)) < 0)                
 			{                         
 			perror("sendto");                        
 			exit(1);                
 			}        
 		}
 	close(sock);	// close send arp sock
 	return arp_reply;
}

int
send_rarp_request(char * sip, char * smac, char * tip, char * tmac, int number)
{
	struct in_addr src_in_addr, targ_in_addr;
	struct arp_packet pkt;
	struct sockaddr sa;
	int sock, err;
 	int i=0, j=0;
 	int recvd_size=0;
 	/* buf is buffer containing the ethernet frame */
	char buf[65535];
	struct ethernet *eth_hdr = NULL;
	struct arp *arp_hdr = NULL;
	rarp_reply = -1;

	// create a thread to handle receive ARP reply
	struct platformThread_t Platform;
	Platform.pfFnStartRoutine = (void*) rev_rarp_reply;
	PLATFORM_ThreadCreate(&Platform);	

	PLATFORM_SleepMSec(100);

	sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP));
	if (sock < 0)        
		{                 
		perror("socket");                
		return -1;        
		}
      
 	pkt.frame_type = htons(RARP_FRAME_TYPE);        
 	pkt.hw_type = htons(ETHER_HW_TYPE);        
 	pkt.prot_type = htons(IP_PROTO_TYPE);        
 	pkt.hw_addr_size = MAC_ADDR_LEN;        
 	pkt.prot_addr_size = IP_ADDR_LEN;        
 	pkt.op = htons(OP_RARP_REQUEST); 

	get_hw_addr(pkt.targ_hw_addr, "ff:ff:ff:ff:ff:ff");        
 	get_hw_addr(pkt.rcpt_hw_addr, tmac);    

 	//get_hw_addr(pkt.rcpt_hw_addr, tmac);        
 	//get_hw_addr(pkt.targ_hw_addr, "ff:ff:ff:ff:ff:ff");	//ES: according to RFC903  

 	get_hw_addr(pkt.src_hw_addr, smac);        
 	get_hw_addr(pkt.sndr_hw_addr, smac);        
 	get_ip_addr(&src_in_addr, sip);        
 	get_ip_addr(&targ_in_addr, tip);

 	memcpy(pkt.sndr_ip_addr, &src_in_addr, IP_ADDR_LEN);        
 	//memcpy(pkt.rcpt_ip_addr, &targ_in_addr, IP_ADDR_LEN);        
 	bzero(pkt.padding, 18);         
 	strcpy(sa.sa_data, DEFAULT_DEVICE); 

 	for (j = 0; j < number; j++)        
 		{                 
 		if (sendto(sock, &pkt, sizeof(pkt), 0, &sa, sizeof(sa)) < 0)                
 			{                         
 			perror("sendto");                        
 			exit(1);                
 			}        
 		}
 	close(sock);	// close send arp sock
 	return rarp_reply;
}

void die(const char* str)
{
	fprintf(stderr,"Error: %s\n",str);
	exit(1);
}


void get_ip_addr(struct in_addr* in_addr,char* str)
{
	struct hostent* hostp;         
	in_addr->s_addr = inet_addr(str);
	
	if (in_addr->s_addr == -1)        
		{                 
			if ((hostp = gethostbyname(str)))                
				{                         
					bcopy(hostp->h_addr, in_addr, hostp->h_length);                
				}                
			else                
				{                         
					fprintf(stderr, "send_arp: unknown host %s\n", str);                        
					exit(1);                
				}        
		}
}

void get_hw_addr(u_char* buf,char* str)
{
	int i;         
	char c, val;         
	for (i = 0; i < ETH_HW_ADDR_LEN; i++)        
		{                 
			if (!(c = tolower(*str++)))                
				{                         
					die("Invalid hardware address");                
				} 

			if (isdigit(c))                
				{                         
					val = c - '0';                
				}                 
			else if (c >= 'a' && c <= 'f')                
				{                         
					val = c - 'a' + 10;               
				}                
			else                
				{                         
					die("Invalid hardware address");                
				}    

			*buf = val << 4;                 
			if (!(c = tolower(*str++)))                
				{                         
					die("Invalid hardware address");                
				}   

			if (isdigit(c))                
				{                         
					val = c - '0';                
				}                 
			else if (c >= 'a' && c <= 'f')                
				{                         
					val = c - 'a' + 10;                
				}                
			else                
				{        
					die("Invalid hardware address");                 
				}      

			*buf++ |= val;                
			if (*str == ':')                
				{                         
					str++;                
				}        
		}
}

#if 0
static void
dump_arp(struct arp *arp_hdr)
{
    uint16_t htype = ntohs(arp_hdr->htype);
    uint16_t ptype = ntohs(arp_hdr->ptype);
    uint16_t oper = ntohs(arp_hdr->oper);
    switch(htype)
    {
        case 0x0001:
          //  printf("ARP HTYPE: Ethernet(0x%04X)\n", htype);
            break;
        default:
         //   printf("ARP HYPE: 0x%04X\n", htype);
            break;
    }
    switch(ptype)
    {
        case 0x0800:
         //   printf("ARP PTYPE: IPv4(0x%04X)\n", ptype);
            break;
        default:
         //   printf("ARP PTYPE: 0x%04X\n", ptype);
            break;
    }
  //  printf("ARP HLEN: %d\n", arp_hdr->hlen);
  //  printf("ARP PLEN: %d\n", arp_hdr->plen);
    switch(oper)
    {
        case 0x0001:
          //  printf("ARP OPER: Request(0x%04X)\n", oper);
            break;
        case 0x0002:
          //  printf("ARP OPER: Response(0x%04X)\n", oper);
            arp_reply = 0;
            break;
        default:
           // printf("ARP OPER: 0x%04X\n", oper);
            break;
    }
    /*
    printf("ARP Sender HA: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp_hdr->sender_ha[0],arp_hdr->sender_ha[1],arp_hdr->sender_ha[2],
           arp_hdr->sender_ha[3], arp_hdr->sender_ha[4], arp_hdr->sender_ha[5]);
    printf("ARP Sender PA: %d.%d.%d.%d\n", arp_hdr->sender_pa[0],
           arp_hdr->sender_pa[1], arp_hdr->sender_pa[2], arp_hdr->sender_pa[3]);
    printf("ARP Target HA: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp_hdr->target_ha[0],arp_hdr->target_ha[1],arp_hdr->target_ha[2],
           arp_hdr->target_ha[3], arp_hdr->target_ha[4], arp_hdr->target_ha[5]);
    printf("ARP Target PA: %d.%d.%d.%d\n", arp_hdr->target_pa[0],
           arp_hdr->target_pa[1], arp_hdr->target_pa[2], arp_hdr->target_pa[3]);
    printf("ARP DONE =====================\n");
    */
}

#else 

static void
dump_arp(struct arp *arp_hdr)
{
    uint16_t oper = ntohs(arp_hdr->oper);
    switch(oper)
    {
    	case OP_ARP_REPLY:
          	arp_reply = 0;
            break;
        case OP_RARP_REPLY:
            rarp_reply = 0;
            break;
    }
}

#endif