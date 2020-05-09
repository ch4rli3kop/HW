#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>

#define TARGET "192.168.41.140"

typedef struct ethernet_header{
   	uint8_t dst_mac[6];
   	uint8_t src_mac[6];
   	uint16_t type;
} Eth, *pEth;

typedef struct ip_header{
   	uint8_t version_and_length;
   	uint8_t type;
   	uint16_t length;
   	uint16_t identification;
   	uint16_t flag_and_offset;
   	uint8_t ttl;
   	uint8_t protocol;
   	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dst_ip;
} Ip, *pIp;

typedef struct icmp_header{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t id;
	uint16_t seq;
} Icmp, *pIcmp;

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
}


int main(int argc, char* argv[]){
	int sd;
	struct sockaddr_in sin;
	int t = 1;
	u_char buf[0x100];
		
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sd < 0) {
		perror("socket() error\n");
		exit(-1);
	}

	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &t, sizeof(t)) < 0){
		perror("setsockopt() error\n");
		exit(-1);
	}

	sin.sin_family = AF_INET;
	inet_aton(TARGET, &sin.sin_addr);

	/*
	pEth eth = (pEth) buf;
	memcpy(&eth->dst_mac, "\xff\xff\xff\xff\xff\xff", 6);
	memcpy(&eth->src_mac, "\x11\x22\x33\x44\x55\x66", 6);
	eth->type = htons(0x0800);
	*/

	pIp ip = (pIp)(buf);
	ip->version_and_length = 0x45;
	ip->type = 0x00;
	ip->length = htons(0x0054);
	ip->length = htons(0x2222);
	ip->identification = 0xffff;		
	ip->flag_and_offset = htons(0x4000);
	ip->ttl = 64;
	ip->protocol = 1;
	inet_aton("192.168.41.144", &ip->src_ip);
	inet_aton(TARGET, &ip->dst_ip);
	ip->checksum = 0;
	//ip->checksum = in_cksum(ip, sizeof(Ip));

	/*uint16_t check_sum = 0;
	for (int i=0; i<20; i+=2){
		check_sum += (buf[14+i] << 8) | buf[14+i+1];
	}*/
	//ip->checksum = ~check_sum;

	pIcmp icmp = (pIcmp)(buf + sizeof(Ip));
	icmp->type = 0x8;
	icmp->code = 0x0;
	icmp->id = 1;
	icmp->seq = 1;
	icmp->checksum = 0;
	icmp->checksum = in_cksum(icmp, sizeof(Icmp));

	if (sendto(sd, buf, sizeof(Ip) + sizeof(Icmp), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
		perror("sendto() error\n");
		exit(-1);
	}

	return 0;
}
