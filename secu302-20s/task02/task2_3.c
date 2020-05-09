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

void send_packet(uint32_t src, uint32_t dst, uint16_t id, uint16_t seq, char* data, int data_len){
	int sd;
	struct sockaddr_in sin;
	int t = 1;
	int pkt_len;
	u_char* pbuf;
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
	//ip->length = htons(0x0054);
	//ip->length = htons(0x2222);
	ip->identification = 0xffff;		
	ip->flag_and_offset = 0x0;
	ip->ttl = 64;
	ip->protocol = 1;
	ip->src_ip = dst;
	ip->dst_ip = src;	
	ip->checksum = 0;
	ip->checksum = in_cksum(ip, sizeof(Ip));

	/*uint16_t check_sum = 0;
	for (int i=0; i<20; i+=2){
		check_sum += (buf[14+i] << 8) | buf[14+i+1];
	}*/
	//ip->checksum = ~check_sum;

	pIcmp icmp = (pIcmp)(buf + sizeof(Ip));
	icmp->type = 0x0;
	icmp->code = 0x0;
	icmp->id = id;
	icmp->seq = seq;
	icmp->checksum = 0;

	pkt_len = sizeof(Ip) + sizeof(Icmp);
	if (data_len > 0){
		pbuf = buf + pkt_len;
		memcpy(pbuf, data, data_len);
		pkt_len += data_len;
		icmp->checksum = in_cksum(icmp, sizeof(Icmp) + data_len);
	} else
		icmp->checksum = in_cksum(icmp, sizeof(Icmp));
	
	printf("\n###  send echo-reply  ###\n");	
	if (sendto(sd, buf, pkt_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
		perror("sendto() error\n");
		exit(-1);
	}

}

void ip_addr(int addr, char* ip_buf){
        sprintf(ip_buf, "%d.%d.%d.%d", addr&0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, (addr >> 24) & 0xff);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	pEth eth = (pEth) packet;
        pIp ip;
        pIcmp icmp;
        int data_len;
        char* buf;
        char src[0x20];
        char dst[0x20];

        if (ntohs(eth->type) == 0x0800) ip = (pIp)(packet + sizeof(Eth));
        else return;

        if (ip->protocol == 0x1) icmp = (pIcmp)(packet + sizeof(Eth) + sizeof(Ip));
        else return;

        if (icmp->type == 0x8){ // echo-request
                printf("\n### receive echo-request ###\n");
                ip_addr(ip->src_ip, src);
                ip_addr(ip->dst_ip, dst);
                printf("%s  ->  %s\n", src, dst);
       		data_len = ntohs(ip->length) - sizeof(Ip) - sizeof(Icmp);
		if (data_len > 8){
			buf = packet + sizeof(Eth) + sizeof(Ip) + sizeof(Icmp);
			send_packet(ip->src_ip, ip->dst_ip, icmp->id, icmp->seq, buf, data_len);	
		}
		else send_packet(ip->src_ip, ip->dst_ip, icmp->id, icmp->seq, NULL, 0);
	}
}


int main(int argc, char* argv[]){

	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;
        char filter_exp[] = "ip proto icmp";
        bpf_u_int32 net;

	setvbuf(stdin, 0, 2, 0);
        setvbuf(stdout, 0, 2, 0);
        setvbuf(stderr, 0, 2, 0);

        handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
        pcap_compile(handle, &fp, filter_exp, 0, net);
        pcap_setfilter(handle, &fp);

        pcap_loop(handle, -1, got_packet, NULL);

        pcap_close(handle);
	
	return 0;
}
