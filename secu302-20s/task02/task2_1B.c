#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

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
   	//struct in_addr src_ip;
   	//struct in_addr dst_ip;
	uint32_t src_ip;
	uint32_t dst_ip;
} Ip, *pIp;

typedef struct tcp_header{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t data_offset;
	uint8_t flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
} Tcp, *pTcp;

void ip_addr(int addr, char* ip_buf){
	sprintf(ip_buf, "%d.%d.%d.%d", addr&0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, (addr >> 24) & 0xff);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	pEth eth = (pEth) packet;	
	pIp ip;
	pTcp tcp;
	int data_len;
	char buf[0x1000];
	char src[0x20];
	char dst[0x20];

	if (ntohs(eth->type) == 0x0800) ip = (pIp)(packet + sizeof(Eth));
	else return;

	if (ip->protocol == 0x6) tcp = (pTcp)(packet + sizeof(Eth) + sizeof(Ip));
	else return;

	if (ntohs(tcp->src_port) == 23 || ntohs(tcp->dst_port) == 23){
		printf("\n### Telnet ###\n");
		ip_addr(ip->src_ip, src);
		ip_addr(ip->dst_ip, dst);
		printf("%s  ->  %s\n", src, dst);
		data_len = ntohs(ip->length) - sizeof(Ip) - sizeof(Tcp);
		printf("Data len : %d\n", data_len);
		memcpy(buf, (char*)(packet + sizeof(Eth) + sizeof(Ip) + sizeof(Tcp)), data_len);
		buf[data_len] = '\x00';
		printf("Data : \n%s\n", buf);
	}
}

void main(int argc, char* argv[]){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "ip proto tcp";
	bpf_u_int32 net;

	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);

	handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);
}
