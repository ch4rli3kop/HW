#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

char*  print_addr(int addr){
	printf("%d.%d.%d.%d", addr&0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, (addr >> 24) & 0xff);
}

void hexdump(char* pkt, int len){
	
	int dst, src;
	
	memcpy(&src, &pkt[26], 4);
	memcpy(&dst, &pkt[30], 4);
	
	print_addr(src);
	printf(" -> ");
	print_addr(dst);
	printf("\n");	
	/*
	for(int i=0 ; i<len; i++){
		printf("%X ", pkt[i]);
		if (len%16 == 0) printf("\n");
	}
	*/
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	hexdump(packet, header->len);
	//printf("Got a packet\n");
}

void main(int argc, char* argv[]){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "ip proto icmp";
	bpf_u_int32 net;

	handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);
}
