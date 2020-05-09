#include <stdio.h>
#include <pcap.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	printf("AAA\n");	
	//printf("%s  -> ", inet_ntoa(pkt.ip.src_ip) );
}

int main(int argc, char* argv[]){
	pcap_t *handle;
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

