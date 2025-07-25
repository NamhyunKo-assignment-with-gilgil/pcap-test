#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

typedef struct my_ethernet_hdr {	/* ethernet_hdr total 14bytes */
    u_int8_t  ether_dhost[6];	/* destination ethernet address */
    u_int8_t  ether_shost[6];	/* source ethernet address */
    u_int16_t ether_type;	/* protocol */
} Ethernet;

typedef struct my_ipv4_hdr {	/* ipv4_hdr */
    u_int8_t ip_v_n_hl;	/* version & IHL(header length) */
    u_int8_t ip_tos;	/* TOS(type of service) */
    u_int16_t ip_len;	/* total length */
    u_int16_t ip_id;	/* identification */
    u_int16_t ip_off;	/* flags & fragment offset */
    u_int8_t ip_ttl;	/* TTL(time to live) */
    u_int8_t ip_p;	/* protocol */
    u_int16_t ip_sum;	/* header checksum */
    u_int32_t ip_src, ip_dst;	/* source & dest address */
} Ipv4;

typedef struct my_tcp_hdr{	/* tcp_hdr */
    u_int16_t th_sport;	/* source port */
    u_int16_t th_dport;	/* destination port */
    u_int32_t th_seq;	/* sequence number */
    u_int32_t th_ack;	/* acknowledgement number */
	u_int8_t th_off;	/* data offset & reserved */
    u_int8_t th_flags;	/* control flags */
    u_int16_t th_win;	/* window */
    u_int16_t th_sum;	/* checksum */
    u_int16_t th_urp;	/* urgent pointer */
} Tcp;

void print_packet(const u_char* packet){
    Ethernet* ethernet = (Ethernet*) packet;
    

    for(int i = 0; i < 32; i++) printf("=");
    printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
        print_packet(packet);
	}

	pcap_close(pcap);
}
