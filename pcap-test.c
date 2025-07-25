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

u_int16_t print_ethernet(Ethernet* ethernet){
    printf("\n[Ethernet]\n");

    printf("DST MAC : ");
    for (int i = 0; i < 6 ; i++) {
        printf("%02x",ethernet->ether_dhost[i]);
        if (i != 5) printf(":");
        else printf("\n");
    }

    printf("SRC MAC : ");
    for (int i = 0; i < 6 ; i++) {
        printf("%02x",ethernet->ether_shost[i]);
        if (i != 5) printf(":");
        else printf("\n");
    }

    printf("Protocol : %04x\n", ntohs(ethernet->ether_type));
    
    return ntohs(ethernet->ether_type);
}

u_int8_t print_ipv6(Ipv4* ip){
    printf("\n[Ipv4]\n");

    printf("DST IP : ");
    printf("%d.", (ip->ip_dst & 0x000000ff));
    printf("%d.", (ip->ip_dst & 0x0000ff00) >> 8);
    printf("%d.", (ip->ip_dst & 0x00ff0000) >> 16);
    printf("%d\n", (ip->ip_dst & 0xff000000) >> 24);

    printf("SRC IP : ");
    printf("%d.", (ip->ip_src & 0x000000ff));
    printf("%d.", (ip->ip_src & 0x0000ff00) >> 8);
    printf("%d.", (ip->ip_src & 0x00ff0000) >> 16);
    printf("%d\n", (ip->ip_src & 0xff000000) >> 24);

    printf("Protocol : %02x\n", ip->ip_p);

    return ip->ip_p;
}

void print_packet(const u_char* packet){
    Ethernet* ethernet = (Ethernet*) packet;
    u_int16_t ether_type = print_ethernet(ethernet);
    
    if(ether_type != 0x0800) return;
    
    Ipv4* ip = (Ipv4*) (packet + sizeof(Ethernet));
    u_int8_t protocol = print_ipv6(ip);
    
    if(protocol != 0x06) return;

    printf("ip header length : %02x %02x\n",ip->ip_v_n_hl >> 4, ip->ip_v_n_hl & 0x00ff);
    // Tcp* tcp = (Tcp*) (packet + sizeof(Ethernet) + );




    for(int i = 0; i < 32; i++) printf("="); printf("\n");
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
