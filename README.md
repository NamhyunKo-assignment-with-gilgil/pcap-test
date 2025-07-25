## 과제 설명


https://gitlab.com/gilgil/sns/-/wikis/basic-header-analysis/basic-header-analysis

https://gitlab.com/gilgil/sns/-/wikis/pcap-programming/pcap-programming

https://gitlab.com/gilgil/sns/-/wikis/pcap-programming/report-pcap-test

## 공부 내용


### 구조체

- 구조체에 대해서는 기본적으로 알고 있는 내요이라 별명을 붙여서 사용했다.
- 새로 배운 구조체의 특징은 구조체 포인터 캐스팅이다.
- 구조체 포인터 캐스팅이란?
    - 특정 문자열(바이트 문자열 포함)의 주소(포인터)에 맞게 해당 구조체 포인터 변수를 연결해주면 구조체의 구조에 맞게 값들이 구조체 내부 변수들 형식에 맞게 들어가는 방법이다.
    - [https://zapiro.tistory.com/entry/구조체를-이용한-메모리-접근](https://zapiro.tistory.com/entry/%EA%B5%AC%EC%A1%B0%EC%B2%B4%EB%A5%BC-%EC%9D%B4%EC%9A%A9%ED%95%9C-%EB%A9%94%EB%AA%A8%EB%A6%AC-%EC%A0%91%EA%B7%BC)

### pcap.h의 함수

https://gitlab.com/gilgil/sns/-/wikis/pcap-programming/pcap-programming

### libnet-headers.h의 구조체

- libnet/headers.h에서 해당 구조체를 프로토콜 패킷 구조에 맞게 이해했다.
- 하나 신기했던 것은 int의 최소 크기가 8bit라 4비트씩 저장된 패킷의 값은 구조체 내에서 4비트씩 쪼개기로 사용한 것이었다.
- 또한 컴파일러의 조건문을 사용하여 바이트오더를 계산하여 ip_v와 ip_hl를 구분한 것을 확인했다.
    - 지금은 리눅스 기준으로 코드를 작성했지만, 추후 반영이 필요하다.

### 각 프로토콜의 패킷 구조

https://gitlab.com/gilgil/sns/-/wikis/basic-header-analysis/basic-header-analysis

https://en.wikipedia.org/wiki/Ethernet_frame

https://en.wikipedia.org/wiki/IPv4

https://en.wikipedia.org/wiki/Transmission_Control_Protocol

## 소스 코드 설명


### 라이브러리 불러오기

- `pcap.h`
- `stdbool.h`
- `stdio.h`

```c
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
```

### `my_ethernet_hdr`, `my_ipv4_hdr`, `my_tcp_hdr` 함수

- `libnet.h`의 구조체 참고
    - 아는 것만 사용하고 싶어서 `ip_v`와 `ip_hl` 는 한번에 저장하고 나중에 비트 계산해서 사용했다.

```c
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
```

### `print_ethernet_packet` 함수

- Ethernet 구조체 포인터를 인자로 받는다.
- 구조체 순서대로 Destination MAC Address, Source MAC Address, Ethernet Type이므로 순서대로 출력해준다.
- Ethernet 타입을 확인한다.
    
    > Most notably, an EtherType value of 0x0800 indicates that the frame contains an IPv4 datagram, 0x0806 indicates an ARP datagram, and 0x86DD indicates an IPv6 datagram.  (참고: https://en.wikipedia.org/wiki/Ethernet_frame)
    > 
    - **0x0800 이면 → ipv4 이므로 계속 함수 진행**
    - 0x0806 이면 → arp 이므로 지금 코드에서는 해당 x
    - 0x86DD 이면 → ipv6 이므로 지금 코드에서는 해당 x

```c
void print_ethernet_packet(Ethernet* ethernet){
    printf("[Ethernet]\n");
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
}
```

### `print_ipv4` 함수

- ip 주소는 일단 4바이트씩 저장되어 있으므로 순서를 확인해서 &연산으로 원하는 값만 가져온 후 비트 이동을 통해 원하는 자리로 맞쳐왔다.
    - 비트 연산으로 값을 사용해서, 구지 바이트 오더를 변경하지 않았다. (little로 저장이되어 있었다.)
    - 추후 반복문으로 구현할 예정이다. (가능할 듯 하다.)
- ip에도 다음 프로토콜의 종류를 저장해놓기 때문에 해당 값을 반환해준다.
    - tcp인지 확인용

```c
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
```

### `print_tcp` 함수

- tcp 데이터 출력
    
    > **Data Offset (DOffset): 4 bits**Specifies the size of the TCP header in 32-bit words. The minimum size header is 5 words and the maximum is 15 words thus giving the minimum size of 20 bytes and maximum of 60 bytes, allowing for up to 40 bytes of options in the header. This field gets its name from the fact that it is also the offset from the start of the TCP segment to the actual data.
    > 
    - TCP 헤더의 길이는 Data Offset으로 확인 가능하다. 근데 얘도 마찬가지로 4 곱해야 원하는 값이 나온다.
        - word로 저장한다.
        - tcp의 word는 4바이트이다.

```c
u_int8_t print_tcp(Tcp* tcp){
    printf("\n[Tcp]\n");
    printf("DST PORT : %d\n", ntohs(tcp->th_dport));
    printf("SRC PORT : %d\n", ntohs(tcp->th_sport));

    return tcp->th_off >> 4;
}
```

### `print_packet` 함수

- 각 print_{프로토콜} 함수를 불러와주는 함수이다.
- 구조체에 해당 패킷에 맞게 포인터 캐스팅을 해주기 위해 시작 지점을 계산해서 넣어준다.
    - 이전 패킷의 헤더 길이를 더해서 넣어준다.
- 추가로 우리가 원하는 패킷만 출력하기 위해 패킷의 종류를 필터링해준다.
    - 다음 패킷이 ipv4와 tcp 인 경우만 이어서 코드를 진행하고 나머지는 그 전에 멈춘다.

```c
void print_packet(const u_char* packet, u_int32_t packet_len){
    Ethernet* ethernet = (Ethernet*) packet;
    u_int16_t ether_type = print_ethernet(ethernet);
    
    if(ether_type != 0x0800) return;
    
    Ipv4* ip = (Ipv4*) (packet + sizeof(Ethernet));
    u_int8_t protocol = print_ipv6(ip);
    
    if(protocol != 0x06) return;

    u_int8_t ip_v = ip->ip_v_n_hl >> 4;
    u_int8_t ip_hl = ip->ip_v_n_hl & 0x0f;
    printf("ip header length : %d %d\n", ip_v, ip_hl);
    
    Tcp* tcp = (Tcp*) (packet + sizeof(Ethernet) + (ip_hl * 4));
    u_int8_t tcp_off = print_tcp(tcp);
    
    u_int8_t data_pointer = sizeof(Ethernet) + (ip_hl * 4) + (tcp_off * 4);

    printf("\nTcp Packet Header Length : %d\n", data_pointer);
    printf("Tcp Packet Data Length : %d\n", packet_len - data_pointer);

    printf("\n[Data] less 10 byte\n");
    for(u_int8_t i = data_pointer; (i < data_pointer + 10) && (i < packet_len); i++) printf("%02x ", *(packet + i));
    printf("\n");

    for(int i = 0; i < 32; i++) printf("="); printf("\n");
}
```

### `main` 함수

- 스켈레톤 코드를 받아와서 print_packet함수만 호출했다.
- 코드를 이해해보자면 프로그램 실행 인자를 검사해서 예외처리를 해준다.
    - parse함수는 네트워크 이름을 인자로 받게 상황을 만들어주는 함수
- pcap을 이용해서 패킷을 받을때 에러 처리를 해주기 위한 코드도 존재한다.
- 무한 반복문으로 패킷을 받아온다.
- packet과 header에 대한 정보를 받아온다.

```cpp
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
    print_packet(packet, header->caplen);
	}

	pcap_close(pcap);
}

```
