#define _CRT_SECURE_NO_WARNINGS
#define WIN32
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <pcap\pcap.h>
#include <pcap.h>
#include <string.h>
#include <WinSock2.h>
#include <stdint.h>

typedef struct Ethernet_Header {
	u_char des[6];
	u_char src[6];
	short int ptype;
}Ethernet_Header;

typedef struct ipaddress {
	u_char ip1;
	u_char ip2;
	u_char ip3;
	u_char ip4;
}ip;

typedef struct IPHeader {
	u_char HeaderLength : 4;
	u_char Version : 4;
	u_char TypeOfService;
	u_short TotalLength;
	u_short ID;
	u_short FlagOffset;

	u_char TimeToLive;
	u_char Protocol;
	u_short checksum;
	ip SenderAddress;
	ip DestinationAddress;
	u_int Option_Padding;

	unsigned short source_port;
	unsigned short dest_port;
}IPHeader;

typedef struct TCPHeader
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short tcp_checksum;
	unsigned short urgent_pointer;
}TCPHeader;

typedef struct udp_hdr {
	unsigned short source_port;
	unsigned short dest_port;
	unsigned short udp_length;
	unsigned short udp_checksum;

} UDP_HDR;

typedef struct CheckSummer {
	u_short part1;
	u_short part2;
	u_short part3;
	u_short part4;
	u_short part5;
	u_short checksum;
	u_short part6;
	u_short part7;
	u_short part8;
	u_short part9;

}CheckSummer;

typedef struct DNS {
	u_short identifier_dns;
	u_short flag_dns;
	u_short question_dns;
	u_short answer_dns;
	u_char domain_name_dns[60];

}domain;

typedef struct DHCP {
	unsigned char op;             // 오퍼레이션 코드(메시지 처리 방식)
	unsigned char htype;          // 하드웨어 타입
	unsigned char hlen;           // 하드웨어 주소 길이
	unsigned char hops;           // Hops
	unsigned int transactionId;   // 트랜잭션 ID
	unsigned short elapsed;       // DHCP 헤더 내의 시간 정보
	unsigned short flags;         // DHCP 헤더 내의 부팅 프로세스 플래그
	unsigned char messageType;    // DHCP 메시지 타입을 나타내는 값
} DHCP;

// HTTP 패킷을 처리하는 함수
void packet_handler_http(u_char* param, const struct pcap_pkthdr* h, const u_char* data);
// DNS 패킷을 처리하는 함수
void packet_handler_dns(u_char* param, const struct pcap_pkthdr* h, const u_char* data);
// DHCP 패킷을 처리하는 함수
void packet_handler_dhcp(u_char* param, const struct pcap_pkthdr* h, const u_char* data);

// 프로토콜 정보를 출력하는 함수
void print_protocol(IPHeader* IH, CheckSummer* CS);

// 패킷의 16진수 데이터를 출력하는 함수
void print_packet_hex_data(u_char* data, int Size);

// pcap_loop 실행 함수
void run_pcap_loop(pcap_t* pickedDev, void (*handler)());

// HTTP 요청 패킷, 응답 패킷 필터링
boolean is_http_packet(uint8_t* data);


void main() {
	pcap_if_t* allDevice;
	pcap_if_t* device;
	char errorMSG[256];
	char counter = 0;
	pcap_t* pickedDev;

	if ((pcap_findalldevs(&allDevice, errorMSG)) == -1)
		printf("장치 검색 오류");

	int count = 0;

	// 사용 가능한 네트워크 장치 목록 출력
	for (device = allDevice; device != NULL; device = device->next) {
		printf("┏  %d 번 네트워크 카드 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n", count);
		printf("┃ 어댑터 정보 : %s ┃\n", device->name);
		printf("┃ 어댑터 설명 : %s \n", device->description);
		printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n");
		count = count + 1;
	}

	printf("패킷을 수집할 네트워크 카드 선택 >> ");
	device = allDevice;

	int choice;
	scanf_s("%d", &choice);

	for (count = 0; count < choice; count++) {
		device = device->next;
	}

	pickedDev = pcap_open_live(device->name, 65536, 0, 1000, errorMSG);
	pcap_freealldevs(allDevice);

	while (1) {
		int protocol = 0;
		printf("\n분석을 원하는 프로토콜을 고르시오.\n");
		printf("1. FTP(TCP)\n2. HTTP(TCP)\n3. DNS(UDP)\n4. DHCP\n5. 종료\n");
		printf(" >> ");
		scanf_s("%d", &protocol);

		printf("\n패킷 분석 중 멈추고 싶으면 'p', 나가고 싶으면 'q'를 누르시오.\n\n");
		Sleep(3000);


		switch (protocol) {
		case 1:
			printf("안할듯");
			break;
		case 2:
			run_pcap_loop(pickedDev, packet_handler_http);
			break;
		case 3:
			run_pcap_loop(pickedDev, packet_handler_dns);
			break;
		case 4:
			run_pcap_loop(pickedDev, packet_handler_dhcp);
			break;
		case 5:
			printf("프로그램을 종료합니다.\n");
			break;
		default:
			printf("잘못 누르셨습니다. 다시 입력해주세요.\n");
			break;
		}
	}
}

void packet_handler_http(u_char* param, const struct pcap_pkthdr* h, const u_char* data) {
	(VOID)(param);
	(VOID)(data);

	Ethernet_Header* EH = (Ethernet_Header*)data;
	IPHeader* IH = (struct IPHeader*)(data + 14);
	CheckSummer* CS = (struct CheckSummer*)(data + 14);
	TCPHeader* TCP = (TCPHeader*)(data + 14 + (IH->HeaderLength) * 4);

	// UDP 포트가 80이면서 프로토콜이 TCP인 경우에만 처리
	if ((ntohs(TCP->source_port) == 80 || ntohs(TCP->dest_port) == 80) && IH->Protocol == IPPROTO_TCP) {

		// 34 == 이더넷 헤더 크기(14) + TCP 헤더 크기(20)
		// IH->HeaderLength == IP 헤드의 길이(32bit 단위) / IH->HeaderLength*4 == IP 헤드의 길이(byte 단위)
		// 결론 : 34 + (IH->HeaderLength) * 4는 포인터를 이더넷과 IP 헤더를 건너뛰고 패킷의 페이로드 데이터 시작 부분을 가리키도록 설정
		// HTTP 패킷
		uint8_t* packet = data + 34 + (IH->HeaderLength) * 4;
		if (is_http_packet(packet)) {
			print_protocol(IH, CS);

			printf("┃  --------------------------------------------------------------------------  \n");
			printf("┃\t\t*[ TCP 헤더 ]*\t\t\n");
			printf("┃\tSCR PORT : %d\n", ntohs(TCP->source_port));
			printf("┃\tDEST PORT : %d\n", ntohs(TCP->dest_port));
			printf("┃\tSeg : %u\n", ntohl(TCP->sequence));
			printf("┃\tAck : %u\n", ntohl(TCP->acknowledge));
			printf("┃\tChecksum : 0x%04X\n", ntohs(TCP->tcp_checksum)); // 체크섬
			printf("┃\n");
			printf("┃  --------------------------------------------------------------------------  \n");
			printf("┃\t\t*[ Application 헤더 ]*\t\t\n");
			char* end_of_headers = strstr((char*)packet, "\r\n\r\n");
			if (end_of_headers != NULL) {
				// '\r\n\r\n'이 발견된 경우, 해당 위치까지만 출력
				int header_length = end_of_headers - (char*)packet;
				char* headers = (char*)malloc(header_length + 1); // 배열의 크기를 변수로 둘 수 없기 때문에 동적 메모리 할당
				headers[header_length + 1];
				memcpy(headers, packet, header_length);
				headers[header_length] = '\0'; // 문자열 끝에 null 문자 추가
				printf("%s", headers);
				free(headers); // 동적으로 할당한 메모리 해제
			}
			else {
				// '\r\n\r\n'이 발견되지 않은 경우, 전체 패킷 출력
				printf("┃\t%s", packet);
			}
			printf("┃\n");
			printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
		}
	}
}

void packet_handler_dns(u_char* param, const struct pcap_pkthdr* h, const u_char* data) {
	(VOID)(param);
	(VOID)(data);

	Ethernet_Header* EH = (Ethernet_Header*)data;

	IPHeader* IH = (struct IPHeader*)(data + 14);
	CheckSummer* CS = (struct CheckSummer*)(data + 14);
	UDP_HDR* UDP = (struct UDP_HDR*)(data + 34);
	domain* dns = (struct DNS*)(data + 42);

	// UDP 포트가 53이면서 프로토콜이 UDP인 경우에만 처리
	if ((ntohs(UDP->source_port) == 53 || ntohs(UDP->dest_port) == 53) && IH->Protocol == IPPROTO_UDP) {
		print_protocol(IH, CS);

		printf("┃  --------------------------------------------------------------------------  \n");
		printf("┃\t\t*[ UDP 헤더 ]*\t\t\n");
		printf("┃\tSrc Port : %d\n", ntohs(UDP->source_port)); // 출발지 포트
		printf("┃\tDest Port : %d\n", ntohs(UDP->dest_port)); // 목적지 포트
		printf("┃\tLength : %d\n", ntohs(UDP->udp_length)); // 길이
		printf("┃\tChecksum : 0x%04X\n", ntohs(UDP->udp_checksum)); // 체크섬
		printf("┃\n");

		printf("┃  --------------------------------------------------------------------------  \n");
		printf("┃\t\t*[ Application 헤더 ]*\t\t\n");
		printf("┃\tIdentifier : 0x%04X\n", ntohs(dns->identifier_dns)); // 식별자
		printf("┃\tFlag : 0x%04X\n", ntohs(dns->flag_dns)); // 플래그
		printf("┃\tQuestion : %d\n", ntohs(dns->question_dns)); // 질의
		printf("┃\tAnswer : %d\n", ntohs(dns->answer_dns)); // 응답
		printf("┃\tDomain Name : "); // 도메인 이름
		for (int i = 0; i < 60; i++) {
			if (dns->domain_name_dns[i] > 60)
				printf("%c", dns->domain_name_dns[i]);
			else if (dns->domain_name_dns[i - 1] > 60)
				printf(".");
			if ((dns->domain_name_dns[i - 2] == 'c' && dns->domain_name_dns[i - 1] == 'o' && dns->domain_name_dns[i] == 'm') || dns->domain_name_dns[i - 2] == 'n' && dns->domain_name_dns[i - 1] == 'e' && dns->domain_name_dns[i] == 't')
				break;
		}
		printf("\n");
		printf("┃\n");
		printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
	}
}

void packet_handler_dhcp(u_char* param, const struct pcap_pkthdr* h, const u_char* data) {
	(VOID)(param);
	(VOID)(data);

	Ethernet_Header* EH = (Ethernet_Header*)data;

	IPHeader* IH = (struct IPHeader*)(data + 14);
	CheckSummer* CS = (struct CheckSummer*)(data + 14);
	UDP_HDR* UDP = (struct UDP_HDR*)(data + 34);
	DHCP* dhcp = (struct DHCP*)(data + 42);


	const char* dhcpMessageType = "";
	switch (data[284]) {
	case 1:
		dhcpMessageType = "DHCP Discover";
		break;
	case 2:
		dhcpMessageType = "DHCP Offer";
		break;
	case 3:
		dhcpMessageType = "DHCP Request";
		break;
	case 4:
		dhcpMessageType = "DHCP Decline";
		break;
	case 5:
		dhcpMessageType = "DHCP Acknowledge";
		break;
	case 6:
		dhcpMessageType = "DHCP Negative Acknowledge";
		break;
	case 7:
		dhcpMessageType = "DHCP Release";
		break;
	case 8:
		dhcpMessageType = "DHCP Inform";
		break;
	default:
		dhcpMessageType = "Unknown DHCP Message Type";
		break;
	}

	// UDP 포트가 67이면서 프로토콜이 DHCP인 경우에만 처리
	if ((ntohs(UDP->source_port) == 67 || ntohs(UDP->dest_port) == 67) && IH->Protocol == IPPROTO_UDP) {
		print_protocol(IH, CS);

		printf("┃  --------------------------------------------------------------------------  \n");
		printf("┃\t\t*[ UDP 헤더 ]*\t\t\n");
		printf("┃\tSrc Port : %d\n", ntohs(UDP->source_port)); // 출발지 포트
		printf("┃\tDest Port : %d\n", ntohs(UDP->dest_port)); // 목적지 포트
		printf("┃\tLength : %d\n", ntohs(UDP->udp_length)); // 길이
		printf("┃\tChecksum : 0x%04X\n", ntohs(UDP->udp_checksum)); // 체크섬
		printf("┃\n");

		printf("┃  --------------------------------------------------------------------------  \n");
		printf("┃\t\t*[ Application 헤더 ]*\t\t\n");
		printf("┃\tMessage Type: %s\n", dhcpMessageType); // DHCP 메시지 타입
		printf("┃\tOperation Code (op): %d\n", dhcp->op);
		printf("┃\tHardware Type (htype): 0x%02X\n", dhcp->htype);
		printf("┃\tHardware Address Length: %d\n", dhcp->hlen);
		printf("┃\tHops: %d\n", dhcp->hops); // Hops
		printf("┃\tTransaction ID: 0x%08x\n", ntohl(dhcp->transactionId)); // 트랜잭션 ID
		printf("┃\tElapsed: %d\n", ntohs(dhcp->elapsed)); // DHCP 헤더 내의 시간 정보
		printf("┃\tFlags: 0x%04X\n", ntohs(dhcp->flags)); // 부팅 프로세스 플래그
		printf("┃\n");
		printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
	}
}

// 이더넷 헤더, UDP, TCP 헤더 뺌
void print_protocol(IPHeader* IH, CheckSummer* CS) {
	printf("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
	printf("┃\t\t*[ IP 헤더 ]*\n");
	printf("┃\tChecksum : 0x%04X\n", ntohs(CS->checksum)); // 체크섬
	printf("┃\tTTL : %d\n", IH->TimeToLive); // TTL
	printf("┃\tSrc IP Address : %d.%d.%d.%d\n", IH->SenderAddress.ip1, IH->SenderAddress.ip2, IH->SenderAddress.ip3, IH->SenderAddress.ip4); // 출발지 IP 주소
	printf("┃\tDest IP Address : %d.%d.%d.%d\n", IH->DestinationAddress.ip1, IH->DestinationAddress.ip2, IH->DestinationAddress.ip3, IH->DestinationAddress.ip4); // 목적지 IP 주소
	printf("┃\n");

	print_packet_hex_data((u_char*)IH, ntohs(IH->TotalLength));
}

void print_packet_hex_data(u_char* data, int Size) {
	unsigned char a, line[17], c;
	int j;

	printf("┃  --------------------------------------------------------------------------  \n");
	printf("┃\t\t*[ 패킷 내용 ]*\n");
	printf("┃");
	for (int i = 0; i < Size; i++) {
		c = data[i];
		printf(" %.2x", (unsigned int)c);
		a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';
		line[i % 16] = a;
		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1) {
			line[i % 16 + 1] = '\0';
			printf("          ");
			for (j = strlen((const char*)line); j < 16; j++) {
				printf("   ");
			}
			printf("%s \n", line);
			printf("┃");
		}

		if (i == Size - 1 && (i + 1) % 16 != 0) {
			for (j = 0; j < (16 - (i + 1) % 16) * 3; j++) {
				printf(" ");
			}
			printf(" ");
			for (j = 0; j <= i % 16; j++) {
				printf("   ");
			}
		}
	}
	printf("\n");
}



boolean is_http_packet(uint8_t* data) {
	if (strncmp(data, "HTTP", 4) == 0)
		return 1;

	char* http_methods[] = { "GET", "POST", "PUT", "DELETE", NULL };
	for (int i = 0; http_methods[i] != NULL; i++) {
		if (strncmp(data, http_methods[i], strlen(http_methods[i])) == 0)
			return 1;
	}
	return 0;
}

void run_pcap_loop(pcap_t* pickedDev, void (*handler)()) {
    while (1) {
        if (_kbhit()) {
            char ch = _getch();
            if (ch == 'q' || ch == 'Q') {
                break;
            }
            else if (ch == 'p' || ch == 'P') {
                printf("일시정지(아무키 입력시 다시 분석 진행)\n");
                _getch();
                printf("다시 실행\n");
            }
        }
        pcap_loop(pickedDev, 0, handler, NULL);
    }
}