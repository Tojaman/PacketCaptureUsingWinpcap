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

// DNS 패킷을 처리하는 함수
void packet_handler_http(u_char* param, const struct pcap_pkthdr* h, const u_char* data);
void packet_handler_dns(u_char* param, const struct pcap_pkthdr* h, const u_char* data);

// 프로토콜 정보를 출력하는 함수
void print_protocol(Ethernet_Header* EH, IPHeader* IH, CheckSummer* CS);

// 패킷의 16진수 데이터를 출력하는 함수
void print_packet_hex_data(u_char* data, int Size);

boolean is_http_packet(uint8_t* data);


/*전역변수*/
u_int sel = 0;

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
		printf("\n프로토콜을 선택해 주세요.\n");
		printf(" 1. TCP\n 2. UDP\n 3. HTTP\n 4. FTP\n 5. DNS\n 6. DHCP\n 8. IP로 검색\n");
		printf(" >> ");
		scanf_s("%d", &sel);
		switch (sel) {
		case 1:
			printf("안할듯");
			break;
		case 2:
			printf("안할듯");
			break;
		case 3:
			pcap_loop(pickedDev, 0, packet_handler_http, NULL);
			break;
		case 4:
			printf("준비중");
			break;
		case 5:
			pcap_loop(pickedDev, 0, packet_handler_dns, NULL);
			break;
		case 6:
			printf("준비중");
			break;
		default:
			printf("다시입력\n");
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
			print_protocol(EH, IH, CS);

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
		print_protocol(EH, IH, CS);

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

// UDP 왜넣음?
void print_protocol(Ethernet_Header* EH, IPHeader* IH, CheckSummer* CS) {
	printf("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
	printf("┃\t\t*[ Ethernet 헤더 ]*\t\t\n");
	printf("┃\tSrc MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->src[0], EH->src[1], EH->src[2], EH->src[3], EH->src[4], EH->src[5]);//송신자 MAC
	printf("┃\tDst MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->des[0], EH->des[1], EH->des[2], EH->des[3], EH->des[4], EH->des[5]);//수신자 MAC
	printf("┃--------------------------------------------\n");

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