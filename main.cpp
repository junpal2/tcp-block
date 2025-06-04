#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

Mac my_mac;
Ip my_ip;

typedef struct _pseudo_header {
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
} pseudo_header;

void usage(){
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

//디버깅용 raw 데이터 출력
void debug(char* ptr, uint32_t num){
	for(int i=0; i<num; i++){
		printf("%02X ", ptr[i]);
	}
}

int GetAddrs(const char* interface, Mac* my_mac, Ip* my_ip){
	struct ifreq ifr;
	int sockfd, ret;
	char ipstr[30]={0};
	uint8_t macbuf[6]={0};

	sockfd=socket(AF_INET, SOCK_DGRAM, 0); //정보요청용
	if(sockfd<0){
		printf("socket() FAILED\n");
		return -1;
	}

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	ret=ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret<0){
		printf("ioctl() FAILED\n");
		close(sockfd);
		return -1;
	}
	memcpy(macbuf, ifr.ifr_hwaddr.sa_data, 6);
	*my_mac=Mac(macbuf);

	ret=ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret<0){
		printf("ioctl() FAILED\n");
		close(sockfd);
		return -1;
	}
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
	//sa_data의 0~1은 포트
	*my_ip=Ip(ipstr);
	close(sockfd);

	return 0;
}

uint16_t Checksum(uint16_t* ptr, int len){
	uint32_t sum=0;
	uint16_t odd=0;
	
	while(len>1){
		sum+=*ptr++; //16비트 더하고 다음 16비트로
		len-=2;
	}
	if(len==1){ //길이 홀수면 마지막 1바이트 16비트로 바꿔서 더하기
		*(uint8_t*)(&odd)=(*(uint8_t *)ptr);
		sum+=odd;
	}
	while(sum>>16){
		sum=(sum&0xFFFF)+(sum>>16);
	}
	return (uint16_t)~sum;
}

void trim(char* s) {
    int len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\n' || s[len - 1] == '\r'))
        s[--len] = '\0';
}

int main(int argc, char* argv[]){
	if(argc!=3){
		usage();
		return 0;
	}
	char* dev =(char*)malloc(strlen(argv[1])+1);
	memset(dev, 0, strlen(argv[1])+1);
	strncpy(dev, argv[1], strlen(argv[1]));
	GetAddrs(dev, &my_mac, &my_ip);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle=pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if(handle==nullptr){
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char* pattern=(char*)malloc(strlen(argv[2])+1);
	memset(pattern, 9, strlen(argv[2])+1);
	strncpy(pattern, argv[2], strlen(argv[2]));
	trim(pattern);

	struct pcap_pkthdr* header;
	const u_char* packet;
	PEthHdr ethernet_hdr;
	PIpHdr ip_hdr;
	PTcpHdr tcp_hdr;
	int res;

	while(true){
		res=pcap_next_ex(handle, &header, &packet);
		if(res==0) continue;
		else if(res==PCAP_ERROR || res==PCAP_ERROR_BREAK){
			printf("pcap_next_ex() return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		ethernet_hdr=(PEthHdr)packet; //첫 14바이트
		if(ethernet_hdr->type()==EthHdr::Ip4){
			ip_hdr=(PIpHdr)((uint8_t*)ethernet_hdr+sizeof(struct EthHdr));
			uint32_t iphdr_len=ip_hdr->ip_len*4;
			uint32_t ippkt_len=ntohs(ip_hdr->total_len); //패킷 전체길이
			uint32_t pkt_len=ippkt_len+sizeof(struct EthHdr);
			
			if(ip_hdr->proto==6){ //TCP
				tcp_hdr=(PTcpHdr)((uint8_t*)ip_hdr+iphdr_len);
				uint32_t tcphdr_len=tcp_hdr->th_off*4;
				uint32_t tcpdata_len=ippkt_len-iphdr_len-tcphdr_len;

				if(tcpdata_len==0) continue;

				char* tcp_data=(char*)malloc(tcpdata_len+1);
				memset(tcp_data, 0, tcpdata_len+1);
				strncpy(tcp_data, (char*)((uint8_t*)tcp_hdr+tcphdr_len), tcpdata_len);

				if(strstr(tcp_data, pattern) && !strncmp(tcp_data, "GET", 3)){ 
					//패턴 포함 + HTTP GET 요청
					
					//1. 클라이언트에게 FIN+ACK 패킷 전송
					int rawsock=socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
					int value=1;
				       	//IP_HDRINCL 옵션 활성화, 직접 만든 IP 헤더 사용
					//value = 1이면 사용자가 직접 IP 헤더 생성
					//(char*):const void* 대신 char* 를 요구할 수도 있기에
					setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, (char *)&value, sizeof(value));

					struct sockaddr_in rawaddr;
					rawaddr.sin_family=AF_INET;
					rawaddr.sin_port=tcp_hdr->sport; //클라이언트 포트
					rawaddr.sin_addr.s_addr=(uint32_t)ip_hdr->sip_; //클라이언트 ip
					const char* tcpdata_my="HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
					uint16_t iphdr_my_len=sizeof(IpHdr), tcphdr_my_len=sizeof(TcpHdr), tcpdata_my_len=strlen(tcpdata_my);
					uint16_t my_total_len=iphdr_my_len+tcphdr_my_len+tcpdata_my_len;

					char* my_packet=(char*)malloc(my_total_len+1);
					memset(my_packet, 0, my_total_len+1);

					PIpHdr iphdr_my=(PIpHdr)my_packet;
					PTcpHdr tcphdr_my=(PTcpHdr)(my_packet+iphdr_my_len);
					memcpy(my_packet+iphdr_my_len+tcphdr_my_len, tcpdata_my, tcpdata_my_len);

					tcphdr_my->sport=tcp_hdr->dport;
					tcphdr_my->dport=tcp_hdr->sport;
					tcphdr_my->seqnum=tcp_hdr->acknum; //org-packet.ack 값 그대로
					tcphdr_my->acknum=htonl(ntohl(tcp_hdr->seqnum)+tcpdata_len); //org-packet.seq 값에 org-packet.tcp_data_size 를 더한 값
					tcphdr_my->th_off=tcphdr_my_len/4;
					tcphdr_my->flags=0b00010001; //ACK: 0b00010000 FIN: 0b00000001
					tcphdr_my->win=htons(60000); //16비트, 최대 65535


					iphdr_my->ip_len=iphdr_my_len/4;
					iphdr_my->ip_v=4;
					iphdr_my->total_len=htons(my_total_len); //IP+TCP
					iphdr_my->ttl=128;
					iphdr_my->proto=6;
					iphdr_my->sip_=ip_hdr->dip_;
					iphdr_my->dip_=ip_hdr->sip_;

					pseudo_header* psdheader=(pseudo_header*)malloc(sizeof(pseudo_header));
					memset(psdheader, 0, sizeof(pseudo_header));
					psdheader->source_address=ip_hdr->dip_;
					psdheader->dest_address=ip_hdr->sip_;
					psdheader->protocol=IPPROTO_TCP;
					psdheader->tcp_length=htons(tcphdr_my_len+tcpdata_my_len);

					//연속적이지 않기에 pseudo header와 TCP header+data를 따로 계산해서 더함
					uint32_t tcp_checksum=Checksum((uint16_t*)tcphdr_my, tcphdr_my_len+tcpdata_my_len)+Checksum((uint16_t*)psdheader, sizeof(pseudo_header));
					tcphdr_my->crc=(tcp_checksum&0xffff)+(tcp_checksum>>16);
					iphdr_my->check=Checksum((uint16_t*)iphdr_my, iphdr_my_len);

					if(sendto(rawsock, my_packet, my_total_len, 0, (struct sockaddr *)&rawaddr, sizeof(rawaddr))<0){
						perror("Send failed");
						return -1;
					}
					free(psdheader);
					free(my_packet);
					close(rawsock);

					//2.서버에게 RST 패킷 전송
					uint32_t newpkt_len=sizeof(EthHdr)+iphdr_len+sizeof(TcpHdr);
					char* newpkt=(char*)malloc(newpkt_len);
					memset(newpkt, 0, newpkt_len);
					memcpy(newpkt, packet, newpkt_len);

					ethernet_hdr=(PEthHdr)newpkt;
					ip_hdr=(PIpHdr)((char*)ethernet_hdr+sizeof(EthHdr));
					tcp_hdr=(PTcpHdr)((char*)ip_hdr+iphdr_len);

					//L2 switch의 CAM table이 깨지는 것을 방지하기 위해 자신 인터페이스의 mac 값을 사용
					ethernet_hdr->smac_=my_mac;
					//org-packet의 ether.dmac은 이미 복사됨
					ip_hdr->total_len=htons(iphdr_len+sizeof(TcpHdr));
					ip_hdr->check=0;
					tcp_hdr->th_off=sizeof(TcpHdr)/4;
					tcp_hdr->seqnum=htonl(ntohl(tcp_hdr->seqnum)+tcpdata_len);
					tcp_hdr->flags=0b00010100;
					tcp_hdr->crc=0;

					psdheader=(pseudo_header*)malloc(sizeof(pseudo_header));
					memset(psdheader, 0, sizeof(pseudo_header));
					psdheader->source_address=ip_hdr->sip_;
					psdheader->dest_address=ip_hdr->dip_;
					psdheader->protocol=IPPROTO_TCP;
					psdheader->tcp_length=htons(sizeof(TcpHdr));

					tcp_checksum=Checksum((uint16_t*)tcp_hdr, sizeof(TcpHdr))+Checksum((uint16_t*)psdheader, sizeof(pseudo_header));
					tcp_hdr->crc=(tcp_checksum&0xFFFF)+(tcp_checksum>>16);
					ip_hdr->check=Checksum((uint16_t*)ip_hdr, iphdr_len);

					if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(newpkt), newpkt_len)){
						fprintf(stderr, "pcap_sendpacket return %d error=%s", res, pcap_geterr(handle));
					}

					free(psdheader);
					free(newpkt);
				}
			}
		}
	}
}
