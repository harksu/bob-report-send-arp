#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <iostream>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0\n");
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

void send_Arp(pcap_t* handle, Mac source_mac, Ip source_ip, Mac target_mac, Ip target_ip ){
	//기본적으로 스켈레톤 코드에서 작성된 arp 코드를 가져오되, 이번 과제에서는 단순히 하나의 타겟이 아님
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(target_mac);
	packet.eth_.smac_ = Mac(source_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(source_mac);
	packet.arp_.sip_ = htonl(Ip(source_ip));
	packet.arp_.tmac_ = Mac(target_mac);
	packet.arp_.tip_ = htonl(Ip(target_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}





int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];	
	
	Mac myMac = get_my_mac_address(dev);

	std::string macStr = std::string(myMac);
    std::cout << "MAC Address of interface "<< ": " << macStr << std::endl;
	//test
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	

	

	


	pcap_close(handle);
}
