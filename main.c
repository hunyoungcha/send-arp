#include "packet_struct.h"
#include "main.h"

int main(int argc, char* argv[]){
    char* interface = argv[1];
    char* senderip = argv[2];
    char* targetip = argv[3];
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, 0, 0, 0, errbuf);

    const u_char* packet;

    unsigned char SenderMac[6];
    GetMacAddress(interface, SenderMac);

    struct ethernet_header eth;
    MakeEthHeader(&eth, SenderMac);

    struct arp_header arp;
    MakeArpHeader(&arp, senderip, targetip, SenderMac);

    struct EthArpPacket arpPacket;

    pcap_sendpacket(pcap, (const u_char*)&arpPacket, sizeof(struct EthArpPacket));
	pcap_close(pcap);
	return 0;
}

int GetMacAddress(const char *interface, unsigned char* mac_addr) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    
    close(sock);
    return 0;
}

int MakeEthHeader(struct ethernet_header* ether, unsigned char* SenderMac){
    uint8_t TargetMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(ether->dstMac, TargetMac, sizeof(ether->dstMac)); 
    
    memcpy(ether->srcMac, SenderMac, sizeof(ether->srcMac));

    ether->type = htons(0x0806);
}

int MakeArpHeader(struct arp_header* arp, const char* senderIP, const char* targetIP, unsigned char* SenderMac) {
    arp->HdType = htons(1);
    arp->ProtocolType = htons(0x0800);
    arp->HdAddressLength = htons(6);
    arp->ProtocolAddressLength = htons(4);
    arp->Opcode = htons(1);

    memcpy(arp->SenderMac, SenderMac, sizeof(arp->SenderMac));

    struct in_addr SenderInAddr = IPStringToByte(senderIP);
    memcpy(arp->SenderIP, &SenderInAddr, sizeof(arp->SenderIP));

    uint8_t TargetMac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(arp->TargetMac, TargetMac, sizeof(arp->TargetMac));

    struct in_addr TargetInAddr = IPStringToByte(targetIP);
    memcpy(arp->TargetIP, &TargetInAddr, sizeof(arp->TargetIP));

}

struct in_addr IPStringToByte(const char* ip ){
    struct in_addr addr;
    if(inet_pton(AF_INET, ip, &addr) == 1){
        return addr;
    }
}