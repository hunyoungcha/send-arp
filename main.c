#include "packet_struct.h"
#include "main.h"

int main(int argc, char* argv[]){
    //argv[~] 코드 수정 필요
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

    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        eth.srcMac[0],eth.srcMac[1],eth.srcMac[2],eth.srcMac[3],eth.srcMac[4],eth.srcMac[5]);
    
    
    // struct arp_header arp;
    // MakeArpHeader(&arp);
    
        // struct EthArpPacket* arpPacket = SendArpPacket(mac, senderip, targetip);
    pcap_sendpacket(pcap, (const u_char*)&eth, sizeof(struct ethernet_header));
	// pcap_close(pcap);
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

struct EthArpPacket* SendArpPacket(const char *senderMac, const char *senderIP, const char* targetIP) {
    struct EthArpPacket packet;
    
    /*Ethernet*/ //enum으로 변경하기 (define이라도)
    //DstMac
    uint8_t TargetMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(packet.eth.dstMac, TargetMac, sizeof(packet.eth.dstMac));
    //SrcMac
    memcpy(packet.eth.srcMac, senderMac, sizeof(packet.eth.srcMac));
    //Type
    packet.eth.type=htons(0x0806);

    /*ARP*/ //enum으로 변경하기 (define이라도)
    packet.arp.HdType = htons(1);
    packet.arp.ProtocolType = htons(0x0800);
    packet.arp.HdAddressLength = htons(6);
    packet.arp.ProtocolAddressLength = htons(4);
    packet.arp.Opcode = htons(1);
    
    //Sender Mac
    memcpy(packet.eth.srcMac, senderMac, sizeof(packet.eth.srcMac));
    
    //Sender IP
    struct in_addr S_in_addr = IPStringToByte(senderIP);
    memcpy(packet.arp.SenderIP, &S_in_addr, 4);

    //Target Mac
    uint8_t ArpTargetMac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(packet.arp.TargetMac, ArpTargetMac, sizeof(packet.arp.TargetMac));    

    //Target IP
    struct in_addr T_in_addr = IPStringToByte(targetIP);
    memcpy(packet.arp.TargetIP, &T_in_addr, 4);

    return &packet;
}

struct in_addr IPStringToByte(const char* ip ){
    struct in_addr addr;
    if(inet_pton(AF_INET, ip, &addr) == 1){
        return addr;
    }
}

int MakeEthHeader(struct ethernet_header* ether, unsigned char* SenderMac){
    uint8_t TargetMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(ether->dstMac, TargetMac, sizeof(ether->dstMac)); 
    
    memcpy(ether->srcMac, SenderMac, sizeof(ether->srcMac));

    ether->type = htons(0x0806);
}

// int MakeArpHeader() {

// }