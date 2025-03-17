#include "packet_struct.h"
#include "main.h"



int main(int argc, char* argv[]){  
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(argv[1], 0, 0, 0, errbuf);

    const u_char* packet;
    int packet_size = sizeof(packet);

    int res = pcap_sendpacket(pcap, packet, packet_size);
	
    unsigned char mac[6];
    GetMacAddress("eth0", mac);
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
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