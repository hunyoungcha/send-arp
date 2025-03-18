#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

int GetMacAddress(const char *interface, unsigned char* mac_addr);

struct EthArpPacket* SendArpPacket(const char *senderMac, const char *senderIP, const char* targetIP);

struct in_addr IPStringToByte(const char* ip);

int MakeEthHeader(struct ethernet_header* ether, unsigned char* SenderMac);