#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>

int GetMacAddress(const char *interface, unsigned char* mac_addr);