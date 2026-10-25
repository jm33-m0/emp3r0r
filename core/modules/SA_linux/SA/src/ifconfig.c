#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <errno.h>

#include "beacon_api.h"

int run_ifconfig(void){
    struct ifaddrs *ifap = NULL;
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *ifa2 = NULL;
    int checkcode = 0;
    struct sockaddr_in *sin = NULL;
    struct sockaddr_in *sin_netmask = NULL;
    struct sockaddr_in *sin_broadcast = NULL;
    struct sockaddr_in6 *sin6 = NULL;
    char ip6buf[256*2 + 1];

    checkcode = getifaddrs(&ifap);
    if (checkcode != 0){
        return 0;
    }

    /* Loop through the entries once, with just AF_PACKET/AF_LINK types
     * print the name, then iterate over the rest of the entries ignoring
     * the AF_LINK/AF_PACKET case, and print the addresses we want to handle 
     * and print the unknown types encountered for future reference. */
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        switch(ifa->ifa_addr->sa_family){
#ifdef __APPLE__
            case AF_LINK:
#else
            case AF_PACKET:
#endif
                BeaconPrintf(CALLBACK_OUTPUT, "%s:\n", ifa->ifa_name);
                for (ifa2 = ifap; ifa2; ifa2 = ifa2->ifa_next) {
                    if (strcmp(ifa->ifa_name, ifa2->ifa_name) != 0){
                        continue;
                    }
                    switch(ifa2->ifa_addr->sa_family){
                        case AF_INET:
                            sin = (struct sockaddr_in*)ifa2->ifa_addr;
                            sin_netmask = (struct sockaddr_in*)ifa2->ifa_netmask;
                            sin_broadcast = (struct sockaddr_in*) ifa2->ifa_broadaddr;
                            BeaconPrintf(CALLBACK_OUTPUT, "\tIP Address: %s\n", inet_ntoa(sin->sin_addr));
                            BeaconPrintf(CALLBACK_OUTPUT, "\tNetmask: %s\n", inet_ntoa(sin_netmask->sin_addr));
                            BeaconPrintf(CALLBACK_OUTPUT, "\tBroadcast: %s\n", inet_ntoa(sin_broadcast->sin_addr));
                            break;
                        case AF_INET6:
                            sin6 = (struct sockaddr_in6*)ifa2->ifa_addr;
                            inet_ntop(AF_INET6, &sin6->sin6_addr, ip6buf, sizeof(ip6buf));
                            BeaconPrintf(CALLBACK_OUTPUT, "\tIPv6 Address: %s\n", ip6buf);
                            break;
#ifdef __APPLE__
                        case AF_LINK:
#else
                        case AF_PACKET:
#endif
                            break;
                        default:
                            BeaconPrintf(CALLBACK_OUTPUT, "Unsupported address family: %d\n", ifa->ifa_addr->sa_family);
                            break;
                    }
                }

                break;
            default:
                break;
        }
    }
    if (ifap){
        freeifaddrs(ifap);
    }
    return 0;
}

int go(char* indata, int inlen){
    
    (void)run_ifconfig();
    return 0;
}

#ifdef TEST_IFCONFIG
int main(void){
    (void)run_ifconfig();
    return 0;
}
#endif
