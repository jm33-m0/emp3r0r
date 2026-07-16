
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#ifdef BOF
#include <ws2ipdef.h>
#else
#include <ws2tcpip.h>
#endif
#include <windows.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"

/* GAA flags - define if not available in mingw headers */
#ifndef GAA_FLAG_INCLUDE_PREFIX
#define GAA_FLAG_INCLUDE_PREFIX          0x0010
#endif
#ifndef GAA_FLAG_INCLUDE_GATEWAYS
#define GAA_FLAG_INCLUDE_GATEWAYS        0x0080
#endif
#ifndef GAA_FLAG_INCLUDE_ALL_INTERFACES
#define GAA_FLAG_INCLUDE_ALL_INTERFACES  0x0100
#endif

#ifndef AF_INET6
#define AF_INET6 23
#endif

#ifndef IF_TYPE_IEEE80211
#define IF_TYPE_IEEE80211 71
#endif

#ifndef IF_TYPE_TUNNEL
#define IF_TYPE_TUNNEL 131
#endif

#ifndef IP_ADAPTER_DHCP_ENABLED
#define IP_ADAPTER_DHCP_ENABLED 0x00000004
#endif

const char* get_adapter_type_string(DWORD ifType)
{
    switch (ifType) {
        case IF_TYPE_ETHERNET_CSMACD:
            return "Ethernet adapter";
        case IF_TYPE_IEEE80211:
            return "Wireless LAN adapter";
        case IF_TYPE_TUNNEL:
            return "Tunnel adapter";
        case IF_TYPE_PPP:
            return "PPP adapter";
        default:
            return "Unknown adapter";
    }
}

const char* get_node_type_string(UINT nodeType)
{
    switch (nodeType) {
        case 1: return "Broadcast";
        case 2: return "Peer-Peer";
        case 4: return "Mixed";
        case 8: return "Hybrid";
        default: return "Unknown";
    }
}

void format_mac_address(BYTE *addr, DWORD addrLen, char *outBuf, int outBufSize)
{
    int pos = 0;
    DWORD i;
    for (i = 0; i < addrLen && pos < outBufSize - 4; i++) {
        if (i == addrLen - 1) {
            pos += MSVCRT$sprintf(outBuf + pos, "%02X", (int)addr[i]);
        } else {
            pos += MSVCRT$sprintf(outBuf + pos, "%02X-", (int)addr[i]);
        }
    }
}

void format_ipv4_address(struct sockaddr *sa, char *outBuf, int outBufSize)
{
    struct sockaddr_in *sa_in = (struct sockaddr_in *)sa;
    BYTE *b = (BYTE *)&sa_in->sin_addr;
    MSVCRT$sprintf(outBuf, "%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
}

void format_ipv6_address(struct sockaddr *sa, char *outBuf, int outBufSize)
{
    /* Use InetNtopW then convert to narrow */
    wchar_t wBuf[64];
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
    LPCWSTR result = WS2_32$InetNtopW(AF_INET6, &sa6->sin6_addr, wBuf, 64);
    if (result) {
        MSVCRT$wcstombs(outBuf, wBuf, outBufSize);
    } else {
        MSVCRT$strcpy(outBuf, "::?");
    }
}

void prefix_length_to_subnet_mask(UINT8 prefixLen, char *outBuf, int outBufSize)
{
    ULONG mask = 0;
    if (prefixLen > 0 && prefixLen <= 32) {
        mask = ~0UL << (32 - prefixLen);
    }
    MSVCRT$sprintf(outBuf, "%d.%d.%d.%d",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF);
}

void format_duid(BYTE *duid, DWORD duidLen, char *outBuf, int outBufSize)
{
    int pos = 0;
    DWORD i;
    for (i = 0; i < duidLen && pos < outBufSize - 4; i++) {
        if (i == duidLen - 1) {
            pos += MSVCRT$sprintf(outBuf + pos, "%02X", (int)duid[i]);
        } else {
            pos += MSVCRT$sprintf(outBuf + pos, "%02X-", (int)duid[i]);
        }
    }
}

void format_unix_time(DWORD unixTime, char *outBuf, int outBufSize)
{
    /* Convert Unix timestamp to local time string matching ipconfig format */
    /* e.g. "Saturday, March 8, 2026 10:15:30 PM" */
    static const char *dayNames[] = {"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
    static const char *monthNames[] = {"January","February","March","April","May","June",
        "July","August","September","October","November","December"};
    ULONGLONG ft64;
    FILETIME ftUtc, ftLocal;
    SYSTEMTIME st;

    if (unixTime == 0) {
        outBuf[0] = '\0';
        return;
    }

    /* Unix epoch to FILETIME: add 11644473600 seconds, convert to 100-ns */
    ft64 = ((ULONGLONG)unixTime + 11644473600ULL) * 10000000ULL;
    ftUtc.dwLowDateTime = (DWORD)(ft64 & 0xFFFFFFFF);
    ftUtc.dwHighDateTime = (DWORD)(ft64 >> 32);

    KERNEL32$FileTimeToLocalFileTime(&ftUtc, &ftLocal);
    KERNEL32$FileTimeToSystemTime(&ftLocal, &st);

    {
        int hour12 = st.wHour % 12;
        const char *ampm = (st.wHour >= 12) ? "PM" : "AM";
        if (hour12 == 0) hour12 = 12;

        MSVCRT$sprintf(outBuf, "%s, %s %d, %d %d:%02d:%02d %s",
            dayNames[st.wDayOfWeek],
            monthNames[st.wMonth - 1],
            st.wDay, st.wYear,
            hour12, st.wMinute, st.wSecond, ampm);
    }
}

void get_dhcp_lease_info(const char *adapterName, DWORD *leaseObtained, DWORD *leaseExpires, char *dhcpServer, int dhcpServerBufSize)
{
    /* Read DHCP lease times and server from registry */
    char *regPath = (char *)intAlloc(512);
    HKEY hKey;
    DWORD size, type;

    *leaseObtained = 0;
    *leaseExpires = 0;
    dhcpServer[0] = '\0';

    if (!regPath) return;

    MSVCRT$sprintf(regPath,
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
        adapterName);

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        type = 0;
        ADVAPI32$RegQueryValueExA(hKey, "LeaseObtainedTime", NULL, &type, (LPBYTE)leaseObtained, &size);

        size = sizeof(DWORD);
        type = 0;
        ADVAPI32$RegQueryValueExA(hKey, "LeaseTerminatesTime", NULL, &type, (LPBYTE)leaseExpires, &size);

        size = (DWORD)dhcpServerBufSize;
        type = 0;
        ADVAPI32$RegQueryValueExA(hKey, "DhcpServer", NULL, &type, (LPBYTE)dhcpServer, &size);

        ADVAPI32$RegCloseKey(hKey);
    }

    intFree(regPath);
}

int get_netbios_option(const char *adapterName)
{
    /* Read NetBIOS over TCP/IP setting from registry */
    char *regPath = (char *)intAlloc(512);
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    DWORD type = 0;
    int result = 0; /* default = enabled */

    if (!regPath) return 0;

    MSVCRT$sprintf(regPath,
        "SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_%s",
        adapterName);

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(hKey, "NetbiosOptions", NULL, &type, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            result = (int)value;
        }
        ADVAPI32$RegCloseKey(hKey);
    }

    intFree(regPath);
    return result; /* 0=default(enabled), 1=enabled, 2=disabled */
}

void print_global_section(PFIXED_INFO pFixedInfo)
{
    internal_printf("\nWindows IP Configuration\n\n");
    internal_printf("   Host Name . . . . . . . . . . . . : %s\n", pFixedInfo->HostName);
    internal_printf("   Primary Dns Suffix  . . . . . . . : %s\n", pFixedInfo->DomainName);
    internal_printf("   Node Type . . . . . . . . . . . . : %s\n", get_node_type_string(pFixedInfo->NodeType));
    internal_printf("   IP Routing Enabled. . . . . . . . : %s\n", pFixedInfo->EnableRouting ? "Yes" : "No");
    internal_printf("   WINS Proxy Enabled. . . . . . . . : %s\n", pFixedInfo->EnableProxy ? "Yes" : "No");

    /* DNS Suffix Search List from registry */
    {
        HKEY hKey;
        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD size = 0;
            DWORD type = 0;
            /* First try SearchList (comma-separated) */
            if (ADVAPI32$RegQueryValueExA(hKey, "SearchList", NULL, &type, NULL, &size) == ERROR_SUCCESS && size > 1) {
                char *searchList = (char *)intAlloc(size + 1);
                if (searchList) {
                    if (ADVAPI32$RegQueryValueExA(hKey, "SearchList", NULL, &type, (LPBYTE)searchList, &size) == ERROR_SUCCESS && searchList[0]) {
                        /* Parse comma-separated list */
                        int first = 1;
                        char *ctx = NULL;
                        char *token = MSVCRT$strtok_s(searchList, ",", &ctx);
                        while (token) {
                            /* Skip leading spaces */
                            while (*token == ' ') token++;
                            if (*token) {
                                if (first) {
                                    internal_printf("   DNS Suffix Search List. . . . . . : %s\n", token);
                                    first = 0;
                                } else {
                                    internal_printf("                                       %s\n", token);
                                }
                            }
                            token = MSVCRT$strtok_s(NULL, ",", &ctx);
                        }
                    }
                    intFree(searchList);
                }
            } else if (pFixedInfo->DomainName[0]) {
                /* Fall back to DomainName if no SearchList */
                internal_printf("   DNS Suffix Search List. . . . . . : %s\n", pFixedInfo->DomainName);
            }
            ADVAPI32$RegCloseKey(hKey);
        } else if (pFixedInfo->DomainName[0]) {
            internal_printf("   DNS Suffix Search List. . . . . . : %s\n", pFixedInfo->DomainName);
        }
    }
}

void print_adapter_section(PIP_ADAPTER_ADDRESSES pAddr)
{
    char addrBuf[80];
    char maskBuf[20];
    char macBuf[24];
    char *utf8Str = NULL;
    int hasDhcpv6Info = 0;

    /* Skip loopback */
    if (pAddr->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
        return;

    /* Adapter header: "\nType FriendlyName:\n\n" */
    utf8Str = Utf16ToUtf8(pAddr->FriendlyName);
    internal_printf("\n%s %s:\n\n", get_adapter_type_string(pAddr->IfType), utf8Str ? utf8Str : "");
    if (utf8Str) { intFree(utf8Str); utf8Str = NULL; }

    /* Media State - only show if not up */
    if (pAddr->OperStatus != IfOperStatusUp) {
        internal_printf("   Media State . . . . . . . . . . . : Media disconnected\n");
    }

    /* Connection-specific DNS Suffix */
    utf8Str = Utf16ToUtf8(pAddr->DnsSuffix);
    internal_printf("   Connection-specific DNS Suffix  . : %s\n", utf8Str ? utf8Str : "");
    if (utf8Str) { intFree(utf8Str); utf8Str = NULL; }

    /* Description */
    utf8Str = Utf16ToUtf8(pAddr->Description);
    internal_printf("   Description . . . . . . . . . . . : %s\n", utf8Str ? utf8Str : "");
    if (utf8Str) { intFree(utf8Str); utf8Str = NULL; }

    /* Physical Address */
    if (pAddr->PhysicalAddressLength > 0) {
        format_mac_address(pAddr->PhysicalAddress, pAddr->PhysicalAddressLength, macBuf, sizeof(macBuf));
        internal_printf("   Physical Address. . . . . . . . . : %s\n", macBuf);
    }

    /* DHCP Enabled */
    internal_printf("   DHCP Enabled. . . . . . . . . . . : %s\n",
        (pAddr->Flags & IP_ADAPTER_DHCP_ENABLED) ? "Yes" : "No");

    /* Autoconfiguration Enabled */
    internal_printf("   Autoconfiguration Enabled . . . . : Yes\n");

    /* If adapter is disconnected, stop here */
    if (pAddr->OperStatus != IfOperStatusUp) {
        return;
    }

    /* Walk unicast addresses - IPv6 first, then IPv4 (matching ipconfig order) */
    {
        PIP_ADAPTER_UNICAST_ADDRESS pUni;

        /* First pass: IPv6 addresses */
        for (pUni = pAddr->FirstUnicastAddress; pUni; pUni = pUni->Next) {
            if (pUni->Address.lpSockaddr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)pUni->Address.lpSockaddr;
                format_ipv6_address(pUni->Address.lpSockaddr, addrBuf, sizeof(addrBuf));

                /* Check if link-local (fe80::) */
                BYTE *ipv6bytes = (BYTE *)&sa6->sin6_addr;
                if (ipv6bytes[0] == 0xfe && ipv6bytes[1] == 0x80) {
                    internal_printf("   Link-local IPv6 Address . . . . . : %s%%%lu(Preferred) \n",
                        addrBuf, (unsigned long)sa6->sin6_scope_id);
                } else {
                    internal_printf("   IPv6 Address. . . . . . . . . . . : %s(Preferred) \n", addrBuf);
                }
            }
        }

        /* Second pass: IPv4 addresses */
        for (pUni = pAddr->FirstUnicastAddress; pUni; pUni = pUni->Next) {
            if (pUni->Address.lpSockaddr->sa_family == AF_INET) {
                format_ipv4_address(pUni->Address.lpSockaddr, addrBuf, sizeof(addrBuf));
                internal_printf("   IPv4 Address. . . . . . . . . . . : %s(Preferred) \n", addrBuf);

                /* Subnet Mask from prefix length */
                prefix_length_to_subnet_mask(pUni->OnLinkPrefixLength, maskBuf, sizeof(maskBuf));
                internal_printf("   Subnet Mask . . . . . . . . . . . : %s\n", maskBuf);
            }
        }
    }

    /* Lease Obtained / Lease Expires (only for DHCP-enabled adapters with IPv4) */
    if (pAddr->Flags & IP_ADAPTER_DHCP_ENABLED) {
        DWORD leaseObtained = 0, leaseExpires = 0;
        char dhcpServerStr[64];
        char timeBuf[128];
        get_dhcp_lease_info(pAddr->AdapterName, &leaseObtained, &leaseExpires, dhcpServerStr, sizeof(dhcpServerStr));

        if (leaseObtained) {
            format_unix_time(leaseObtained, timeBuf, sizeof(timeBuf));
            internal_printf("   Lease Obtained. . . . . . . . . . : %s\n", timeBuf);
        }
        if (leaseExpires) {
            format_unix_time(leaseExpires, timeBuf, sizeof(timeBuf));
            internal_printf("   Lease Expires . . . . . . . . . . : %s\n", timeBuf);
        }
    }

    /* Default Gateway */
    {
        PIP_ADAPTER_GATEWAY_ADDRESS_LH pGw = pAddr->FirstGatewayAddress;
        if (pGw) {
            if (pGw->Address.lpSockaddr->sa_family == AF_INET) {
                format_ipv4_address(pGw->Address.lpSockaddr, addrBuf, sizeof(addrBuf));
            } else if (pGw->Address.lpSockaddr->sa_family == AF_INET6) {
                format_ipv6_address(pGw->Address.lpSockaddr, addrBuf, sizeof(addrBuf));
            } else {
                addrBuf[0] = '\0';
            }
            internal_printf("   Default Gateway . . . . . . . . . : %s\n", addrBuf);
            pGw = pGw->Next;
            while (pGw) {
                if (pGw->Address.lpSockaddr->sa_family == AF_INET) {
                    format_ipv4_address(pGw->Address.lpSockaddr, addrBuf, sizeof(addrBuf));
                } else if (pGw->Address.lpSockaddr->sa_family == AF_INET6) {
                    format_ipv6_address(pGw->Address.lpSockaddr, addrBuf, sizeof(addrBuf));
                }
                internal_printf("                                       %s\n", addrBuf);
                pGw = pGw->Next;
            }
        } else {
            internal_printf("   Default Gateway . . . . . . . . . : \n");
        }
    }

    /* DHCP Server (after gateway, only for DHCP-enabled) */
    if (pAddr->Flags & IP_ADAPTER_DHCP_ENABLED) {
        /* Try Dhcpv4Server from adapter structure first */
        if (pAddr->Dhcpv4Server.iSockaddrLength > 0 && pAddr->Dhcpv4Server.lpSockaddr &&
            pAddr->Dhcpv4Server.lpSockaddr->sa_family == AF_INET) {
            format_ipv4_address(pAddr->Dhcpv4Server.lpSockaddr, addrBuf, sizeof(addrBuf));
            /* Only print if not 0.0.0.0 or 255.255.255.255 */
            if (MSVCRT$strcmp(addrBuf, "0.0.0.0") != 0 && MSVCRT$strcmp(addrBuf, "255.255.255.255") != 0) {
                internal_printf("   DHCP Server . . . . . . . . . . . : %s\n", addrBuf);
            }
        } else {
            /* Fallback: read from registry */
            char dhcpSrv[64];
            DWORD dummy1 = 0, dummy2 = 0;
            get_dhcp_lease_info(pAddr->AdapterName, &dummy1, &dummy2, dhcpSrv, sizeof(dhcpSrv));
            if (dhcpSrv[0] && MSVCRT$strcmp(dhcpSrv, "255.255.255.255") != 0) {
                internal_printf("   DHCP Server . . . . . . . . . . . : %s\n", dhcpSrv);
            }
        }
    }

    /* DHCPv6 IAID and Client DUID - only show if adapter has IPv6 unicast addresses */
    {
        PIP_ADAPTER_UNICAST_ADDRESS pUni;
        for (pUni = pAddr->FirstUnicastAddress; pUni; pUni = pUni->Next) {
            if (pUni->Address.lpSockaddr->sa_family == AF_INET6) {
                hasDhcpv6Info = 1;
                break;
            }
        }
    }
    if (hasDhcpv6Info) {
        internal_printf("   DHCPv6 IAID . . . . . . . . . . . : %lu\n",
            (unsigned long)pAddr->Dhcpv6Iaid);

        if (pAddr->Dhcpv6ClientDuidLength > 0) {
            char *duidBuf = (char *)intAlloc(pAddr->Dhcpv6ClientDuidLength * 4);
            if (duidBuf) {
                format_duid(pAddr->Dhcpv6ClientDuid, pAddr->Dhcpv6ClientDuidLength, duidBuf, pAddr->Dhcpv6ClientDuidLength * 4);
                internal_printf("   DHCPv6 Client DUID. . . . . . . . : %s\n", duidBuf);
                intFree(duidBuf);
            }
        }
    }

    /* DNS Servers */
    {
        PIP_ADAPTER_DNS_SERVER_ADDRESS pDns = pAddr->FirstDnsServerAddress;
        int first = 1;
        while (pDns) {
            addrBuf[0] = '\0';
            if (pDns->Address.lpSockaddr->sa_family == AF_INET) {
                format_ipv4_address(pDns->Address.lpSockaddr, addrBuf, sizeof(addrBuf));
            } else if (pDns->Address.lpSockaddr->sa_family == AF_INET6) {
                format_ipv6_address(pDns->Address.lpSockaddr, addrBuf, sizeof(addrBuf));
            }
            if (first) {
                internal_printf("   DNS Servers . . . . . . . . . . . : %s\n", addrBuf);
                first = 0;
            } else {
                internal_printf("                                       %s\n", addrBuf);
            }
            pDns = pDns->Next;
        }
    }

    /* NetBIOS over Tcpip */
    {
        int nbOpt = get_netbios_option(pAddr->AdapterName);
        internal_printf("   NetBIOS over Tcpip. . . . . . . . : %s\n",
            (nbOpt == 2) ? "Disabled" : "Enabled");
    }

    /* Connection-specific DNS Suffix Search List */
    {
        PIP_ADAPTER_DNS_SUFFIX pSuffix = pAddr->FirstDnsSuffix;
        int first = 1;
        while (pSuffix) {
            if (pSuffix->String[0]) {
                utf8Str = Utf16ToUtf8(pSuffix->String);
                if (utf8Str) {
                    if (first) {
                        internal_printf("   Connection-specific DNS Suffix Search List :\n");
                        first = 0;
                    }
                    internal_printf("                                       %s\n", utf8Str);
                    intFree(utf8Str);
                    utf8Str = NULL;
                }
            }
            pSuffix = pSuffix->Next;
        }
    }
}

void getIPInfo(void)
{
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurr = NULL;
    PFIXED_INFO pFixedInfo = NULL;
    ULONG addrBufLen = 0;
    ULONG netBufLen = 0;
    DWORD ret;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;

    /* Get adapter addresses - two-call pattern */
    ret = IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &addrBufLen);
    if (ret != ERROR_BUFFER_OVERFLOW) {
        BeaconPrintf(CALLBACK_ERROR, "GetAdaptersAddresses failed: %lu", ret);
        goto END;
    }
    pAddresses = (PIP_ADAPTER_ADDRESSES)intAlloc(addrBufLen);
    if (!pAddresses) {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed for adapter addresses");
        goto END;
    }
    ret = IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &addrBufLen);
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "GetAdaptersAddresses failed: %lu", ret);
        goto END;
    }

    /* Get network params - two-call pattern */
    if (IPHLPAPI$GetNetworkParams(NULL, &netBufLen) == ERROR_BUFFER_OVERFLOW) {
        pFixedInfo = (PFIXED_INFO)intAlloc(netBufLen);
        if (!pFixedInfo) {
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed for network params");
            goto END;
        }
        if (IPHLPAPI$GetNetworkParams(pFixedInfo, &netBufLen) != NO_ERROR) {
            BeaconPrintf(CALLBACK_ERROR, "GetNetworkParams failed");
            goto END;
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "GetNetworkParams failed to get buffer size");
        goto END;
    }

    /* Print global section */
    print_global_section(pFixedInfo);

    /* Print per-adapter sections */
    for (pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
        print_adapter_section(pCurr);
    }

END:
    if (pAddresses) {
        intFree(pAddresses);
    }
    if (pFixedInfo) {
        intFree(pFixedInfo);
    }
}

#ifdef BOF

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    if (!bofstart()) {
        return;
    }
    getIPInfo();
    printoutput(TRUE);
};

#else
int main()
{
    getIPInfo();
}

#endif
