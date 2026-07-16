/*
2  * PROJECT:     ReactOS netstat utility
3  * LICENSE:     GPL - See COPYING in the top level directory
4  * FILE:        base/applications/network/netstat/netstat.c
5  * PURPOSE:     display IP stack statistics
6  * COPYRIGHT:   Copyright 2005 Ged Murphy <gedmurphy@gmail.com>
7  */

#include <windows.h>
#include <winbase.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"

#define HOSTNAMELEN 256
#define PORTNAMELEN 256
#define ADDRESSLEN  512
#ifndef AF_INET6
#define AF_INET6 23
#endif

CHAR TcpState[][32] = {
    "???",
    "CLOSED",
    "LISTENING",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "DELETE_TCB"
};

char* GetIpHostName(BOOL Local, UINT IpAddr, CHAR Name[], int NameLen)
{
    UINT nIpAddr = WS2_32$htonl(IpAddr);
        MSVCRT$sprintf(Name, "%u.%u.%u.%u",
        (nIpAddr >> 24) & 0xFF,
        (nIpAddr >> 16) & 0xFF,
        (nIpAddr >> 8)  & 0xFF,
        (nIpAddr)       & 0xFF);
    return Name;
}

char* GetIp6HostName(UCHAR addr[16], CHAR Name[], int NameLen)
{
    MSVCRT$sprintf(Name, "%x:%x:%x:%x:%x:%x:%x:%x",
        WS2_32$htons(*(USHORT*)&addr[0]),
        WS2_32$htons(*(USHORT*)&addr[2]),
        WS2_32$htons(*(USHORT*)&addr[4]),
        WS2_32$htons(*(USHORT*)&addr[6]),
        WS2_32$htons(*(USHORT*)&addr[8]),
        WS2_32$htons(*(USHORT*)&addr[10]),
        WS2_32$htons(*(USHORT*)&addr[12]),
        WS2_32$htons(*(USHORT*)&addr[14]));
    return Name;
}

char* GetPortName(UINT Port, PCSTR Proto, CHAR Name[], INT NameLen)
{
    MSVCRT$sprintf(Name, "%u", WS2_32$htons((WORD)Port));
    return Name;
}

void GetNameByPID(DWORD processId, char* procName, DWORD *procNameLength)
{
    BOOL state;
    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

    if (NULL != hProcess)
    {
        state = KERNEL32$QueryFullProcessImageNameA(hProcess, 0, (LPSTR)procName, procNameLength);
        KERNEL32$CloseHandle(hProcess);

        if (state)
        {
            procName[*procNameLength] = ' ';
            (*procNameLength)++;
            procName[*procNameLength] = '\0';
            return;
        }

        procName[0] = '\0';
        *procNameLength = 0;
    }
    else
    {
        procName[0] = '\0';
        *procNameLength = 0;
    }
}


void ResolvePID(DWORD pid, char* name, DWORD* size)
{
    int i;
    for (i = 0; i < MAX_PATH; i++)
        name[i] = '\x00';
    *size = MAX_PATH;
    GetNameByPID(pid, name, size);
}


void ShowTcpTable()
{
    PMIB_TCPTABLE_OWNER_PID ptTable;
    DWORD error, dwSize;
    DWORD i;
    CHAR HostIp[HOSTNAMELEN], HostPort[PORTNAMELEN];
    CHAR RemoteIp[HOSTNAMELEN], RemotePort[PORTNAMELEN];
    CHAR Host[ADDRESSLEN], Remote[ADDRESSLEN];

    dwSize = 0;
    error = IPHLPAPI$GetExtendedTcpTable(
        NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (error != ERROR_INSUFFICIENT_BUFFER)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to snapshot TCP4 endpoints.\n");
        return;
    }

    ptTable = (PMIB_TCPTABLE_OWNER_PID)intAlloc(dwSize);
    error = IPHLPAPI$GetExtendedTcpTable(
        ptTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (error)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get TCP4 endpoints table.\n");
        intFree(ptTable);
        return;
    }

    for (i = 0; i < ptTable->dwNumEntries; i++)
    {
        MIB_TCPROW_OWNER_PID row = ptTable->table[i];
        char name[MAX_PATH];
        DWORD size;

        GetIpHostName(TRUE, row.dwLocalAddr, HostIp, HOSTNAMELEN);
        GetPortName(row.dwLocalPort, "tcp", HostPort, PORTNAMELEN);
        MSVCRT$sprintf(Host, "%s:%s", HostIp, HostPort);

        if (row.dwState == MIB_TCP_STATE_LISTEN)
        {
            MSVCRT$sprintf(Remote, "*:*");
        }
        else
        {
            GetIpHostName(FALSE, row.dwRemoteAddr, RemoteIp, HOSTNAMELEN);
            GetPortName(row.dwRemotePort, "tcp", RemotePort, PORTNAMELEN);
            MSVCRT$sprintf(Remote, "%s:%s", RemoteIp, RemotePort);
        }

        ResolvePID(row.dwOwningPid, name, &size);
        internal_printf("  %-6s %-48s %-48s %-13s %s(%lu)\n",
            "TCP", Host, Remote, TcpState[row.dwState], name, row.dwOwningPid);
    }

    intFree(ptTable);
}

void ShowTcp6Table()
{
    PMIB_TCP6TABLE_OWNER_PID ptTable;
    DWORD error, dwSize;
    DWORD i;
    CHAR HostIp[HOSTNAMELEN], HostPort[PORTNAMELEN];
    CHAR RemoteIp[HOSTNAMELEN], RemotePort[PORTNAMELEN];
    CHAR Host[ADDRESSLEN], Remote[ADDRESSLEN];

    dwSize = 0;
    error = IPHLPAPI$GetExtendedTcpTable(
        NULL, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (error != ERROR_INSUFFICIENT_BUFFER)
    {
        return;
    }

    ptTable = (PMIB_TCP6TABLE_OWNER_PID)intAlloc(dwSize);
    error = IPHLPAPI$GetExtendedTcpTable(
        ptTable, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (error)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get TCP6 endpoints table.\n");
        intFree(ptTable);
        return;
    }

    for (i = 0; i < ptTable->dwNumEntries; i++)
    {
        MIB_TCP6ROW_OWNER_PID row = ptTable->table[i];
        char name[MAX_PATH];
        DWORD size;

        GetIp6HostName(row.ucLocalAddr, HostIp, HOSTNAMELEN);
        GetPortName(row.dwLocalPort, "tcp", HostPort, PORTNAMELEN);
        MSVCRT$sprintf(Host, "[%s]:%s", HostIp, HostPort);

        if (row.dwState == MIB_TCP_STATE_LISTEN)
        {
            MSVCRT$sprintf(Remote, "*:*");
        }
        else
        {
            GetIp6HostName(row.ucRemoteAddr, RemoteIp, HOSTNAMELEN);
            GetPortName(row.dwRemotePort, "tcp", RemotePort, PORTNAMELEN);
            MSVCRT$sprintf(Remote, "[%s]:%s", RemoteIp, RemotePort);
        }

        ResolvePID(row.dwOwningPid, name, &size);
        internal_printf("  %-6s %-48s %-48s %-13s %s(%lu)\n",
            "TCP6", Host, Remote, TcpState[row.dwState], name, row.dwOwningPid);
    }

    intFree(ptTable);
}

void ShowUdpTable()
{
    PMIB_UDPTABLE_OWNER_PID uTable;
    DWORD error, dwSize;
    DWORD i;
    CHAR HostIp[HOSTNAMELEN], HostPort[PORTNAMELEN];
    CHAR Host[ADDRESSLEN];

    dwSize = 0;
    error = IPHLPAPI$GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (error != ERROR_INSUFFICIENT_BUFFER)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to snapshot UDP4 endpoints.\n");
        return;
    }

    uTable = (PMIB_UDPTABLE_OWNER_PID)intAlloc(dwSize);
    error = IPHLPAPI$GetExtendedUdpTable(uTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (error)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get UDP4 endpoints table.\n");
        intFree(uTable);
        return;
    }

    for (i = 0; i < uTable->dwNumEntries; i++)
    {
        MIB_UDPROW_OWNER_PID row = uTable->table[i];
        char name[MAX_PATH];
        DWORD size;

        GetIpHostName(TRUE, row.dwLocalAddr, HostIp, HOSTNAMELEN);
        GetPortName(row.dwLocalPort, "udp", HostPort, PORTNAMELEN);
        MSVCRT$sprintf(Host, "%s:%s", HostIp, HostPort);

        ResolvePID(row.dwOwningPid, name, &size);
        internal_printf("  %-6s %-48s %-48s %-13s %s(%lu)\n",
            "UDP", Host, "*:*", "", name, row.dwOwningPid);
    }

    intFree(uTable);
}

void ShowUdp6Table()
{
    PMIB_UDP6TABLE_OWNER_PID uTable;
    DWORD error, dwSize;
    DWORD i;
    CHAR HostIp[HOSTNAMELEN], HostPort[PORTNAMELEN];
    CHAR Host[ADDRESSLEN];

    dwSize = 0;
    error = IPHLPAPI$GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (error != ERROR_INSUFFICIENT_BUFFER)
    {
        /* No IPv6 UDP entries or API failure - silently skip */
        return;
    }

    uTable = (PMIB_UDP6TABLE_OWNER_PID)intAlloc(dwSize);
    error = IPHLPAPI$GetExtendedUdpTable(uTable, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (error)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get UDP6 endpoints table.\n");
        intFree(uTable);
        return;
    }

    for (i = 0; i < uTable->dwNumEntries; i++)
    {
        MIB_UDP6ROW_OWNER_PID row = uTable->table[i];
        char name[MAX_PATH];
        DWORD size;

        GetIp6HostName(row.ucLocalAddr, HostIp, HOSTNAMELEN);
        GetPortName(row.dwLocalPort, "udp", HostPort, PORTNAMELEN);
        MSVCRT$sprintf(Host, "[%s]:%s", HostIp, HostPort);

        ResolvePID(row.dwOwningPid, name, &size);
        internal_printf("  %-6s %-48s %-48s %-13s %s(%lu)\n",
            "UDP6", Host, "*:*", "", name, row.dwOwningPid);
    }

    intFree(uTable);
}


void Netstat(int choices)
{
    internal_printf("Active Connections\n\n");
    internal_printf("  %-6s %-48s %-48s %-13s %s\n",
        "Proto", "Local Address", "Foreign Address", "State", "Process (PID)");
    internal_printf("  %-6s %-48s %-48s %-13s %s\n",
        "-----", "-------------", "---------------", "-----", "-------------");
    if(choices & 0x0001){
        ShowTcpTable();
    } 
    if(choices & 0x0010){
        ShowTcp6Table();
    }
    if(choices & 0x0100){
        ShowUdpTable();
    } 
    if(choices & 0x1000){
        ShowUdp6Table();
    }
}


#ifdef BOF

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart())
        return;
    datap parser = {0};
	int user_choices = 0;
	BeaconDataParse(&parser, Buffer, Length);

	user_choices = BeaconDataInt(&parser);
    Netstat(user_choices);
    printoutput(TRUE);
}

#else

int main()
{
    Netstat();
    return 0;
}

#endif