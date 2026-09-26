#include "bofdefs.h"
#include "base.c"


void UdpEnumInfo(char* serverIp)
{
	int port = 1434;
	int timeout = 1000;
    WSADATA wsaData;
    SOCKET udpSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    char sendBuffer[1] = { 0x02 };
    char recvBuffer[1024];
    int recvBufferLen = sizeof(recvBuffer);
    int serverAddrLen = sizeof(serverAddr);
    char* response = NULL;

    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        internal_printf("WSAStartup failed with error: %d\n", WS2_32$WSAGetLastError());
        return;
    }

	//
    // Create a UDP socket
	//
    udpSocket = WS2_32$socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSocket == INVALID_SOCKET) {
        internal_printf("Socket creation failed with error: %d\n", WS2_32$WSAGetLastError());
        goto END;
    }

    if (WS2_32$setsockopt(udpSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        internal_printf("Failed to set receive timeout: %d\n", WS2_32$WSAGetLastError());
        goto END;
    }

    if (WS2_32$setsockopt(udpSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        internal_printf("Failed to set send timeout: %d\n", WS2_32$WSAGetLastError());
        goto END;
    }

    intZeroMemory(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = WS2_32$htons(port);
    if (WS2_32$inet_pton(AF_INET, serverIp, &serverAddr.sin_addr) != 1) {
        internal_printf("Invalid server IP address.\n");
        goto END;
    }

	//
    // Send the magic 0x02 byte
	//
    if (WS2_32$sendto(udpSocket, sendBuffer, sizeof(sendBuffer), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        internal_printf("Failed to send request: %d\n", WS2_32$WSAGetLastError());
        goto END;
    }

    int bytesReceived = WS2_32$recvfrom(udpSocket, recvBuffer, recvBufferLen - 1, 0, (struct sockaddr*)&serverAddr, &serverAddrLen);
    if (bytesReceived == SOCKET_ERROR) {
        internal_printf("Failed to receive response: %d\n", WS2_32$WSAGetLastError());
        goto END;
    }

    recvBuffer[bytesReceived] = '\0';

    response = intAlloc(bytesReceived + 1);
    if (response == NULL) {
        internal_printf("Memory allocation failed.\n");
        goto END;
    }

	//
	// Convert the response to a printable string
	//
    int responseIndex = 0;
	for (int i = 0; i < bytesReceived; ++i) {
		if (recvBuffer[i] >= 32 && recvBuffer[i] <= 126) {
			response[responseIndex++] = recvBuffer[i];
		}
	}
    response[responseIndex] = '\0';

	if (response != NULL) {
        internal_printf("SQL Server Connection Info:\n\n%s\n", response);
        intFree(response);
    } else {
        internal_printf("Failed to retrieve SQL Server info.\n");
    }

END:
	// Cleanup
	if (udpSocket != INVALID_SOCKET) {
    	WS2_32$closesocket(udpSocket);
	}
    WS2_32$WSACleanup();
}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	char* ip;

	//
	// parse beacon args 
	//
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	
	ip = BeaconDataExtract(&parser, NULL);

	ip = *ip == 0 ? NULL : ip;
	
	if(!bofstart())
	{
		return;
	}

	if (ip == NULL)
	{
		internal_printf("[!] IP argument is required\n");
		printoutput(TRUE);
		return;
	}
	
	UdpEnumInfo(ip);

	printoutput(TRUE);
};

#else

int main()
{
	UdpEnumInfo("10.5.10.22");
}

#endif
