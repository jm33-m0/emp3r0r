#include "functions.c"

UINT my_htonl(UINT hostlong) {
    static const int endianness_test = 1;
    if (*((char*)&endianness_test) == 1)
        return ((hostlong >> 24) & 0xFF) | ((hostlong >> 8) & 0xFF00) | ((hostlong << 8) & 0xFF0000) | ((hostlong << 24) & 0xFF000000);
    else
        return hostlong;
}

UINT my_ntohl(UINT netlong) {
    return my_htonl(netlong);
}

void sendBytes(char* server, char* port, PBYTE content, int contentSize, PBYTE* response, int* size) {
    WSADATA wsaData;
    int iResult = WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        PRINT_OUT("[x] Failed to start WSA Winsocks: %d\n", iResult);
        return;
    }

    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* result = NULL;
    iResult = WS2_32$getaddrinfo(server, port, &hints, &result);
    if (iResult != 0) {
        PRINT_OUT("[x] Failed to get KDC IP info: %d\n", iResult);
        WS2_32$WSACleanup();
        return;
    }

    struct addrinfo* ptr = NULL;
    SOCKET ConnectSocket = INVALID_SOCKET;
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        ConnectSocket = WS2_32$socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            PRINT_OUT("[x] Failed to connect to the KDC: %ld\n", WS2_32$WSAGetLastError());
            WS2_32$WSACleanup();
            return;
        }

        iResult = WS2_32$connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            WS2_32$closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    WS2_32$freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        PRINT_OUT("[x] Failed to connect to server!\n");
        WS2_32$WSACleanup();
        return;
    }

    int networkContentSize = my_htonl(contentSize);
    char test[4] = "";
    MemCpy(test, &networkContentSize, sizeof(int));
    iResult = WS2_32$send(ConnectSocket, test, 4, 0);
    iResult = WS2_32$send(ConnectSocket, content, contentSize, 0);
    if (iResult == SOCKET_ERROR) {
        PRINT_OUT("[x] Failed to write data: %d\n", WS2_32$WSAGetLastError());
        WS2_32$closesocket(ConnectSocket);
        WS2_32$WSACleanup();
        return;
    }

    char sizeBuff[4] = "";
    iResult = WS2_32$recv(ConnectSocket, sizeBuff, 4, 0);
    if (iResult < 0) {
        PRINT_OUT("[x] Failed to receive data size from KDC: %d\n", WS2_32$WSAGetLastError());
        return;
    }

    MemCpy(size, sizeBuff, sizeof(int));
    *size = my_ntohl(*size) & 0x7fffffff;

    *response = MemAlloc(*size);
    if (!*response) {
        PRINT_OUT("[x] Failed to allocate KDC response buffer\n");
        return;
    }
    PBYTE buff = *response;
    int bufferSize = 0;
    do {
        iResult = WS2_32$recv(ConnectSocket, buff, *size, 0);
        if (iResult < 0) {
            PRINT_OUT("[x] Failed to receive data size from KDC: %d\n", WS2_32$WSAGetLastError());
            return;
        }
        buff += iResult;
        bufferSize += iResult;
    } while (bufferSize != *size);

    WS2_32$closesocket(ConnectSocket);
    WS2_32$WSACleanup();
}
