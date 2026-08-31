/****************************************************************************
 * SPDX-FileCopyrightText: 2026 Johannes Leupolz
 * SPDX-License-Identifier: MIT
 * See testdata/fixtures/LICENSE.
 * 
 * Creates a window with a background bitmap (simple zigzag pattern).
 ****************************************************************************/
#include <windows.h>

/* Forward declaration for the window procedure */
LRESULT FAR PASCAL __export WndProc(HWND, UINT, WPARAM, LPARAM);

HANDLE hInst; /* Global instance handle required by CreateWindow */
     
/* 01111101 = 0x7F*/
/* 10111011 = 0xBB*/    
/* 11010111 = 0xD7 */
/* 11101111 = 0xEF */
short Zigzag[] = { 0x7F, 0xBB, 0xD7, 0xEF, 0xFF, 0xFF, 0xFF, 0xFF };
HBITMAP hZigzagBitmap;
HBRUSH hZigzagBrush;
HDC    hMemDC;

BOOL FAR PASCAL __export InitApp(HANDLE hInstance) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "BmpWin";
    return RegisterClass(&wc);
}

BOOL FAR PASCAL __export InitInstance(HANDLE hInstance, int nCmdShow) {
    HWND hwnd;              
    
    
    hwnd = CreateWindow("BmpWin", "Bitmap Test", WS_OVERLAPPEDWINDOW,
                        CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
                        NULL, NULL, hInstance, NULL);
    if (!hwnd) return FALSE;
                                 
    hZigzagBitmap = CreateBitmap(8, 8, 1, 1, (LPSTR) Zigzag);
    hZigzagBrush = CreatePatternBrush(hZigzagBitmap);
                                                       
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    return TRUE;
}

LRESULT FAR PASCAL __export WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
	RECT Rect;
	HBRUSH   hOldBrush;
    switch (msg) {
        case WM_CREATE: {
            return 0;
        }
        case WM_COMMAND: {
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        case WM_ERASEBKGND:
            UnrealizeObject(hZigzagBrush);
            hOldBrush = SelectObject(wp, hZigzagBrush);
            GetClientRect(hwnd, &Rect);
            PatBlt(wp, Rect.left, Rect.top,
                   Rect.right-Rect.left, Rect.bottom-Rect.top, PATCOPY);
            SelectObject(wp, hOldBrush);
            return TRUE;
        default:
            break;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

int PASCAL WinMain(HANDLE hInstance, HANDLE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    MSG msg;
    if (!hPrevInstance) {
        hInst = hInstance;          /* CRITICAL: Initialize instance handle */
        InitApp(hInstance);
    }
    if (!InitInstance(hInstance, nCmdShow)) return FALSE;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
}