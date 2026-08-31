/****************************************************************************
 * SPDX-FileCopyrightText: 2026 Johannes Leupolz
 * SPDX-License-Identifier: MIT
 * See testdata/fixtures/LICENSE.
 * 
 * Generates an .exe with controllable NE header attributes 
 * via a .DEF file for parser validation.
 ****************************************************************************/
#include <windows.h>

LRESULT FAR PASCAL __export WndProc(HWND, UINT, WPARAM, LPARAM);

BOOL FAR PASCAL __export InitApp(HANDLE hInstance) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "HdrFlags";
    return RegisterClass(&wc);
}

LRESULT FAR PASCAL __export WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_KEYDOWN && wp == VK_ESCAPE) {
        PostQuitMessage(0);
        return 0;
    }
    if (msg == WM_CLOSE) {
        DestroyWindow(hwnd);
        return 0;
    }
    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

BOOL FAR PASCAL __export InitInstance(HANDLE hInstance, int nCmdShow) {
    HWND hwnd = CreateWindow("HdrFlags", "HeaderFlags Test", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 300, 200,
                             NULL, NULL, hInstance, NULL);
    if (!hwnd) return FALSE;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    return TRUE;
}

int PASCAL WinMain(HANDLE hInstance, HANDLE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    MSG msg;
    if (!hPrevInstance) InitApp(hInstance);
    if (!InitInstance(hInstance, nCmdShow)) return FALSE;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
}