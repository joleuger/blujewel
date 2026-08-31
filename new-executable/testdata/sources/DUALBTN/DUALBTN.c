/****************************************************************************
 * SPDX-FileCopyrightText: 2026 Johannes Leupolz
 * SPDX-License-Identifier: MIT
 * See testdata/fixtures/LICENSE.
 * 
 * Creates a window with two buttons to test WM_COMMAND routing,
 * child control creation, and import table resolution (MessageBox).
 ****************************************************************************/
#include <windows.h>

/* Forward declaration for the window procedure */
LRESULT FAR PASCAL __export WndProc(HWND, UINT, WPARAM, LPARAM);

HANDLE hInst; /* Global instance handle required by CreateWindow */

BOOL FAR PASCAL __export InitApp(HANDLE hInstance) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "DualBtn";
    return RegisterClass(&wc);
}

BOOL FAR PASCAL __export InitInstance(HANDLE hInstance, int nCmdShow) {
    HWND hwnd;
    hwnd = CreateWindow("DualBtn", "Dual Buttons Test", WS_OVERLAPPEDWINDOW,
                        CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
                        NULL, NULL, hInstance, NULL);
    if (!hwnd) return FALSE;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    return TRUE;
}

LRESULT FAR PASCAL __export WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            HWND hBtnMsg, hBtnClose;
            /* Cast to (WORD) ensures correct 16-bit control ID passing in Win3.1 */
            hBtnMsg  = CreateWindow("BUTTON", "Show Msg",
                                    WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                    40, 40, 110, 25,
                                    hwnd, (HMENU)(WORD)1, hInst, NULL);
            hBtnClose = CreateWindow("BUTTON", "Close",
                                     WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                     40, 80, 110, 25,
                                     hwnd, (HMENU)(WORD)2, hInst, NULL);

            /* Fail gracefully if button creation fails */
            if (!hBtnMsg || !hBtnClose) {
                MessageBox(hwnd, "Failed to create buttons!", "Creation Error", MB_OK | MB_ICONSTOP);
                return -1;
            }
            return 0;
        }
        case WM_COMMAND: {
            int ctrlId = LOWORD(wp);
            if (ctrlId == 1) {
                MessageBox(hwnd, "NE Parser Smoke Test", "Info", MB_OK);
            } else if (ctrlId == 2) {
                DestroyWindow(hwnd);
            }
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
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