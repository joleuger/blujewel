/*
 * HELLOC2.C - C-Teil des dynamisch ladbaren VxD "HELLO2"
 *
 * Wichtig fuer C in einem VxD:
 *  - Kein C-Runtime (kompiliert mit -Zl), keine Stringliterale, keine
 *    uninitialisierten Globals (_BSS ist im .def als discardable markiert).
 *  - Code und Daten muessen in die gelockten Segmente _LTEXT / _LDATA,
 *    sonst koennte der VMM sie auslagern oder verwerfen.
 *  - Aufrufe von VMM-Services passieren im Assembler-Teil (hello.asm).
 */

typedef unsigned long DWORD;

/* DIOCPARAMETERS, wie in vwin32.h (hier selbst definiert, keine Header noetig) */
typedef struct tagDIOCPARAMS {
    DWORD Internal1;
    DWORD VMHandle;
    DWORD Internal2;
    DWORD dwIoControlCode;
    DWORD lpvInBuffer;
    DWORD cbInBuffer;
    DWORD lpvOutBuffer;
    DWORD cbOutBuffer;
    DWORD lpcbBytesReturned;
    DWORD lpoOverlapped;
    DWORD hDevice;
    DWORD tagProcess;
} DIOCPARAMS;

#define DIOC_OPEN               0UL
#define DIOC_CLOSEHANDLE        ((DWORD)-1L)
#define HELLO_IOCTL_GET_COUNTER 1UL
#define ERROR_NOT_SUPPORTED     50UL

#pragma code_seg("_LTEXT")
#pragma data_seg("_LDATA")

/* bewusst ungleich 0 initialisiert, damit die Variable in _LDATA landet */
static DWORD g_counter = 1000UL;

DWORD __cdecl Hello2Init(void)
{
    g_counter = 1000UL;
    return 0UL;
}

DWORD __cdecl Hello2Exit(void)
{
    return 0UL;
}

DWORD __cdecl Hello2Dioc(DIOCPARAMS *p)
{
    switch (p->dwIoControlCode) {

    case DIOC_OPEN:
    case DIOC_CLOSEHANDLE:
        return 0UL;                         /* ok */

    case HELLO_IOCTL_GET_COUNTER:
        g_counter++;
        if (p->cbOutBuffer >= sizeof(DWORD) && p->lpvOutBuffer != 0UL) {
            *(DWORD *)p->lpvOutBuffer = g_counter;
            if (p->lpcbBytesReturned != 0UL)
                *(DWORD *)p->lpcbBytesReturned = sizeof(DWORD);
            return 0UL;
        }
        return ERROR_NOT_SUPPORTED;

    default:
        return ERROR_NOT_SUPPORTED;
    }
}
