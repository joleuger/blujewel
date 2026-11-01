/*
 * TESTAPP.C - kleine Win32-Konsolenanwendung, die HELLO.VXD dynamisch laedt,
 * den Zaehler abfragt und das VxD durch Schliessen des Handles wieder entlaedt.
 *
 * Bauen:  cl testapp.c        (Visual C++ unter Windows 9x)
 * Start:  testapp             (HELLO.VXD muss im aktuellen Verzeichnis liegen)
 */
#include <windows.h>
#include <stdio.h>

#define HELLO_IOCTL_GET_COUNTER 1

int main(void)
{
    char  full[MAX_PATH];
    char  name[MAX_PATH + 8];
    char *filepart;
    HANDLE h;
    DWORD  value = 0, returned = 0;

    if (!GetFullPathName("HELLO.VXD", sizeof(full), full, &filepart)) {
        printf("GetFullPathName fehlgeschlagen\n");
        return 1;
    }
    wsprintf(name, "\\\\.\\%s", full);

    /* FILE_FLAG_DELETE_ON_CLOSE: VxD wird beim CloseHandle entladen
       (die Datei selbst bleibt erhalten) */
    h = CreateFile(name, 0, 0, NULL, 0, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("VxD konnte nicht geladen werden (Fehler %lu)\n", GetLastError());
        return 1;
    }

    if (DeviceIoControl(h, HELLO_IOCTL_GET_COUNTER, NULL, 0,
                        &value, sizeof(value), &returned, NULL))
        printf("Zaehler vom VxD: %lu\n", value);
    else
        printf("DeviceIoControl fehlgeschlagen (Fehler %lu)\n", GetLastError());

    CloseHandle(h);
    return 0;
}
