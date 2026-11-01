HELLO.VXD - dynamisch ladbarer VxD (LE-Format) fuer Windows 95/98/ME
====================================================================

Dateien
  hello.asm    DDB, Control-Procedure, Spruenge in den C-Code (MASM)
  helloc.c     C-Teil: Zaehler und DeviceIoControl-Handler
  hello.def    Segment-Klassen und Export von HELLO_DDB fuer den VxD-Linker
  build.bat    Build mit ML (MASM 6.11d), CL (Microsoft C) und LINK /VXD
  testapp.c    Win32-Testprogramm: laedt das VxD, fragt den Zaehler ab

Voraussetzungen
  - Windows 95 DDK oder Windows 98 DDK (ml.exe, vmm.inc, link.exe mit /VXD)
  - Microsoft Visual C++ 4.x bis 6.0 (cl.exe). Neuere Compiler (GS-Cookie,
    __security_check_cookie) sind fuer VxDs ungeeignet.

Bauen
  1. In build.bat DDKINC und DDKBIN auf die DDK-Installation setzen.
  2. build         (Retail)    oder    build debug   (mit Trace_Out)
  3. Ergebnis: HELLO.VXD (LE-Image mit MZ-Stub)

Testen (Windows 9x)
  cl testapp.c
  testapp
  -> "Zaehler vom VxD: 1001"
  Das VxD wird per CreateFile("\\.\<voller Pfad>\HELLO.VXD") dynamisch geladen
  und beim CloseHandle wieder entladen. Debug-Meldungen ("HELLO.VXD: geladen")
  erscheinen bei Debug-Build im Debugger (WDEB386, SoftICE, DebugView-Ersatz).

Hinweise
  - Dieses Projekt wurde NICHT mit der Microsoft-Toolchain gebaut oder auf
    einem echten Windows 9x getestet; die Pfade der DDK-Installation und
    kleinere Makro-Details (vmm.inc je nach DDK-Version) koennen Anpassungen
    brauchen.
  - Die Segmentpragmas in helloc.c (_LTEXT/_LDATA) sind noetig, damit C-Code
    und -Daten gelockt im Speicher bleiben. Keine Stringliterale, keine
    uninitialisierten Globals und keine CRT-Funktionen im C-Teil verwenden.
  - Wer statischen Ladevorgang (system.ini / VxD=) braucht, entfernt "DYNAMIC"
    in hello.def und behandelt statt Sys_Dynamic_Device_Init die Nachricht
    Device_Init (hello.asm).
