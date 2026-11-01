@echo off
rem ============================================================
rem  Build-Skript fuer HELLO.VXD
rem  Microsoft C (VC++ 4.x - 6.0) + MASM 6.11d + LINK /VXD aus dem DDK
rem
rem  Aufruf:  build          Retail-Build
rem           build debug    Debug-Build (Trace_Out-Ausgaben aktiv)
rem ============================================================

rem ---------------- HIER ANPASSEN ----------------------------
rem Windows 98 DDK:
set DDKINC=C:\98DDK\inc\win98
set DDKBIN=C:\98DDK\bin\win98
rem Windows 95 DDK (stattdessen einkommentieren):
rem set DDKINC=C:\DDK\inc32
rem set DDKBIN=C:\DDK\bin
rem Visual C++ (cl.exe) - wenn nicht schon im PATH:
rem set VCBIN=C:\MSDEV\BIN
rem -----------------------------------------------------------

if not exist "%DDKINC%\vmm.inc" goto kein_ddk
if not exist "%DDKBIN%\ml.exe"  goto kein_ml

rem DDK-Tools (ml.exe, link.exe mit /VXD) muessen VOR dem VC-link im PATH stehen
set PATH=%DDKBIN%;%VCBIN%;%PATH%

set DEBLEVEL=0
set ADEBUG=
if /i "%1"=="debug" set DEBLEVEL=1
if /i "%1"=="debug" set ADEBUG=-DDEBUG

echo [1/3] Assembler: hello.asm
ml -coff -DBLD_COFF -DIS_32 -DMASM6 -DDEBLEVEL=%DEBLEVEL% %ADEBUG% -W2 -Zd -c -Cx -I"%DDKINC%" -Fohello.obj hello.asm
if errorlevel 1 goto fehler

echo [2/3] C-Compiler: helloc.c
rem -Gs  keine Stack-Probes     -Zl  keine Default-Library im Objekt
rem -Zp1 gepackte Strukturen    -O1  klein optimieren (kein __chkstk, kein CRT)
cl -c -Gs -Zl -Zp1 -O1 -D_X86_ -DWIN32 -DIS_32 -DDEBLEVEL=%DEBLEVEL% %ADEBUG% -Fohelloc.obj helloc.c
if errorlevel 1 goto fehler

echo [3/3] Linker: HELLO.VXD
link -vxd -nodefaultlib -machine:i386 -nologo -map -def:hello.def -out:hello.vxd hello.obj helloc.obj
if errorlevel 1 goto fehler

echo.
echo Fertig: HELLO.VXD
echo Test:   cl testapp.c   und danach   testapp.exe
goto ende

:kein_ddk
echo vmm.inc nicht gefunden in "%DDKINC%". Bitte DDKINC in build.bat anpassen.
goto ende
:kein_ml
echo ml.exe nicht gefunden in "%DDKBIN%". Bitte DDKBIN in build.bat anpassen.
goto ende
:fehler
echo.
echo *** Build fehlgeschlagen ***
:ende
