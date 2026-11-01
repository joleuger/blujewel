@echo off
rem ============================================================
rem  Build script for the DOS32A LE samples (Open Watcom)
rem  Requirement: WATCOM environment set (run owsetenv.bat first)
rem  The output is UNBOUND: it needs DOS32A.EXE at run time. See
rem  README.txt - the extender is not in this repository.
rem ============================================================
if "%WATCOM%"=="" goto nowatcom

rem --- C version ---
wcc386 -bt=dos -s -os -zq -fo=hallo.obj hallo.c
if errorlevel 1 goto fehler
wlink system dos32a option stub=stub32a.exe option quiet file hallo.obj name hallo.exe
if errorlevel 1 goto fehler

rem --- assembler version (no C runtime, very small) ---
wasm -zq -fo=hallasm.obj hallo.asm
if errorlevel 1 goto fehler
wlink system dos32a option stub=stub32a.exe option quiet file hallasm.obj name hallasm.exe
if errorlevel 1 goto fehler

rem --- install as fixtures --------------------------------------------
rem The name= argument is load-bearing: its DOS-8.3 stem is what lands in the
rem LE header's module-name field (HALLO.EXE / HALLASM.EXE). The descriptive
rem file name with the repository's .BIN suffix is applied by this copy step,
rem exactly as ../dos4gw/build.sh does it.
copy /y hallo.exe   ..\..\fixtures\hallo.BIN
if errorlevel 1 goto fehler
copy /y hallasm.exe ..\..\fixtures\hallasm.BIN
if errorlevel 1 goto fehler

echo.
echo Done: hallo.exe and hallasm.exe here, hallo.BIN and hallasm.BIN in
echo       ..\..\fixtures\  (LE, loader stub, needs DOS32A.EXE to run)
goto ende

:nowatcom
echo WATCOM environment not set. Run owsetenv.bat first.
goto ende
:fehler
echo Build failed.
:ende
