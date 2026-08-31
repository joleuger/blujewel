/*
 * SPDX-FileCopyrightText: 2026 Johannes Leupolz
 * SPDX-License-Identifier: MIT
 * See testdata/fixtures/LICENSE.
 *
 * Deliberately mirrors msg_os2b.c so the two compiled NE binaries can be
 * diffed structurally: same intent (pop a message box, exit), same
 * toolchain (OpenWatcom 16-bit compiler/linker), same NE container format,
 * but different target-OS byte, different DLL imports (KERNEL/USER/GDI
 * instead of OS2/PMWIN), and the classic WinMain entry convention instead
 * of OS/2's PM main().
 *
 * Build (from an OpenWatcom 2.0 environment, WATCOM/PATH set up):
 *   wcc -bt=windows -mm -s msg_w31.c
 *   wlink SYSTEM windows NAME hello_win31 FILE msg_w31.o OPTION STACK=8k
 */

#define STRICT
#include <windows.h>

int PASCAL WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPSTR lpCmdLine, int nCmdShow )
{
    MessageBox( NULL,
                "Hello from BluJewel!\n\n"
                "This NE executable was built for Windows 3.1 as a parser "
                "test fixture.",
                "BluJewel NE Sample (Windows 3.1)",
                MB_OK | MB_ICONINFORMATION );

    return( 0 );
}
