/*
 * SPDX-FileCopyrightText: 2026 Johannes Leupolz
 * SPDX-License-Identifier: MIT
 * See testdata/fixtures/LICENSE.
 *
 * Minimal OS/2 1.x Presentation Manager program that pops up a single
 * message box and exits. Built as a 16-bit "New Executable" (NE) targeting
 * the OS/2 1.x PM runtime, so it exercises the OS/2 half of the NE format
 * that BluJewel's parser needs to tolerate (as opposed to the Windows 3.1
 * half, which is the project's primary focus).
 *
 * Notable NE-header differences vs. a Windows 3.x NE binary that a parser
 * should watch for, all deliberately left as-is here rather than "fixed":
 *   - e_target_os byte in the NE header is 1 (OS/2) rather than 2 (Windows)
 *   - imports come from OS2.DLL / DOSCALLS.DLL / PMWIN.DLL etc. instead of
 *     KERNEL/USER/GDI
 *   - entry point conventions and the resident/non-resident name tables are
 *     otherwise structurally identical to the Win 3.1 case, since both
 *     dialects share the same NE container format
 *
 * Built with Microsoft C/C++ 5.1 against the OS/2 1.03 SDK Presentation
 * Manager libraries (16-bit). See the MSG_OS2A provenance note in
 * testdata/fixtures/README.md.
 * 
 * Main difference to MSG_OS2B is that the flags MB_MOVEABLE | MB_INFORMATION
 * are not known in the OS/2 PM SDK 1.3.
 */

#define INCL_WIN
#include <os2.h>

HAB hab;
HMQ hmq;

int main( void )
{
    hab = WinInitialize( 0 );
    if( hab == 0 ) {
        return( 1 );
    }

    hmq = WinCreateMsgQueue( hab, 0 );
    if( hmq == 0 ) {
        WinTerminate( hab );
        return( 1 );
    }

    WinMessageBox( HWND_DESKTOP,
                   HWND_DESKTOP,
                   "Hello from BluJewel!\n\n"
                   "This NE executable was built for OS/2 1.x Presentation "
                   "Manager as a parser test fixture.",
                   "BluJewel NE Sample (OS/2)",
                   0,
                   MB_OK);

    WinDestroyMsgQueue( hmq );
    WinTerminate( hab );

    return( 0 );
}
