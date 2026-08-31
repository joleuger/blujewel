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
 * Build (from an OpenWatcom 2.0 environment, WATCOM/PATH set up):
 *   wcl msg_os2b.c -bt=os2 -l=os2_pm -"op stack=8k"
 * or, split into the two underlying steps:
 *   wcc  -bt=os2 -mm -s msg_os2b.c
 *   wlink SYSTEM os2_pm NAME hello_os2 FILE msg_os2b.obj OPTION STACK=8k
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
                   MB_OK | MB_MOVEABLE | MB_INFORMATION );

    WinDestroyMsgQueue( hmq );
    WinTerminate( hab );

    return( 0 );
}
