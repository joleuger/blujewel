/*
 * SPDX-FileCopyrightText: 2026 Johannes Leupolz
 * SPDX-License-Identifier: MIT
 * See testdata/fixtures/LICENSE.
 *
 * Simple library compiled with visual studio c++ 1.52
 */

#include <windows.h>        
                        
void FAR PASCAL simplib_method(char char_value, int int_value, char *ptr)
{                    
    char buf[2];
    buf[0]=char_value;
    buf[1]='\0';
    OutputDebugString(buf);
}                  