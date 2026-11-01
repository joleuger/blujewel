/*
 * hello.c — the program behind the bound/unbound extender fixtures.
 *
 * Compiled three ways by build.sh (DOS/4GW, DOS32A, OS/2) and linked into
 * several LE/LX fixtures; see README.md for the exact commands. The program
 * is deliberately boring: it prints one line and returns an exit status, so
 * the produced images stay small and their tables stay readable.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>

static const char message[] = "LE/LX fixture: hello from a DOS extender\n";

int main(void)
{
    size_t len = strlen(message);

    fputs(message, stdout);
    /* A second data-object reference: keeps at least two external fixups in
     * the image even at -0 optimization. */
    if (len == 0u) {
        return 1;
    }
    return (int)(len & 1u);
}
