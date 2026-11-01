/* impexp.c — the one program behind `fixtures/os2-impexp.BIN`.
 *
 * SPDX-License-Identifier: MIT
 *
 * Deliberately tiny, and built for one purpose: to be the smallest OS/2 LX
 * image in the corpus that has **imports and exports**, so that the name-
 * table, entry-table and import-table layouts are pinned by a committed,
 * reproducible file instead of only by a non-distributable system DLL.
 *
 * What the two calls and the two exports buy:
 *
 *   - two imported APIs from two different modules (DOSCALLS, PMWIN), bound
 *     **by name** through the linker's `IMPort` directive, so the import
 *     procedure table is non-empty;
 *   - the imported symbol that the object references first is *not* the first
 *     entry of the procedure table: the format puts a mandatory null entry
 *     there, so a walk that reads a zero length byte as "end of table"
 *     reports no imports at all;
 *   - two exports at ordinals 1 and 7 — the gap between them is what makes
 *     the linker emit an entry-table bundle of the "unused" type, and it is
 *     also why the ordinal-7 name ends up in the **non-resident** name table
 *     with a non-zero ordinal word.
 *
 * The declarations below are loose (a handle is an unsigned long, a RECT is a
 * void pointer): nothing here is executed, and pulling in the OS/2 headers
 * would add nothing but size. wcc386 -bt=os2 decorates every one of these
 * names with a trailing underscore, and `build.sh` passes that decorated
 * spelling to the linker directives.
 */

extern unsigned long DosLoadModule(char *, unsigned long *, char *);
extern unsigned long WinQueryWindowPos(unsigned long, void *);

int ImpExpSecond(void);
int ImpExpProbe(int);

int ImpExpProbe(int a)
{
    char   name[52];
    unsigned long mod;
    unsigned long rect[4];

    /* Both imports are reachable from here, so both modules and both
     * procedure names have to exist in the loader section. */
    if (DosLoadModule(name, &mod, "PMWIN") != 0) {
        return a;
    }
    return a + (int)WinQueryWindowPos(mod, rect);
}

int ImpExpSecond(void)
{
    return 42;
}
