# Import/export fixture source

The single program behind `../../fixtures/os2-impexp.BIN`, and the exact
commands that turn it into that fixture. The source is **MIT**
(`SPDX-License-Identifier: MIT`); the image it produces is test data under
`../../license-openwatcom` — see `../../README.md`. No extender and no DLL is
linked in, so `license-dos32a` and `license-dos4gw` do not apply here.

## Why this directory exists

Every other fixture in the corpus is a program: it has a `main`, it imports the
C runtime or nothing, and its loader tables are correspondingly empty. This one
exists only to *have tables*:

| Shape | Fixture bytes | What it pins |
|---|---|---|
| a name-table entry with an ordinal word | `0D "ImpExpSecond_" 0100` `0C "ImpExpProbe_" 0700` `00` (the whole non-resident table) | `[LEN][STRING][ORDINAL DW]` + a `LEN`-0 terminator; two names with **non-zero** ordinals — the shape neither `hellovxd.BIN` (one name, ordinal 0) nor `vmdisp9xvxd.BIN` (one name, ordinal 1) can produce |
| an import procedure table with a null first entry | `00 0E "DosLoadModule_" 12 "WinQueryWindowPos_"` | the mandatory leading null entry; a walk that stops at the first zero length byte reports **no** imports in a file that has two |
| import module records with no ordinal | `08 "DOSCALLS" 05 "PMWIN"` = 15 bytes = `import_procedures − import_modules` | `[LEN][STRING]` only, table length from the two pointers |
| an ordinal gap in the export table | `05 00` between the two ENTRY32 bundles | an "unused" bundle: five ordinals, no object word, no entry data — only `EntryBundle::count` keeps the five visible |
| the fixup sentinel | page table `0 0E 0E`, record table @0x133 | `fixup_record_table + sentinel == import_modules` |

It is 598 bytes, so all of that is readable in one hex dump.

## Building

```sh
./build.sh            # WATCOM=/opt/watcom by default
```

The script compiles `impexp.c`, links it, copies the result to
`../../fixtures/os2-impexp.BIN`, and rewrites `MANIFEST.txt` with the toolchain
version, size and sha256. The build is reproducible: two runs in a row produce
the same sha256 (`61215206…18a3`).

Two things about the invocation are load-bearing and easy to get wrong:

* **`wcc386 -bt=os2` decorates every C symbol with a trailing underscore**
  (`ImpExpProbe` becomes `ImpExpProbe_`). The linker directives must use the
  decorated spelling, which is why the fixture's exported names end in `_`.
* **`-s` (no stack check) plus no library at all.** The image links against
  nothing: the two API references are resolved by the `IMPort` directive, and
  that is exactly what makes the import procedure table carry *names*. Link
  against `os2386.lib` instead and the linker binds the same APIs by
  **ordinal**, the procedure table comes out empty, and the fixture loses its
  purpose.

And three things the toolchain will not do:

* `system os2v2` + `format …` → `E3057: executable format has been established`
  (`system os2v2` already selected the format).
* `format os2 dll` alone → the 16-bit segmented DLL writer, which answers a
  32-bit object with `E2053: cannot reach a DLL with a relative relocation`.
  So this corpus cannot produce an image with module flag 0x8000 (DLL).
* `IMPort name MODULE.OS2` (with the module *extension*) → the linker writes
  the extension where the procedure name belongs: the procedure table came out
  as `00 03 "OS2"`. Omit the extension.

## Files

| File | What it is |
|---|---|
| `impexp.c` | two imported OS/2 API calls, two exported functions |
| `build.sh` | the commands above, run from anywhere |
| `MANIFEST.txt` | generated: toolchain version, size, sha256 |
| `build/` | generated; gitignored |
