# DOS-extender fixture sources

The programs behind the seven `.BIN` fixtures in `../../fixtures/`, and the
exact commands that turn them into those fixtures. Every source here is
**MIT** (`SPDX-License-Identifier: MIT`); the images they produce are test
data under the licenses in `../../` — see `../../README.md`.

## Programs

| Source | Why it exists | Fixture(s) |
|---|---|---|
| `hello.c` | Deliberately boring: one `fputs`, one `strlen`, so the images stay small and their tables stay readable. Linked five times. | `dos4gw-unbound.BIN`, `dos4gw-bound.BIN`, `dos32a-unbound.BIN`, `dos32a-bound.BIN`, `os2-lx.BIN` |
| `many.c` | 1056768 bytes (= 258 pages) of **initialised** data, pushing the image to 260 module pages. Only page numbers above 255 can show that the 3-byte LE page number is big-endian. | `many-pages.BIN` |
| `big.c` | 262144 bytes of **uninitialised** statics plus one initialised page: an object whose `vsize` (0x51070) is 323568 bytes bigger than the pages on disk, in a 9556-byte file. | `big-bss.BIN` |

`hello.c` is written in C89-ish style (a loop instead of `strnlen`, explicit
`unsigned int`) so it compiles identically for all three link targets.

## Building

```sh
WATCOM=/opt/watcom sh build.sh
```

`build.sh` resolves its own directory, so it can be run from anywhere. It
compiles into `build/`, copies the results to `../../fixtures/` under the
descriptive `.BIN` names, and rewrites `MANIFEST.txt` with the toolchain
version plus size and sha256 of each file. Verified toolchain: **Open Watcom
"Version 2.0 beta Oct 19 2026"** (Linux host, `binl64`). Rebuilds reproduce the
committed sha256 values byte for byte.

The environment variables matter and must be assigned one per `export`:

```sh
export WATCOM=/opt/watcom
export PATH="$WATCOM/binl64:$PATH"
export INCLUDE="$WATCOM/h"
export LIBS="$WATCOM/lib386"
```

Writing `export WATCOM=… PATH="$WATCOM/binl64:$PATH"` on one line yields
`PATH=/binl64:…` (the old `$WATCOM` is still empty when `$PATH` is expanded)
and shows up as `wcc386: command not found`.

The commands, per fixture:

```sh
wcc386 -bt=dos4g  -zq -ox -fo=hello_dos4g.obj  hello.c
wcc386 -bt=dos32a -zq -ox -fo=hello_dos32a.obj hello.c
wcc386 -bt=os2    -zq -ox -fo=hello_os2.obj    hello.c
wcc386 -bt=dos4g  -zq -ox -fo=many_dos4g.obj   many.c
wcc386 -bt=dos4g  -zq -ox -fo=big_dos4g.obj    big.c

wlink option quiet system dos4g  file hello_dos4g.obj  name d4gunbnd.exe
wlink option quiet system dos4g  option stub="$WATCOM/binw/dos4gw.exe" file hello_dos4g.obj name d4gbound.exe
wlink option quiet system dos32a file hello_dos32a.obj name d3aunbnd.exe
wlink option quiet system dos32a option stub="$WATCOM/binw/dos32a.exe" file hello_dos32a.obj name d3abound.exe
wlink option quiet system os2v2  file hello_os2.obj    name os2lx.exe
wlink option quiet system dos4g  file many_dos4g.obj   name manypge.exe
wlink option quiet system dos4g  file big_dos4g.obj    name bigbss.exe
```

## Things that are easy to get wrong here

- **`option stub=<extender>` is what makes an image bound.** Without it the
  image carries a small loader stub that searches for the extender
  (`DOS4GPATH` / `DOS4GW` for DOS/4G, `DOS32A` for DOS/32A). With it, `wlink`
  prepends the extender and adds the prefix size to `data_pages` (0x80) —
  nothing else in the LE header changes.
- **`name=` sets the module name inside the LE header**, not just the output
  file name, and it has to be DOS-8.3. That is why the fixtures report
  `D4GUNBND.EXE` and friends while the files are called `*.BIN`.
- **`FORMat OS2 …` together with `SYStem os2v2` fails** with
  `Error! E3057: executable format has been established`; `system os2v2`
  already selects LX on its own.
- **`option pagesize=` does not exist** (`E3033: directive error`), so this
  toolchain cannot produce a page size other than 4096.
- **`wlink system dos32a` warns** `W1093: cannot open dos32a.exe` because
  `lib386` has no `dos32a/` subdirectory; the link still succeeds and the
  image is fine (its own 0x90-byte stub).
- **`-ox` matters for reproducibility.** The committed fixtures were built
  with `-zq -ox`; changing the optimization level changes page counts and
  therefore the sha256.
- Nothing here was ever *executed*: this machine has no DOS/DPMI host (`wine`
  returns exit status 5 without running). The fixtures are parse-only.

## Shapes this toolchain cannot produce (yet)

Recorded so nobody re-derives them: exports/imports beyond the single
`DOSCALLS` module in the LX image (`wlink` gave no working DEF path;
`__Export` links nothing), page types 1/2/3 (iterated, invalid, zero-filled),
any page size other than 4096, and non-resident names. `wbind` (the Open
Watcom Win386 bind utility) is the unexplored candidate for W3/W4 content.
