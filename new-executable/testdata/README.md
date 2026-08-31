# NE-Format Test Fixtures

Real 16-bit "New Executable" (NE) binaries used as test fixtures for the
`ne` crate. All files in this directory are committed to the repository and
MIT-licensed (see `LICENSE`), but they are **excluded from the published
`.crate` package** — the tests that need them run only from a repository
checkout, behind the `fixtures` cargo feature.

A second, non-distributable set of fixtures (Windows 3.x system DLLs and
programs) lives in `testdata/external/` (gitignored, not committed); see
`TESTS.md`, section "External test fixtures", for that list with SHA-256
sums.

## The files

Compiled with MS C 5.1 (Microsoft Windows 98):
- BMPWIN.bin
- DUALBTN.bin
- EMPTYWIN.bin
- HDRFLGS1.bin
- HDRFLGS2.bin
- HDRFLGS3.bin
- HDRFLGS4.bin
- HDRFLGS5.bin 

Compiled with MS C 5.1 (Microsoft OS/2 1.3):
- CMD_ARGS.bin
- MSG_OS2B.bin

Cross-Compiled with OpenWatcom 2.0 under Linux:
- MSG_OS2A.bin
- MSG_W31.bin

| File | Description |
|---|---|
| `DUALBTN.bin`  | Two buttons: one shows a message box, the other closes the app. The **golden fixture** — every value in `example.md` and in the `test_dualbtn_*` test suite was extracted from its bytes. |
| `BMPWIN.bin`   | Draws a zigzag background. |
| `EMPTYWIN.bin` | A minimal "empty window" program. |
| `HDRFLGS1.bin` | Baseline: moveable segments, ordinary relocation table. |
| `HDRFLGS2.bin` | Fixed (non-moveable) segment flags. |
| `HDRFLGS3.bin` | Shared-segment flag variants. |
| `HDRFLGS4.bin` | Large heap/stack/segment values. |
| `HDRFLGS5.bin` | Discardable-segment flag. |
| `MSG_OS2B.bin` | Minimal OS/2 1.x Presentation Manager message-box program. Source: `testdata/sources/MSG_OS2B/msg_os2b.c`. |
| `MSG_W31.bin`  | Minimal Windows 3.x message-box program. Source: `testdata/sources/MSG_W31/msg_w31.c`. |
| `CMD_ARGS.bin` | 13-line K&R-style program printing its argv, compiled for OS/2 1.3 in protected mode with Microsoft C/C++ 5.1. Source: `testdata/sources/CMD_ARGS/cmd_args.c`. Parser stress case: the first file with flags `0x0002` (MULTIPLEDATA without SINGLEDATA), zero heap/stack init, and 512-byte sectors. |
| `MSG_OS2A.bin` | ~40-line Presentation Manager message-box program, compiled for OS/2 1.x PM with Microsoft C/C++ 5.1 against the OS/2 1.03 SDK libraries. Source: `testdata/sources/MSG_OS2A/msg_os2a.c`. The corpus's first PM binary from a Microsoft toolchain: imports `PMWIN` + `DOSCALLS`. |

## Checksums

SHA-256 of the current fixture files (re-verify after any regeneration):

```
eb051220dd51d50587214b2850d80fd3292360a4cd2abd74c9691676864e0326  BMPWIN.bin
c69016acbc3b92d3250fa90719a1d0ff4e3f8f458a04b6af8f7473b1bcf42e60  CMD_ARGS.bin
06f04da3a17c7bab065465ca614a9da69668e36550d8bb64de404e6bf4abdafb  DUALBTN.bin
5eb6f2905a8d47b3a38096f43fad1f6528e1785eb8f2ab5fe3fcd276cf97a11c  EMPTYWIN.bin
aa57641bc89f021d0d0571b7282e4012fce506c4f282838276939d71af854d8d  HDRFLGS1.bin
6f31586dbf3a511515f5c3ece705b21260dfce848ae772a1d439d0f141c0ecf7  HDRFLGS2.bin
699b9f4730259d6f3ed02ebafb4df5d58176f7f5dfb4f3f8c4791bb917b00551  HDRFLGS3.bin
d50a9eaa7b7206a7c8aa41fe9713da4b8105fbdc93cc5276c8240f7017e7e1f6  HDRFLGS4.bin
f3c51e465888fe040d8f386f9d85329d316f29ef498c97cfab86084888dc0ef9  HDRFLGS5.bin
c24b8e5cf603f2e4c4b544519ceae93d6f4ef072f6672489aa268117b1ac06e5  MSG_OS2A.bin
ebde5476f893fdbcd82fc632fd3860031136a1c7239a5f3504c3409ff6f95c8c  MSG_OS2B.bin
3293aa8f10e779ca0f15013118541cc700dad3bdf865250c9b7d9ab902993fcc  MSG_W31.bin
```
