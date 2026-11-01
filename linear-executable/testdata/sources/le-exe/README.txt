DOS32A Hello World (LE format)
==============================

hallo.exe     C version   (Open Watcom, with the C runtime)
hallasm.exe   assembler version (no C runtime, very small)
stub32a.exe   DOS32A loader stub (prepended to the LE image by the link step)

The two .exe files here are byte-identical to the fixtures the test suite
opens (../../fixtures/hallo.BIN, ../../fixtures/hallasm.BIN); they are kept
only so this folder stays a self-contained build. build.bat links them under
these DOS-8.3 names and copies the results to the .BIN names in ../../fixtures,
because the link name is what lands in the image's module-name field
(HALLO.EXE / HALLASM.EXE) while the repository names its fixtures .BIN.

Both images are UNBOUND: the 492-byte stub searches for DOS32A.EXE in the
current directory, in PATH, or through the DOS32A environment variable. The
extender itself is deliberately not in this repository, so to run an image you
must supply DOS32A.EXE yourself (Open Watcom ships one as binw/dos32a.exe) next
to the program or on PATH. Both images were run in DOSBox and print
"Hallo Welt vom DOS32A!" / "Hallo Welt (Assembler)!".

Rebuild:  build.bat   (Open Watcom; run owsetenv.bat first). `system dos32a`
would bind the whole extender as the stub per the linker's own definition, so
the script passes `option stub=stub32a.exe` to link the small stub instead.

Layout of the executables: MZ header + stub, and at offset 0x3C the pointer to
the "LE" signature (0x210 in both files). With the tools SB.EXE and SC.EXE from
the DOS32A package the extender can be bound in afterwards, or the image
compressed.

Note: file names must be DOS-8.3 (hallasm, not hallo_asm).
