# Committed test fixtures

Every file in this directory is an executable image or a VxD archive that a
test opens. Seventeen of them: sixteen built for this project (most from the
sources in `../sources/`; `hellovxd.BIN`, `hello2vxd.BIN` and the four archives
were built by the maintainer with the Microsoft DDK and `devlib`) plus one
third-party image, `vmdisp9xvxd.BIN`, whose attribution lives in
`../license-vmdisp9x`. They are the anchor of the test suite (cargo feature
`fixtures`) and the subject of every verified claim in the implementation
Nothing here is uploaded to the published crate:
`Cargo.toml` ships `src/`, `tests/` and `README.md` only, so the binaries
stay in the repository but never enter a package.

## Manifest

| File | Bytes | sha256 | Format | Built from |
|---|---|---|---|---|
| `hallasm.BIN` | 4938 | `2aa72ce0308c7f2f53ff44417ad0e33cea352f907529071ed2764cf089f39298` | LE | `../sources/le-exe/hallo.asm` |
| `hallo.BIN` | 11090 | `92417030adb42376b0e59d01c864fe5d30ee6abcad68c89eb845c8b3abd1fe2e` | LE | `../sources/le-exe/hallo.c` |
| `dos4gw-unbound.BIN` | 11130 | `f1451a8b4b1d93603d224d09722a78568fb6124e16512aa0f8b2fe22531e785f` | LE | `../sources/dos4gw/hello.c` |
| `dos4gw-bound.BIN` | 73050 | `602aa2a7fbfb0df627c3d023d6c5191ab24f60f6122620edf0ab413a7fd0c89a` | LE | same, `option stub=` |
| `dos32a-unbound.BIN` | 10730 | `747b593698a4bfbda3de8260eeb339d9dda6b639e9970270b376de8868a2f809` | LE | same, `-bt=dos32a` |
| `dos32a-bound.BIN` | 38122 | `890000dfd8cfaef4f05c52a98962760fe6463850867756506434b37fac050b68` | LE | same, `option stub=` |
| `os2-lx.BIN` | 7369 | `afe6501ce6ca382af8de86fd3c9944a8378bf19c27dad249fe29f9d0282c727e` | LX | same, `system os2v2` |
| `os2-impexp.BIN` | 598 | `612152060732d2ef89d5849e2570a24ca593a15c8f5fdbb215ab469afb1318a3` | LX | `../sources/os2imp/impexp.c` (`system os2v2` + `EXPort`/`IMPort`) |
| `many-pages.BIN` | 1064380 | `a0cfa0c340876b3ccad0ebf1d9abd88def48cf2fbb0b3f2276b5fb13401bac39` | LE | `../sources/dos4gw/many.c` |
| `big-bss.BIN` | 9556 | `1052bfc9baf328317e3fe50fc911d9d512cef44fc8acc8f81b3e9dec874a60d5` | LE | `../sources/dos4gw/big.c` |
| `hellovxd.BIN` | 4321 | `a53140e0ddd9a356624fbf74ab36007ff3bb0c4d9f89fa19048b6337a0414dcb` | LE (Win386 VxD) | `../sources/vxd/` (`ml`, `cl`, `link -vxd`) |
| `hello2vxd.BIN` | 4322 | `3ca1f7d67dc8e7bf31f3f73240a2af26af37c8050fb01d341f781ca74193ac0d` | LE (Win386 VxD) | `../sources/vxd/hello2.*`, same toolchain |
| `singlew3.BIN` | 5841 | `315843389625051118aebce30b9f8c456952540614fa813b721d7e37da252d38` | **W3** archive, 1 member | `../sources/vxd/buildw3w4.bat` (`devlib -a`) |
| `singlew4.BIN` | 4506 | `abca78ae601cf177ea873dc4ba49e10b5f0f5d44e83adbd5ee181bb9f567f464` | **W4** archive, codec `"DS"`, 1 chunk | same, `devlib -a` + `devlib -p` |
| `doublew3.BIN` | 6865 | `f593e8f8d3c2912af9ee58028c367f9791916ef72a956e3ab850c96693cf132d` | **W3** archive, **2 members** | same, `devlib -a hello.vxd hello2.vxd` |
| `doublew4.BIN` | 4585 | `e35181b6c67cfe78473b26f64c782fbfd6ba2274af4d6a8adf84c2f10e8a62a6` | **W4** archive, codec `"DS"`, 1 chunk | same, `devlib -a` + `devlib -p` |
| `vmdisp9xvxd.BIN` | 21123 | `794692793ae24b2407745c09b40a800fb0e3ecab519458821bb21fd4d92ce778` | LE (Win386 VxD) | **third party**: vmdisp9x (MIT), rebuilt by the maintainer — `../license-vmdisp9x` |
