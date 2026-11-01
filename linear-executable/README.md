# linear-executable

A Rust parser for **LE/LX (Linear Executable)** files — the 32-bit
flat-object/page format used by OS/2 2.x, DOS-extender applications
(DOS32A, DOS4G, PMODE/W, CauseWay) and Windows 9x **VxD device drivers** —
plus the **W3/W4** VxD archive containers.

Cargo package `linear-executable`, import path `linear_executable::`
(`linear_executable::{le, headers, types, w3, w4, bound, disasm}`). It is the
sibling of the **`ne-rs`** NE/16-bit parser (the `ne-rs/` tree that this
directory was scaffolded from): same design philosophy (zero-copy headers, lazy
tables, `no_std` + `alloc`, `clippy::pedantic` at 0 warnings, bounds-checked
everything), different format.
