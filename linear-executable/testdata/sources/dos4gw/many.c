/*
 * many.c — the program behind the `many-pages.BIN` fixture.
 *
 * Its only purpose is to make the image larger than 255 data pages, because
 * an LE page-table entry stores the file page number in 3 bytes. With <= 255
 * pages every page number fits in the last byte, so no small fixture can
 * tell a big-endian 24-bit read apart from a little-endian one. 1056768
 * bytes of initialised data is 258 pages, which pushes the image past 260
 * pages and makes entry #257 (`00 01 01`) discriminate the two readings.
 *
 * The array is deliberately *initialised* (not plain BSS): only initialised
 * data occupies pages in the file. The initialiser sets the first byte; the
 * rest of the array is zero-filled by the compiler, which keeps this source
 * small and the fixture compressible.
 *
 * SPDX-License-Identifier: MIT
 */

/* First four bytes of the array, used by main() so the array cannot be
 * optimised away. */
static const unsigned char expect[] = {0xA5u, 0x00u, 0x00u, 0x00u};

#define FILLER_BYTES 1056768u /* 258 * 4096 */

static unsigned char filler[FILLER_BYTES] = {0xA5u};

int main(void)
{
    unsigned int i;
    int ok = 1;

    for (i = 0; i < sizeof(expect); ++i) {
        if (filler[i] != expect[i]) {
            ok = 0;
        }
    }
    /* Touch the last byte too, so the whole array stays live. */
    if (filler[FILLER_BYTES - 1u] != 0u) {
        ok = 0;
    }
    return ok ? 0 : 1;
}
