/*
 * big.c — the program behind the `big-bss.BIN` fixture.
 *
 * It puts a large *uninitialised* object in the data object and a small
 * initialised one next to it. The result is the shape the parser must accept
 * but no small fixture produces: the data object's virtual size is far
 * larger than the number of pages the linker actually wrote for it, so the
 * object image has to be zero-extended (see `object_image`). It is also the
 * cheap way to get `vsize > pages * page_size` without a megabyte-sized
 * fixture — only `tiny`, not `huge`, costs file space.
 *
 * SPDX-License-Identifier: MIT
 */

#define HUGE_BYTES 262144u /* 64 * 4096, uninitialised: no file space */
#define TINY_BYTES 4096u   /* initialised: exactly one page on disk */

static unsigned char huge_area[HUGE_BYTES];

static unsigned char tiny_area[TINY_BYTES] = {
    0x4Cu, 0x47u, 0x76u, 0x73u, /* "LGvs" — a recognizable page marker */
    0x01u, 0x02u, 0x03u, 0x04u
};

int main(void)
{
    unsigned int i;
    int sum = 0;

    for (i = 0; i < TINY_BYTES; i += 512u) {
        sum += (int)tiny_area[i];
    }
    /* A write into the uninitialised area keeps `huge_area` from being
     * discarded; it must not be optimised out or the object shrinks. */
    huge_area[0] = (unsigned char)(sum & 0xFF);
    return huge_area[0] == 0u ? 0 : 1;
}
