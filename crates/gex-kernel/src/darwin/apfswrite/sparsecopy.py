#!/usr/bin/env python3
"""Copy a byte range of a sparse file into another file, keeping its holes.

The restore tests' disk files are mostly holes; their container partition
is copied out for fsck_apfs and the device's tools to read. Only the data
regions of SRC's range [SRC_OFF, SRC_OFF + LEN) are read and written
(lseek SEEK_DATA and SEEK_HOLE), each at DST_OFF plus its offset into the
range; DST is created if missing and grown to DST_OFF + LEN, and the rest
of it is left as it was. Prints the number of bytes copied.

usage: sparsecopy.py SRC DST SRC_OFF LEN [DST_OFF]
"""
import argparse
import errno
import os


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('src', help='the sparse file to copy from')
    ap.add_argument('dst', help='the file to copy into (created when missing)')
    ap.add_argument('src_off', type=int, help="the range's offset in SRC, in bytes")
    ap.add_argument('length', type=int, help="the range's length, in bytes")
    ap.add_argument('dst_off', type=int, nargs='?', default=0, help='where the range starts in DST (0)')
    a = ap.parse_args()
    fi = os.open(a.src, os.O_RDONLY)
    fo = os.open(a.dst, os.O_RDWR | os.O_CREAT, 0o644)
    if os.fstat(fo).st_size < a.dst_off + a.length:
        os.ftruncate(fo, a.dst_off + a.length)
    pos, end, n = a.src_off, a.src_off + a.length, 0
    while pos < end:
        try:
            d = os.lseek(fi, pos, os.SEEK_DATA)
        except OSError as e:
            if e.errno == errno.ENXIO:
                break  # no data past pos
            raise
        if d >= end:
            break
        h = min(os.lseek(fi, d, os.SEEK_HOLE), end)
        while d < h:
            b = os.pread(fi, min(h - d, 1 << 24), d)
            os.pwrite(fo, b, d - a.src_off + a.dst_off)
            d += len(b)
            n += len(b)
        pos = h
    print('copied', n)


if __name__ == '__main__':
    main()
