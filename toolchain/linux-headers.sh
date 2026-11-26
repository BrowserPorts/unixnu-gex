#!/bin/sh
# Linux's UAPI headers as the sysroots and gexcc carry them: Debian's
# linux-libc-dev at the version toolchain/pins names (LINUX_HEADERS), through
# toolchain/debian-package.sh.
#
#   toolchain/linux-headers.sh        -> prints the include directory
#
# It holds linux/, asm-generic/ and the other architecture-neutral
# directories, and each architecture's asm/ under its triple
# (x86_64-linux-gnu/asm is x86's, both its i386 and its x86-64 branches).
# Its asm/ directories are links into usr/lib/linux/uapi: copy with -L.
set -eu
HERE=$(dirname "$(realpath "$0")")
# An assignment, so a failure to fetch or unpack stops here (set -e) rather
# than naming the host's own /usr/include.
root=$("$HERE/debian-package.sh" LINUX_HEADERS)
echo "$root/usr/include"
