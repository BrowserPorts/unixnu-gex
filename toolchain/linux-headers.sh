#!/bin/sh
# Linux's UAPI headers as the sysroots and gexcc carry them: Debian's
# linux-libc-dev at the version toolchain/pins names, unpacked (its data, no
# install) once into CACHE. The same headers on any host, where a copy of
# the build machine's /usr/include was whatever it had installed.
#
#   toolchain/linux-headers.sh        -> prints the include directory
#
# It holds linux/, asm-generic/ and the other architecture-neutral
# directories, and each architecture's asm/ under its triple
# (x86_64-linux-gnu/asm is x86's, both its i386 and its x86-64 branches).
# Its asm/ directories are links into usr/lib/linux/uapi: copy with -L.
set -eu
HERE=$(dirname "$(realpath "$0")")
eval "$(sed -n 's/^\(LINUX_HEADERS_[A-Z0-9_]*\) *:= *\(.*\)$/\1=\2/p' "$HERE/pins")"
CACHE=${CACHE:-$HOME/.cache/gex}
dir=$CACHE/linux-headers-$(printf %.12s "$LINUX_HEADERS_SHA256")
mkdir -p "$CACHE"
exec 8>"$dir.lock"
flock 8
if [ ! -f "$dir/.done" ]; then
  "$HERE/../wine/dl.sh" "$LINUX_HEADERS_URL" "$LINUX_HEADERS_SHA256" "$CACHE/dl" >&2
  rm -rf "$dir.tmp" && mkdir -p "$dir.tmp"
  ar p "$CACHE/dl/$(basename "$LINUX_HEADERS_URL")" data.tar.xz | tar -xJ -C "$dir.tmp" ./usr/include ./usr/lib/linux
  touch "$dir.tmp/.done"
  rm -rf "$dir" && mv "$dir.tmp" "$dir"
fi
echo "$dir/usr/include"
