#!/bin/sh
# A pinned Debian package's files: the package toolchain/pins names as
# NAME_URL and NAME_SHA256 (Debian's snapshot archive, or another archive's
# such as WineHQ's), fetched by digest and unpacked (its data, no install,
# no scripts) once into CACHE.
# The same files on any host, where a copy of the build machine's /usr was
# whatever its distribution installed, and nothing on a host that is not
# Linux.
#
#   toolchain/debian-package.sh NAME       -> prints the unpacked root (its usr/ or opt/)
set -eu
HERE=$(dirname "$(realpath "$0")")
name=${1:?NAME}
eval "$(sed -n "s/^\(${name}_URL\|${name}_SHA256\) *:= *\(.*\)\$/\1=\2/p" "$HERE/pins")"
eval "url=\${${name}_URL:?no ${name}_URL in toolchain/pins} sum=\${${name}_SHA256:?no ${name}_SHA256 in toolchain/pins}"
CACHE=${CACHE:-$HOME/.cache/gex}
dir=$CACHE/debian-$(basename "$url" .deb)-$(printf %.12s "$sum")
mkdir -p "$CACHE"
exec 8>"$dir.lock"
flock 8
if [ ! -f "$dir/.done" ]; then
  "$HERE/../wine/dl.sh" "$url" "$sum" "$CACHE/dl" >&2
  deb=$CACHE/dl/$(basename "$url")
  member=$(ar t "$deb" | grep '^data\.tar')
  case $member in
    *.xz) z=-J ;; *.zst) z=--zstd ;; *.gz) z=-z ;; *) z= ;;
  esac
  rm -rf "$dir.tmp" && mkdir -p "$dir.tmp"
  ar p "$deb" "$member" | tar -x $z -C "$dir.tmp"
  touch "$dir.tmp/.done"
  rm -rf "$dir" && mv "$dir.tmp" "$dir"
fi
echo "$dir"
