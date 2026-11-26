#!/bin/sh
# A pinned Debian package's files: the package toolchain/pins names as
# NAME_URL and NAME_SHA256 (Debian's snapshot archive, or another archive's
# such as WineHQ's), fetched by digest and unpacked (its data, no install,
# no scripts) once into CACHE.
# The same files on any host, where a copy of the build machine's /usr was
# whatever its distribution installed, and nothing on a host that is not
# Linux.
#
# The packages live in GEX_PACKAGE_CACHE when it is set
# (runtime/files/build.sh keeps its caller's store there while its own CACHE
# is its work folder), else in CACHE. Some hold paths that differ only in case (linux-libc-dev's
# netfilter headers: xt_CONNMARK.h, a target, beside xt_connmark.h, a match).
# Both of each such set are left out, on every file system, so the store and
# whatever copies from it (the sysroots' headers) can be case-insensitive and
# every host unpacks the same files. Keeping one would be worse than keeping
# neither: on a case-insensitive disk an include of the other name finds it
# and reads the wrong header, where now it fails to compile. Nothing gex
# builds includes them. (-ci in the folder's name: unpacked this way; a store
# unpacked before, with the sets, is left alone.)
#
#   toolchain/debian-package.sh NAME       -> prints the unpacked root (its usr/ or opt/)
set -eu
HERE=$(dirname "$(realpath "$0")")
name=${1:?NAME}
eval "$(sed -n "s/^\(${name}_URL\|${name}_SHA256\) *:= *\(.*\)\$/\1=\2/p" "$HERE/pins")"
eval "url=\${${name}_URL:?no ${name}_URL in toolchain/pins} sum=\${${name}_SHA256:?no ${name}_SHA256 in toolchain/pins}"
CACHE=${GEX_PACKAGE_CACHE:-${CACHE:-$HOME/.cache/gex}}
dir=$CACHE/debian-$(basename "$url" .deb)-$(printf %.12s "$sum")-ci
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
  ar p "$deb" "$member" | tar -t $z | sh "$HERE/case-pairs.sh" > "$dir.case"
  if [ -s "$dir.case" ]; then
    echo "debian-package: $(basename "$url"): $(wc -l < "$dir.case" | tr -d ' ') paths that differ from another only in case, left out:" >&2
    sed 's#^\./##; s#^#  #' "$dir.case" >&2
  fi
  ar p "$deb" "$member" | tar -x $z -C "$dir.tmp" -X "$dir.case"
  rm -f "$dir.case"
  touch "$dir.tmp/.done"
  rm -rf "$dir" && mv "$dir.tmp" "$dir"
fi
echo "$dir"
