#!/bin/sh
# binaryen at toolchain/pins' BINARYEN_VERSION, its release build for this
# host, checked against the pinned digest and unpacked once into CACHE.
#
#   toolchain/binaryen.sh             -> prints the install directory (bin/wasm-opt)
#
# GEX_BINARYEN names an existing install instead.
set -eu
HERE=$(dirname "$(realpath "$0")")
if [ -n "${GEX_BINARYEN:-}" ]; then
  realpath "$GEX_BINARYEN"
  exit 0
fi
eval "$(sed -n 's/^\(BINARYEN_[A-Z0-9_]*\) *:= *\(.*\)$/\1=\2/p' "$HERE/pins")"
case $(uname -s)-$(uname -m) in
  Linux-x86_64) host=x86_64-linux sum=$BINARYEN_SHA256_X86_64_LINUX ;;
  Linux-aarch64) host=aarch64-linux sum=$BINARYEN_SHA256_AARCH64_LINUX ;;
  Darwin-arm64) host=arm64-macos sum=$BINARYEN_SHA256_ARM64_MACOS ;;
  Darwin-x86_64) host=x86_64-macos sum=$BINARYEN_SHA256_X86_64_MACOS ;;
  *) echo "binaryen.sh: no binaryen $BINARYEN_VERSION build for $(uname -s) $(uname -m) (GEX_BINARYEN)" >&2; exit 1 ;;
esac
CACHE=${CACHE:-$HOME/.cache/gex}
dir=$CACHE/binaryen-$BINARYEN_VERSION-$host
mkdir -p "$CACHE"
exec 8>"$dir.lock"
flock 8
if [ ! -x "$dir/bin/wasm-opt" ]; then
  url=$BINARYEN_URL-$host.tar.gz
  "$HERE/../wine/dl.sh" "$url" "$sum" "$CACHE/dl" >&2
  rm -rf "$dir.tmp" && mkdir -p "$dir.tmp"
  tar -xzf "$CACHE/dl/$(basename "$url")" -C "$dir.tmp"
  rm -rf "$dir" && mv "$dir.tmp/binaryen-version_$BINARYEN_VERSION" "$dir" && rm -rf "$dir.tmp"
fi
echo "$dir"
