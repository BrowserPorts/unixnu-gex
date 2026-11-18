#!/bin/sh
# Build the LLP64 plugin and its macro header.
#   toolchain/sysroot/llp64/build.sh OUT_DIR  -> OUT_DIR/GexLLP64.so, OUT_DIR/llp64.h
# clang's C++ headers: CLANG_DEV_INCLUDE, else llvm-config's include directory
# where it has them (an install of all of LLVM, Homebrew's), else, as on our
# Debian hosts where libclang-NN-dev is not installed, the matching Debian
# package fetched once (apt-get download, no root) into
# ~/.cache/gex/libclang-dev/<version>.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(realpath -m "$1"); mkdir -p "$out"
LLVM_CONFIG=${LLVM_CONFIG:-$(command -v llvm-config-22 || command -v llvm-config)}
inc=${CLANG_DEV_INCLUDE:-}
if [ -z "$inc" ] && [ -f "$($LLVM_CONFIG --includedir)/clang/Basic/TargetInfo.h" ]; then
  inc=$($LLVM_CONFIG --includedir)
fi
if [ -z "$inc" ]; then
  major=$($LLVM_CONFIG --version | cut -d. -f1)
  ver=$(dpkg-query -W -f '${Version}' "libclang-cpp$major" 2>/dev/null || echo unknown)
  cache=$HOME/.cache/gex/libclang-dev/$ver
  inc=$cache/usr/lib/llvm-$major/include
  if [ ! -f "$inc/clang/Basic/TargetInfo.h" ]; then
    tmp=$(mktemp -d)
    (cd "$tmp" && apt-get download "libclang-$major-dev=$ver" >/dev/null)
    mkdir -p "$cache"
    dpkg-deb --fsys-tarfile "$tmp"/*.deb | tar -x -C "$cache" "./usr/lib/llvm-$major/include"
    rm -rf "$tmp"
  fi
fi
# A plugin's LLVM symbols are the loading clang's: macOS's linker is told so.
undef=
[ "$(uname -s)" != Darwin ] || undef="-undefined dynamic_lookup"
# shellcheck disable=SC2046
clang++ -shared -fPIC -O1 $undef -I"$inc" $($LLVM_CONFIG --cxxflags) "$here/GexLLP64.cpp" -o "$out/GexLLP64.so.tmp"
mv "$out/GexLLP64.so.tmp" "$out/GexLLP64.so"
"$here/mkmacros.sh" > "$out/llp64.h"
