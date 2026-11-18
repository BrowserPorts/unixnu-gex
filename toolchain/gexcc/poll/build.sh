#!/bin/sh
# Build the GexPoll pass plugin for the system clang (LLVM 22).
#   toolchain/gexcc/poll/build.sh OUT_DIR   -> OUT_DIR/GexPoll.so
set -e
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$1"
LLVM_CONFIG=${LLVM_CONFIG:-$(command -v llvm-config-22 || command -v llvm-config)}
# A plugin's LLVM symbols are the loading clang's: macOS's linker is told so.
undef=
[ "$(uname -s)" != Darwin ] || undef="-undefined dynamic_lookup"
clang++ -shared -fPIC -O2 $undef $($LLVM_CONFIG --cxxflags) "$here/GexPoll.cpp" -o "$1/GexPoll.so"
