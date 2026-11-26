#!/usr/bin/env bash
# gexcc's Windows target: MinGW-named tools building Windows x64 programs and
# DLLs as native wasm modules against 64-bit Wine's native PE side.
#
#   toolchain/gexcc/windows/install.sh PREFIX WINE_BUILD WINE_SRC
#
# WINE_BUILD  a 64-bit Wine build (wasm64, its tools beside it) whose
#             import libraries, headers, libgexrt and winecrt0 programs link
# WINE_SRC    its source tree (headers, nls)
# GEX_WASM64_SYSROOT  the wasm64 sysroot wcc64 compiles with
#                     (toolchain/sysroot/build64.sh)
# MINGW_W64           optional: a mingw-w64 source tree; programs then compile
#                     against its headers, not Wine's, and link the parts of
#                     its runtime those headers expect (the UCRT stdio wrappers)
# Then C++: toolchain/gexcc/windows/build-cxx.sh PREFIX LLVM_SRC.
# Out: PREFIX/bin/x86_64-w64-mingw32-{gcc,g++,cc,c++,windres,ar,ranlib,nm,
# strip,objcopy,objdump} and x86_64-pc-windows-msvc-{clang,clang++,...} (clang-cl's
# identity), PREFIX/lib/gexcc-win (the runtime every program
# links, the install's config), PREFIX/share/gexcc-win/toolchain.cmake.
set -eu
PREFIX=$(realpath -m "$1")
WB=$(realpath "$2")
WS=$(realpath "$3")
: "${GEX_WASM64_SYSROOT:?set GEX_WASM64_SYSROOT}"
HERE=$(dirname "$(realpath "$0")")
for f in "$WB/Makefile" "$WB/libs/gexrt/libgexrt.a" "$WB/libs/winecrt0/libwinecrt0.a" "$WS/include/windows.h"; do
  [ -f "$f" ] || { echo "install.sh: no $f" >&2; exit 1; }
done
L=$PREFIX/lib/gexcc-win
mkdir -p "$PREFIX/bin" "$L" "$PREFIX/share/gexcc-win"
printf 'WINE_BUILD=%s\nWINE_SRC=%s\nSYSROOT64=%s\nCXX=%s\n' "$WB" "$WS" "$(realpath "$GEX_WASM64_SYSROOT")" "$PREFIX/cxx" > "$L/config"
# (Wine's headers matched regardless of case, as on Windows: nocase.py)
python3 "$HERE/nocase.py" "$L/wine-nocase.yaml" "$WS/include" "$WB/include"
if [ -n "${MINGW_W64:-}" ]; then
  MW=$(realpath "$MINGW_W64")
  python3 "$HERE/mingw-headers.py" "$MW/mingw-w64-headers" "$L/include-mingw"
  echo "MINGW_INCLUDE=$L/include-mingw" >> "$L/config"
fi
for t in gcc g++ cc c++ windres ar ranlib nm strip objcopy objdump; do
  ln -sfn "$HERE/gexcc-win" "$PREFIX/bin/x86_64-w64-mingw32-$t"
done
# (clang-cl's identity, for projects written for MSVC: gexcc-win's docstring)
for t in clang clang++ windres ar ranlib nm strip objcopy objdump; do
  ln -sfn "$HERE/gexcc-win" "$PREFIX/bin/x86_64-pc-windows-msvc-$t"
done
sed -e "s#@BIN@#$PREFIX/bin#" -e "s#@AR@#$(command -v llvm-ar)#" -e "s#@RANLIB@#$(command -v llvm-ranlib)#" \
  "$HERE/win64.cmake" > "$PREFIX/share/gexcc-win/toolchain.cmake"
# the runtime: the C++ exception tag, the wmem* functions, dirent, gettimeofday, the entry
# wrappers that run the constructors first
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
CC=$PREFIX/bin/x86_64-w64-mingw32-gcc
clang --target=wasm64-unknown-unknown -mexception-handling -c "$HERE/rt/cpp_exception.s" -o "$T/cpp_exception.o"
"$CC" -O2 -c "$HERE/rt/wchar.c" -o "$T/wchar.o"
"$CC" -O2 -c "$HERE/rt/dirent.c" -o "$T/dirent.o"
"$CC" -O2 -c "$HERE/rt/math.c" -o "$T/math.o"
"$CC" -O2 -c "$HERE/rt/ssp.c" -o "$T/ssp.o"
"$CC" -O2 -c "$HERE/rt/time.c" -o "$T/time.o"
"$CC" -O2 -c "$HERE/rt/comsupp.c" -o "$T/comsupp.o"
for k in main wmain dll; do GEX_WASM_NO_ICALL=1 "$CC" -O2 -DONLY_$k -c "$HERE/rt/start.c" -o "$L/start_$k.o"; done
for k in 0 3; do "$CC" -O2 -DONLY_$k -c "$HERE/rt/wmain.c" -o "$L/wmain$k.o"; done
rm -f "$L/libgexcc-win.a"
llvm-ar rcs "$L/libgexcc-win.a" "$T/cpp_exception.o" "$T/wchar.o" "$T/dirent.o" "$T/math.o" "$T/ssp.o" "$T/time.o" "$T/comsupp.o"
# libffi (include-rt/ffi.h): -lffi, found in $L as a -L dir would be
"$CC" -O2 -c "$HERE/rt/ffi.c" -o "$T/ffi.o" || exit 1
"$CC" -O2 -c "$HERE/rt/ffilimit.c" -o "$T/ffilimit.o" || exit 1
llvm-ar rcs "$L/libffi.a" "$T/ffi.o" "$T/ffilimit.o" || exit 1
# with mingw-w64's headers: their stdio.h's printf and scanf families with
# the UCRT are mingw-w64's small wrappers over ucrtbase's __stdio_common_*
if [ -n "${MINGW_W64:-}" ]; then
  for f in "$MW"/mingw-w64-crt/stdio/ucrt_*.c; do
    "$CC" -O2 -c "$f" -o "$T/$(basename "$f" .c).o"
  done
  # and the old names (open for _open ...) its import libraries alias
  python3 "$HERE/oldnames.py" "$MW/mingw-w64-crt" "$L/include-mingw" "$HERE/include-mingw-pre" "$T/oldnames.c"
  "$CC" -O2 -c "$T/oldnames.c" -o "$T/oldnames.o"
  # and what MinGW's libws2_32.a has beside the imports: the wspiapi
  # getaddrinfo fallbacks, gai_strerror, the in6addr helpers
  for f in "$MW"/mingw-w64-crt/libsrc/wspiapi/*.c "$MW"/mingw-w64-crt/libsrc/ws2tcpip/*.c; do
    "$CC" -O2 -c "$f" -o "$T/ws2_$(basename "$f" .c).o"
  done
  # and its ANSI stdio entry points (__mingw_printf ...), over the UCRT's
  "$CC" -O2 -c "$HERE/rt/mingwstdio.c" -o "$T/mingwstdio.o"
  "$CC" -O2 -c "$HERE/rt/mingwldexpf.c" -o "$T/mingwldexpf.o"
  llvm-ar rs "$L/libgexcc-win.a" "$T"/ucrt_*.o "$T/oldnames.o" "$T"/ws2_*.o "$T/mingwstdio.o" "$T/mingwldexpf.o"
  # and its static libraries: the GUIDs (uuid, dxguid, strmiids, locationapi,
  # ksuser's beside its imports ...), in L/mingw, where gexcc-win's -lNAME
  # finds them; the list 'dll' marks those that are a DLL's imports too
  rm -rf "$L/mingw"; mkdir -p "$L/mingw"
  python3 "$HERE/mingwlibs.py" "$MW/mingw-w64-crt" | while read -r n kind fs; do
    os=
    for f in $fs; do
      o="$T/ml-$n-$(basename "$f" .c).o"; "$CC" -O2 -c "$MW/mingw-w64-crt/$f" -o "$o" || exit 1; os="$os $o"
    done
    llvm-ar rcs "$L/mingw/lib$n.a" $os || exit 1
    if [ "$kind" = dll ]; then echo "$n" >> "$L/mingw/dll-too"; fi
  done || exit 1
fi
# setjmp/longjmp, a copy of the program's own (a program has no core beside
# it to share the tag with): libgexrt's
(cd "$T" && llvm-ar x "$WB/libs/gexrt/libgexrt.a" wasm32_sjlj.o) && mv "$T/wasm32_sjlj.o" "$L/"
echo "gexcc-win: $PREFIX/bin/x86_64-w64-mingw32-gcc (Wine $WB)"
