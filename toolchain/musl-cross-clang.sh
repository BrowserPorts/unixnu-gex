#!/bin/sh
# A pinned musl cross toolchain (musl.cc's, whose programs are i386 Linux
# ones) for a host that does not run i386 Linux programs (macOS, AArch64
# Linux): the toolchain's own target files (musl, its headers, libgcc,
# libstdc++, the crt objects) with the host's clang and lld in place of its
# gcc and binutils.
#
#   toolchain/musl-cross-clang.sh TOOLCHAIN   -> TOOLCHAIN.clang
#
# TOOLCHAIN.clang has the toolchain's directories, linked, and a bin/ under
# the same names (TRIPLE-gcc, TRIPLE-ar, ...), so CROSS_COMPILE= and
# GEX_TOOLCHAIN= take it as they take the toolchain. LLVM_CONFIG (else
# llvm-config) names the LLVM whose clang and tools it runs; ld.lld is the
# one on PATH.
set -eu
tc=$(realpath "$1")
out=$tc.clang
triple=$(basename "$tc" | sed 's/-cross$//')
gccdir=$(echo "$tc/lib/gcc/$triple"/*)
[ -d "$gccdir" ] && [ -d "$tc/$triple/include" ] || { echo "musl-cross-clang: $tc is not a $triple toolchain" >&2; exit 1; }
# (its directory as LLVM_CONFIG names it, not --bindir's resolved one: a
# Homebrew opt/ path outlives the next point release)
lc=$(command -v "${LLVM_CONFIG:-llvm-config}") || { echo "musl-cross-clang: no llvm-config" >&2; exit 1; }
llvm=$(dirname "$lc")
lld=$(command -v ld.lld) || { echo "musl-cross-clang: no ld.lld on PATH" >&2; exit 1; }
[ -x "$llvm/clang" ] || { echo "musl-cross-clang: no clang in $llvm" >&2; exit 1; }

# What gcc's driver would know by itself: its target, its sysroot, its own
# libraries and its linker.
target="--target=$triple --sysroot=$tc/$triple --gcc-install-dir=$gccdir -fuse-ld=$lld --rtlib=libgcc --unwindlib=libgcc"

rm -rf "$out.tmp" && mkdir -p "$out.tmp/bin"
for d in "$tc"/* "$tc"/.pinned; do
  [ "$(basename "$d")" = bin ] || ln -s "$d" "$out.tmp/$(basename "$d")"
done
tool() {
  printf '#!/bin/sh\nexec %s "$@"\n' "$2" > "$out.tmp/bin/$triple-$1"
  chmod +x "$out.tmp/bin/$triple-$1"
}
# A program linked at a fixed address (-static, -no-pie) goes where GNU ld,
# the toolchain's own linker, puts it: 0x400000 (lld's own is 0x200000,
# which gex keeps for itself).
driver() {
  cat > "$out.tmp/bin/$triple-$1" <<EOF
#!/bin/sh
base=
for a; do
  case \$a in
    -static|-no-pie) base=-Wl,--image-base=0x400000 ;;
    -shared|-r|-c|-E|-S|-M|-MM|-static-pie) base=; break ;;
  esac
done
exec $2 \$base "\$@"
EOF
  chmod +x "$out.tmp/bin/$triple-$1"
}
for n in gcc cc gcc-11.2.1; do driver "$n" "$llvm/clang $target"; done
for n in g++ c++; do driver "$n" "$llvm/clang++ $target --stdlib=libstdc++"; done
tool cpp "$llvm/clang $target -E"
tool as "$llvm/clang $target -c"
for n in ld ld.bfd; do tool "$n" "$lld"; done
for n in ar ranlib nm; do
  tool "$n" "$llvm/llvm-$n"
  tool "gcc-$n" "$llvm/llvm-$n"
done
for n in strip objcopy objdump readelf size strings addr2line; do tool "$n" "$llvm/llvm-$n"; done
tool c++filt "$llvm/llvm-cxxfilt"
rm -rf "$out" && mv "$out.tmp" "$out"
echo "$out"
