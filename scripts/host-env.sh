# The build environment of a macOS host.
#
# The build scripts are written against GNU tools, bash 4 or later and a case-sensitive
# file system. On macOS the tools come from Homebrew and the build folders sit on a
# case-sensitive volume; this file names both in one place. The Makefile reads it on
# Darwin through `--make`, which prints the settings as NAME=VALUE words. A build script
# run by hand is run from bash after `. scripts/host-env.sh`.
#
#   GEX_BUILD        this checkout's build folder on the case-sensitive volume (default:
#                    the folder target/ links into), with out/, work/ and tmp/ beside it
#   GEX_SHARED       what every checkout on the host shares, as a Linux host shares
#                    ~/.cache/gex and ~/emsdk (default: shared/ beside GEX_BUILD): cache/
#                    (CACHE), emsdk/, py/, mingw/, seeds/ and xdg-cache/
#   HOMEBREW_PREFIX  Homebrew's prefix (default /opt/homebrew)
#   GEX_MINGW        the MinGW GCC bin folder (default GEX_SHARED/mingw/bin)
#   GEX_EMSDK        the emsdk at EMSCRIPTEN_VERSION (toolchain/pins), exported as EMSDK
#                    (default GEX_SHARED/emsdk; an EMSDK already set is another project's)
#
# CACHE and MUSL64_SEED keep a value already set. TMPDIR is always the build folder's,
# since macOS sets it to the internal disk, and XDG_CACHE_HOME always the shared one.
#
# Homebrew: bash coreutils findutils gnu-sed gnu-tar grep gawk make libtool bison flock
# llvm@22 lld@22 wasm-tools xkbcomp. GNU binutils stay off PATH: their ar writes archives
# the host's linker rejects, and the guest toolchains bring their own. Python:
# GEX_SHARED/py, a venv with meson at MESON_VERSION (wine/libs.pins), mako, pyyaml and
# packaging.

gex_host_env() {
    local root hb build shared fail=0 d probe
    root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
    hb=${HOMEBREW_PREFIX:-/opt/homebrew}

    if [ -n "$GEX_BUILD" ]; then
        build=$GEX_BUILD
    elif [ -d "$root/target" ]; then
        build=$(dirname "$(cd "$root/target" && pwd -P)")
    else
        echo "host-env: target/ is missing: link it into the build volume or set GEX_BUILD" >&2
        return 1
    fi
    if [ "$build" = "$root" ]; then
        echo "host-env: target/ is a folder in the checkout: link it into the build volume or set GEX_BUILD" >&2
        return 1
    fi
    case $build in
    *[[:space:]]*) echo "host-env: GEX_BUILD has a space in it: $build" >&2; return 1 ;;
    esac

    # Linux sources hold names that differ only in case (xt_MARK.h, xt_mark.h)
    probe=$(mktemp "$build/.case.XXXXXX") || return 1
    if [ -e "$(dirname "$probe")/$(basename "$probe" | tr '[:lower:]' '[:upper:]')" ]; then
        rm -f "$probe"
        echo "host-env: $build is on a case-insensitive volume" >&2
        return 1
    fi
    rm -f "$probe"

    shared=${GEX_SHARED:-$(dirname "$build")/shared}
    [ -d "$shared" ] || { echo "host-env: no shared folder $shared (GEX_SHARED)" >&2; return 1; }
    case $shared in
    *[[:space:]]*) echo "host-env: GEX_SHARED has a space in it: $shared" >&2; return 1 ;;
    esac
    GEX_MINGW=${GEX_MINGW:-$shared/mingw/bin}
    GEX_PATH=$HOME/.cargo/bin:$shared/py/bin:$hb/opt/llvm@22/bin:$hb/opt/lld@22/bin
    for d in coreutils findutils gnu-sed gnu-tar grep gawk make libtool; do
        GEX_PATH=$GEX_PATH:$hb/opt/$d/libexec/gnubin
    done
    GEX_PATH=$GEX_PATH:$hb/opt/bison/bin:$GEX_MINGW:$hb/bin
    GEX_BASH=$hb/bin/bash

    for d in $(echo "$GEX_PATH" | tr : ' '); do
        [ -d "$d" ] || { echo "host-env: missing $d" >&2; fail=1; }
    done
    for d in "$GEX_BASH" "$hb/bin/flock" "$hb/bin/wasm-tools" "$hb/bin/xkbcomp" \
             "$HOME/.cargo/bin/rustup" "$shared/py/bin/meson"; do
        [ -x "$d" ] || { echo "host-env: missing $d" >&2; fail=1; }
    done
    [ "$fail" = 0 ] || return 1

    GEX_HOST_ENV=1
    CACHE=${CACHE:-$shared/cache}
    EMSDK=${GEX_EMSDK:-$shared/emsdk}
    EM_CONFIG=$EMSDK/.emscripten
    MUSL64_SEED=${MUSL64_SEED:-$shared/seeds/musl-wasm64}
    TMPDIR=$build/tmp
    XDG_CACHE_HOME=$shared/xdg-cache
    LLVM_CONFIG=$hb/opt/llvm@22/bin/llvm-config
    mkdir -p "$CACHE" "$TMPDIR" "$XDG_CACHE_HOME"
    GEX_HOST_VARS="GEX_HOST_ENV GEX_PATH GEX_BASH GEX_MINGW CACHE EMSDK EM_CONFIG MUSL64_SEED TMPDIR XDG_CACHE_HOME LLVM_CONFIG"
}

if [ "$1" = --make ]; then
    gex_host_env || exit 1
    # make splits the output into words, so no value may hold a space
    for v in $GEX_HOST_VARS; do
        eval "val=\$$v"
        case $val in
        *[[:space:]]*) echo "host-env: $v has a space in it: $val" >&2; exit 1 ;;
        esac
        printf '%s=%s\n' "$v" "$val"
    done
elif [ -z "$GEX_HOST_ENV" ]; then
    if gex_host_env; then
        for v in $GEX_HOST_VARS; do export "$v"; done
        export PATH=$GEX_PATH:$PATH
    fi
fi
