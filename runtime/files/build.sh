#!/bin/sh
# Build the runtime's files into runtime/files/out for the multi-process build
# (MP, the default), the single-thread build (SP), or both, from one tree.
# runtime/build.sh makes the npm package from them.
#
#   runtime/files/build.sh [--mp | --sp | --both] [--no-assets] [--no-gl] [--no-x] [--x-only] [--gl-only]
#
# THE STEPS
#
# 1. The runtime both flavours run, built once into runtime/files/out by
#    runtime/files/build-assets.sh:
#    - the shim, kernel and seed, which the runtime loads as
#      gex_browser.shared.wasm, gex_kernel.wasm and seed.shared.wasm;
#    - the providers, rootfs and guest GL libraries.
#    SP loads the same three files and clears their memories' `shared` flag
#    as it compiles them (single.mjs enableSingle). An SP-only shim cannot be
#    smaller: its per-fiber stacks and TLS are what the atomics build provides.
# 2. Mesa and Xwayland for each flavour, each in its own build tree:
#
#      Mesa      MP: $CACHE/mesa-mt -> runtime/files/out/gex/
#                SP: $CACHE/mesa-st -> runtime/files/out/gex/st/
#      Xwayland  MP: $CACHE/xwl-mt  -> runtime/files/out/gex/xwayland/
#                SP: $CACHE/xwl-st  -> runtime/files/out/gex/xwayland-st/
#
#    Mesa rebuilds incrementally through ninja. The Xwayland script always
#    builds from scratch, so it is skipped while a stamp of its inputs
#    matches.
#
# $CACHE is GEX_WEB_BUILD, by default target/web-build. The packages
# toolchain/debian-package.sh unpacks stay in the caller's store
# (GEX_PACKAGE_CACHE, or the caller's CACHE).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export GEX_PACKAGE_CACHE="${GEX_PACKAGE_CACHE:-${CACHE:-$HOME/.cache/gex}}"
CACHE="${GEX_WEB_BUILD:-$ROOT/target/web-build}"
MP=1 SP=0 ASSETS=1 GL=1 X=1
for a in "$@"; do
    case $a in
    --mp) MP=1 SP=0 ;;
    --sp) MP=0 SP=1 ;;
    --both) MP=1 SP=1 ;;
    --no-assets) ASSETS=0 ;;
    --no-gl) GL=0 ;;
    --no-x) X=0 ;;
    # Only Xwayland into runtime/files/out.
    --x-only) ASSETS=0 GL=0 X=1 ;;
    # Only Mesa into runtime/files/out.
    --gl-only) ASSETS=0 GL=1 X=0 ;;
    *) echo "usage: runtime/files/build.sh [--mp | --sp | --both] [--no-assets] [--no-gl] [--no-x] [--x-only] [--gl-only]" >&2; exit 2 ;;
    esac
done
mkdir -p "$CACHE"
say() { printf '\n== %s\n' "$*"; }

# -- 1. shared by both: shim, kernel, seeds, providers, rootfs ----------------
if [ "$ASSETS" = 1 ]; then
    say "runtime and assets"
    GEX_NO_REFRESH_DIST=1 "$HERE/build-assets.sh"
fi

# -- 2. Mesa and Xwayland, per flavour ----------------------------------------
# What a Mesa build reads, as xwl_key does for Xwayland: the Mesa checkout (its commit and any
# uncommitted change), the build script, the toolchain, and gex's own sources that the build
# compiles or includes (ports/mesa/src, guest/gl, the glue's pre-js hooks: every file outside third_party/mesa in
# its ninja deps). ninja alone rebuilt and relinked gex-wgpu-replay on every build (2-4 min a
# flavour, 15-40 min under load) because a merge touched those files' mtimes, not their content.
mesa_key() { # mesa_key <mt|st>
    {
        echo "$1 ${GEX_MESA_PAGE_ONLY:-}"
        cat "$ROOT/ports/mesa/build.sh"
        emcc --version 2>/dev/null | head -1
        git -C "$ROOT/third_party/mesa" rev-parse HEAD
        git -C "$ROOT/third_party/mesa" diff HEAD
        git -C "$ROOT" ls-files -z ports/mesa/src guest/gl ports/mesa/gex-wgpu-split.js ports/mesa/gex-wgpu-jspi.js | (cd "$ROOT" && xargs -0 cat)
    } | sha256sum | cut -c1-32
}
mesa() { # mesa <mt|st>
    t=1; [ "$1" = st ] && t=0
    key=$(mesa_key "$1") stamp="$CACHE/mesa-$1.stamp" list="$CACHE/mesa-$1.published"
    # Unchanged inputs and every published file still in place: kept (GEX_MESA_REBUILD=1 forces).
    if [ "${GEX_MESA_REBUILD:-0}" != 1 ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$key" ] && [ -s "$list" ] &&
       (while read -r f; do [ -f "$f" ] || exit 1; done < "$list"); then
        say "Mesa ($1): unchanged, its published files kept"
        return 0
    fi
    say "Mesa ($1)"
    rm -f "$stamp"
    GEX_MESA_THREADS=$t "$ROOT/ports/mesa/build.sh" "$CACHE/mesa-$1" > "$CACHE/mesa-$1.log" 2>&1 ||
        { tail -30 "$CACHE/mesa-$1.log"; echo "Mesa ($1) failed; log in $CACHE/mesa-$1.log" >&2; exit 1; }
    grep -a "published" "$CACHE/mesa-$1.log" || true
    sed -n 's/^  published //p' "$CACHE/mesa-$1.log" > "$list"
    [ -s "$list" ] && echo "$key" > "$stamp"
}
xwl_key() { # xwl_key <mt|st>
    {
        echo "$1 ${XWAYLAND_TAG:-} ${WAYLAND_TAG:-}"
        cat "$ROOT/ports/xwayland/build.sh"
        # And the compositor and window manager hostwl is built from: a change
        # to either that left this key alone shipped the old hostwl. (Not
        # gex-kernel, which hostwl uses only for its vfs trait and errno.)
        find "$ROOT/ports/xwayland" "$ROOT/hosts/hostwl" "$ROOT/crates/gex-wayland" "$ROOT/crates/gex-xwm" \
            -type f -not -path '*/target/*' | LC_ALL=C sort | xargs cat
    } | sha256sum | cut -c1-32
}
xwl_host_tools() {
    # Built once into the cache at host-tools.sh's tags, on every host: the
    # X protocol headers are then the same everywhere, not the distribution's
    # (and a host that is not Linux has none).
    "$ROOT/ports/xwayland/host-tools.sh" "$CACHE/xwl-host"
    GEX_XWL_HOST_TOOLS="$CACHE/xwl-host"; export GEX_XWL_HOST_TOOLS
}
xwl() { # xwl <mt|st>
    t=1 pub=xwayland; [ "$1" = st ] && t=0 pub=xwayland-st
    key=$(xwl_key "$1")
    if [ "$(cat "$CACHE/xwl-$1.stamp" 2>/dev/null)" = "$key" ] && [ -f "$ROOT/runtime/files/out/gex/$pub/Xwayland.wasm" ]; then
        say "Xwayland ($1): unchanged, runtime/files/out/gex/$pub kept"
        return 0
    fi
    say "Xwayland ($1)"
    xwl_host_tools
    GEX_XWL_THREADS=$t "$ROOT/ports/xwayland/build.sh" "$CACHE/xwl-$1" > "$CACHE/xwl-$1.log" 2>&1 ||
        { tail -30 "$CACHE/xwl-$1.log"; echo "Xwayland ($1) failed; log in $CACHE/xwl-$1.log" >&2; exit 1; }
    echo "$key" > "$CACHE/xwl-$1.stamp"
    tail -2 "$CACHE/xwl-$1.log"
}
[ "$MP" = 1 ] && [ "$GL" = 1 ] && mesa mt
[ "$SP" = 1 ] && [ "$GL" = 1 ] && mesa st
[ "$MP" = 1 ] && [ "$X" = 1 ] && xwl mt
[ "$SP" = 1 ] && [ "$X" = 1 ] && xwl st
# gex's pages (runtime/app/dist*), copies of runtime/files/out, made again
# from what is here now; make page builds its own after this.
"$ROOT/runtime/app/refresh-dist.sh"
exit 0
