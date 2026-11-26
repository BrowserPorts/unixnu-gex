#!/bin/sh
# gex's own pages, the test page (index.html, src/host/harness.js) and the
# Wine test page (nt.html, src/host/nt-page.js), built over the runtime's
# files in runtime/files/out, one dist per flavour; or the app library
# alone (app.mjs: src/host/app.js and the chunks and Workers it needs).
#
#   runtime/app/build.sh [--mp | --sp | --both] [--debug]
#   runtime/app/build.sh --lib DIR
#
#   MP  runtime/app/dist      served with COOP/COEP; threaded Mesa and Xwayland
#   SP  runtime/app/dist-sp   served without them; non-pthread Mesa and Xwayland
#
# The runtime's files come first (runtime/files/build.sh, or make assets,
# make mesa and make xwayland). For each flavour this stages a public tree
# in $CACHE/public-<flavour>:
#   - hard links to runtime/files/out;
#   - without the other flavour's Mesa and Xwayland;
#   - without the files no page loads: the plain shim, seed and kernel,
#     which run-node.mjs and the check scripts use from runtime/files/out.
# Its large wasm files are stripped of custom sections (DWARF, names) unless
# --debug is given; the unstripped ones are linked into
# target/web-debug/<flavour>/ for symbolizing. vite then builds the
# flavour's dist from that tree, with a config written here over
# runtime/app/config.mjs.
#
# --lib DIR: app.mjs and its chunks into DIR (relative URLs, so they work
# under any path), and nothing of runtime/files/out: the page that imports
# app.mjs brings the runtime's files (an eject site's pack, or its own gex/
# beside it). site/build-eject-page.sh builds the library with its files.
#
# $CACHE is GEX_WEB_BUILD, by default target/web-build.
#
# To serve both dists at once:
#
#   node runtime/app/serve.mjs 8088 --sp-port 8089
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
RT="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$RT/.." && pwd)"
PUB="$RT/files/out"
CACHE="${GEX_WEB_BUILD:-$ROOT/target/web-build}"
DEBUGDIR="$ROOT/target/web-debug"
VITE="$RT/node_modules/.bin/vite"
MP=1 SP=0 DEBUG=0 LIB=
while [ $# -gt 0 ]; do
    case $1 in
    --mp) MP=1 SP=0 ;;
    --sp) MP=0 SP=1 ;;
    --both) MP=1 SP=1 ;;
    --debug) DEBUG=1 ;;
    # (made first and taken by cd: --lib needs no GNU tools, so a caller
    # without host-env.sh's PATH, as Stellite's Linux runtime build is,
    # can run it; macOS's realpath has no -m)
    --lib) mkdir -p "${2:?runtime/app/build.sh --lib DIR}" && LIB=$(cd "$2" && pwd); shift ;;
    *) echo "usage: runtime/app/build.sh [--mp | --sp | --both] [--debug] | --lib DIR" >&2; exit 2 ;;
    esac
    shift
done
[ -x "$VITE" ] || { echo "runtime/app/build.sh: no $VITE (cd runtime && npm ci)" >&2; exit 1; }
mkdir -p "$CACHE"
say() { printf '\n== %s\n' "$*"; }

if [ -n "$LIB" ]; then
    mkdir -p "$LIB"
    CONFIG=$(mktemp "$HERE/.app-lib.XXXXXX")
    mv "$CONFIG" "$CONFIG.mjs"; CONFIG=$CONFIG.mjs
    trap 'rm -f "$CONFIG"' EXIT
    cat > "$CONFIG" <<CFG
import base from '$HERE/config.mjs';
export default {
  ...base,
  root: '$HERE',
  // URLs relative to app.mjs, so the library works under any path.
  base: './',
  publicDir: false,
  logLevel: 'warn',
  build: { ...base.build, outDir: '$LIB', emptyOutDir: false,
           // A library: app.mjs keeps its exports (start, fromLaunch).
           lib: { entry: '$RT/src/host/app.js', formats: ['es'], fileName: () => 'app.mjs' } },
};
CFG
    (cd "$HERE" && "$VITE" build --config "$CONFIG")
    echo "$LIB/app.mjs"
    exit 0
fi

# What the bundle is built from, taken before it is: written as the dist's
# .inputs (runtime/files/build-inputs.mjs). Its gex/.inputs comes from
# runtime/files/out.
PAGE_KEY=$(node "$RT/files/build-inputs.mjs" key page)
dist() { # dist <mp|sp>
    f=$1
    out=$HERE/dist; [ "$f" = sp ] && out=$HERE/dist-sp
    stage=$CACHE/public-$f
    say "runtime/app/${out##*/} ($f)"
    rm -rf "$stage" "$DEBUGDIR/$f"
    # (the files, through runtime/files/out where that is a link, as a
    # checkout whose build folders are on another volume has it: hard links
    # where the stage is on their volume, else copies)
    mkdir -p "$stage"
    cp -al "$PUB/." "$stage/" 2>/dev/null || { rm -rf "$stage" && mkdir -p "$stage" && cp -a "$PUB/." "$stage/"; }
    # Only what this flavour's page loads (runtime.js: the shared shim, the
    # shared seed, gex_kernel.wasm), and only its own Mesa and Xwayland.
    rm -f "$stage"/gex/gex_kernel*.plain.wasm
    for w in "$stage"/gex/gex_browser*.wasm "$stage"/gex/seed*.wasm; do
        case $w in *.shared.wasm) ;; *) rm -f "$w" ;; esac
    done
    if [ "$f" = mp ]; then
        rm -rf "$stage/gex/st" "$stage/gex/xwayland-st"
    else
        rm -rf "$stage/gex/xwayland" "$stage"/gex/gex-wgpu-replay.*
    fi
    if [ "$DEBUG" = 0 ]; then
        # Custom sections out: DWARF, and the name section, which nothing in
        # the runtime reads (a trap then names wasm-function[N]; symbolize
        # with the copies in target/web-debug). Not the seed or the providers,
        # whose gex.* sections the runtime does read.
        mkdir -p "$DEBUGDIR/$f"
        for w in "$stage"/gex/gex_browser*.shared.wasm "$stage"/gex/gex_kernel*.wasm \
                 "$stage"/gex/gex-wgpu-replay.wasm "$stage"/gex/st/gex-wgpu-replay.wasm \
                 "$stage"/gex/xwayland*/Xwayland.wasm "$stage"/gex/xwayland*/gexhostwl.wasm; do
            [ -f "$w" ] || continue
            rel=${w#"$stage"/}
            mkdir -p "$DEBUGDIR/$f/$(dirname "$rel")"
            ln -f "$w" "$DEBUGDIR/$f/$rel" 2>/dev/null || cp "$w" "$DEBUGDIR/$f/$rel"
            # A new file, not a write through the hard link into runtime/files/out.
            wasm-tools strip -a "$w" -o "$w.strip" && mv -f "$w.strip" "$w"
        done
    fi
    # The compositor bridge also zstd'd, which the X server's Worker asks for
    # first (hostx.js moduleBytes).
    for w in "$stage"/gex/xwayland*/gexhostwl.wasm; do
        if [ -f "$w" ]; then zstd -q -f -19 "$w" -o "$w.zst"; fi
    done
    config=$CACHE/vite-$f.config.mjs
    cat > "$config" <<CFG
import base from '$HERE/config.mjs';
export default {
  ...base,
  root: '$HERE',
  publicDir: '$stage',
  build: { ...base.build, outDir: '$out', emptyOutDir: true,
           rollupOptions: { input: { index: '$HERE/index.html', nt: '$HERE/nt.html' } } },
};
CFG
    (cd "$HERE" && GEX_PAGE_MODE="$f" "$VITE" build --config "$config" > "$CACHE/vite-$f.log" 2>&1) ||
        { tail -20 "$CACHE/vite-$f.log"; exit 1; }
    node "$RT/files/build-inputs.mjs" stamp "$out" "page=$PAGE_KEY"
    rm -rf "$stage"
    echo "  runtime/app/${out##*/}: $(du -sh "$out" | cut -f1)"
}
if [ "$DEBUG" = 0 ] && ! command -v wasm-tools >/dev/null 2>&1; then
    echo "need wasm-tools to strip the dists (cargo install wasm-tools), or pass --debug" >&2
    exit 1
fi
[ -f "$PUB/gex/gex_browser.shared.wasm" ] || [ -f "$PUB/gex/gex_browser.x86.shared.wasm" ] ||
    { echo "runtime/app/build.sh: no shim in $PUB/gex (make assets)" >&2; exit 1; }
[ "$MP" = 1 ] && dist mp
[ "$SP" = 1 ] && dist sp
exit 0
