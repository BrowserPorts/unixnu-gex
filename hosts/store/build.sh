#!/bin/sh
# Build store.wasm: gex-store's editor (crates/gex-store/src/editor.rs) on
# its own, for the page's offline editor (runtime/src/store.js). Its
# own memory, not shared, and no kernel: the page hands it a store file's
# sync access handle through one import (`store.io`).
#
#   hosts/store/build.sh [OUT]     default runtime/files/out/gex/store.wasm
set -e
cd "$(dirname "$0")/../.."
OUT=${1:-runtime/files/out/gex/store.wasm}
REMAP="--remap-path-prefix=$(pwd)=/gex --remap-path-prefix=$(rustc --print sysroot)=/rust --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
RUSTFLAGS="$REMAP" cargo build -p gex-store-wasm --target wasm32-unknown-unknown --release --target-dir target/store
W=target/store/wasm32-unknown-unknown/release/gex_store_wasm.wasm
mkdir -p "$(dirname "$OUT")"
if command -v wasm-tools > /dev/null; then
    wasm-tools strip -a "$W" -o "$OUT"
else
    cp "$W" "$OUT"
fi
echo "hosts/store: $OUT, $(wc -c < "$OUT" | tr -d ' ') bytes"
