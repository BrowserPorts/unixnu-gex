#!/usr/bin/env bash
# Run a Windows program on Wine under gexc: a 64-bit Wine install (--dist,
# wine64-dist.sh's) or 32-bit Wine (Wine's own Unix side as wasm32 on gex)
# with the dist and prefix `make -C wine` builds.
#
#   wine/run.sh [options] EXE [ARGS...]
#
# EXE is a host path. The program runs in its own directory (Z:\ maps the
# host root), on a fresh copy of the prefix, with its images and Wine's on
# function-tier units (GEX_WINE32_UNITS=all) from one unit cache.
#
# With --dist a 64-bit Wine install (wine64-dist.sh's: lib/wine/x86_64-unix)
# it runs that on --prefix (required: its WINE64_PREFIX, copied) with
# --null's driver or Wayland, and without doors; a dist with
# lib/wine/i386-windows (WINE64_WOW64=1) runs 32-bit programs in the 64-bit
# process (WoW64). No make then; units default to units beside the dist. --native's
# core goes over a linked copy of the dist, kept beside it (native-KEY).
#
# Options:
#   --null             the null display driver (no compositor; tests)
#   --prefix DIR       copy this prefix instead of the Makefile's
#   --native DIR       (64-bit Wine) the native PE core (wine64-dist.sh's
#                      WINE64_NATIVE) over the dist's x86_64-windows
#   --keep DIR         run in DIR, a prefix copy kept for the next run (made
#                      when missing); without it a temporary copy is removed
#   --dist DIR         this dist instead of the Makefile's
#   --units DIR        unit cache (GEX_CGEN_CACHE; default WINE32_CACHE/units).
#                      Unit keys include gexc's gex-cgen sources: one cache
#                      serves every gexc, each finding its own units.
#   --build-units      build missing units in the background for the next run
#   --size WxH         the compositor's output size (default 1280x720)
#   --out DIR|null     where the compositor writes frames (default null)
#   --env K=V          more environment for the program (repeatable)
#   --debug CHANNELS   WINEDEBUG (default err+all,fixme-all)
#   --timeout S        stop after S seconds (default: none)
#   --no-make          do not run make first (use what is built)
#   --gexc PATH        the x86 gexc (default GEXC, or this tree's target/x86/release/gexc)
# Make settings (WINE32_CACHE, WINE_DIR, ...) pass through the environment.
set -euo pipefail
WINE32=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$WINE32/.." && pwd)
graphics=wayland prefix="" native="" keep="" dist="" units="" size=1280x720 out=null debug=err+all,fixme-all tmo="" make=1 envs=()
gexc=${GEXC:-$ROOT/target/x86/release/gexc}
build_units=""
while [ $# -gt 0 ]; do
  case $1 in
    --null) graphics=null ;;
    --prefix) prefix=$2; shift ;;
    --native) native=$(realpath "$2"); shift ;;
    --keep) keep=$2; shift ;;
    --dist) dist=$2; shift ;;
    --units) units=$2; shift ;;
    --build-units) build_units=1 ;;
    --size) size=$2; shift ;;
    --out) out=$2; shift ;;
    --env) envs+=(--env "$2"); shift ;;
    --debug) debug=$2; shift ;;
    --timeout) tmo=$2; shift ;;
    --no-make) make="" ;;
    --gexc) gexc=$2; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    --) shift; break ;;
    -*) echo "run.sh: unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
  shift
done
exe=$(realpath "${1:?usage: run.sh [options] EXE [ARGS...]}"); shift
[ -x "$gexc" ] || { echo "run.sh: no x86 gexc at $gexc (cargo build --release -p gexc --features x86, or --gexc)" >&2; exit 1; }
target=prefix; [ $graphics = null ] && target=prefix-null
# A 64-bit Wine dist (--dist with lib/wine/x86_64-unix: wine64-dist.sh's)
# runs as it is, with its own prefix: no make.
w64=""; [ -n "$dist" ] && [ -f "$dist/lib/wine/x86_64-unix/wine" ] && w64=1
if [ -n "$w64" ]; then
  [ -n "$prefix" ] || { echo "run.sh: a 64-bit Wine dist needs --prefix (its WINE64_PREFIX)" >&2; exit 1; }
  dist=$(realpath "$dist")
  WINE32_KEY=w64s-$({ echo "$dist $native"; find -L "$dist" ${native:+"$native"} -type f -printf '%T@ %s %p\n' | sort; } | sha256sum | cut -c1-12)
  WINE32_DIST=$dist
  units=${units:-$(dirname "$dist")/units}
else
  [ -n "$make" ] && make -s -C "$WINE32" dist $target >&2
  eval "$(make -s -C "$WINE32" paths)"
  dist=${dist:-$WINE32_DIST}
  [ -n "$prefix" ] || { [ $graphics = null ] && prefix=$WINE32_PREFIX_NULL || prefix=$WINE32_PREFIX; }
  units=${units:-$WINE32_UNITS}
  [ -d "$dist/lib/wine/i386-unix" ] || { echo "run.sh: no dist at $dist" >&2; exit 1; }
fi
[ -f "$prefix/system.reg" ] || { echo "run.sh: no prefix at $prefix" >&2; exit 1; }
mkdir -p "$units"
wl=$(mktemp -d "${TMPDIR:-/tmp}/wine32-wl.XXXXXX"); tmp=""
trap 'rm -rf "$wl" $tmp' EXIT
if [ -n "$keep" ]; then
  pfx=$(realpath -m "$keep"); [ -f "$pfx/system.reg" ] || cp -a "$prefix" "$pfx"
else
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/wine32-run.XXXXXX"); pfx=$tmp/pfx; cp -a "$prefix" "$pfx"
fi
loader=$dist/lib/wine/i386-unix/wine
if [ -n "$w64" ]; then
  # the prefix's driver as --null asks (its prefix keeps one)
  gd=wayland; [ $graphics = null ] && gd=null
  [ "$(grep '^"Graphics"=' "$pfx/user.reg" | tail -1)" = "\"Graphics\"=\"$gd\"" ] ||
  printf '\n[Software\\\\Wine\\\\Drivers] 1791289000\n"Graphics"="%s"\n' $gd >> "$pfx/user.reg"
  # the native core's files in place of the PE ones, on a linked copy
  if [ -n "$native" ]; then
    nd=$(dirname "$dist")/native-$WINE32_KEY
    [ -f "$nd/.done" ] || {
      rm -rf "$nd"; cp -rl "$dist" "$nd"
      for f in "$native"/*; do rm -f "$nd/lib/wine/x86_64-windows/${f##*/}"; cp "$f" "$nd/lib/wine/x86_64-windows/"; done
      touch "$nd/.done"; }
    dist=$nd
  fi
  loader=$dist/lib/wine/x86_64-unix/wine
  [ -d "$dist/lib/wine/i386-windows" ] && envs+=(--env WINEGEX_WOW64=1)
fi
win="Z:$(printf %s "$exe" | tr / '\\')"
gl=(); [ $graphics = wayland ] && gl=(--gl)
cd "$(dirname "$exe")"
export GEX_WINE32_UNITS=${GEX_WINE32_UNITS:-all} GEX_CGEN_CACHE=$units
[ -n "$build_units" ] && export GEX_WINE32_UNITS_BUILD=1
cmd=("$gexc" run --env WINEPREFIX="$pfx" --env WINEDEBUG="$debug" "${envs[@]}" "${gl[@]}"
  --wayland "$wl/wl" --wayland-size "$size" --wayland-out "$out" "$loader" "$win" "$@")
rc=0
if [ -n "$tmo" ]; then timeout -k 10 "$tmo" "${cmd[@]}" || rc=$?; else "${cmd[@]}" || rc=$?; fi
exit $rc
