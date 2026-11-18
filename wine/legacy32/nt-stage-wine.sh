#!/usr/bin/env bash
# Stage Wine's PE DLLs and NLS files into a gex Windows prefix, which 32-bit
# Wine's dist is staged from (wine/legacy32/stage-native.sh).
#
#   wine/legacy32/nt-stage-wine.sh [PREFIX]          stage (default ~/.cache/gex/wine-11.15)
#   wine/legacy32/nt-stage-wine.sh --manifest        regenerate the manifest from the package
#
# The files come from WineHQ's Wine 11.15 package, pinned in toolchain/pins
# (WINEHQ_WINE, unpacked by toolchain/debian-package.sh), so every host
# stages the same prefix; WINE_LIB and WINE_SHARE name another Wine's. Each
# PE image is staged stripped (llvm-strip --strip-all: WineHQ ships them
# with their symbols and DWARF, twice the size), which gives the same bytes
# on every host.
#
# The prefix gets
#   drive_c/windows/system32/  <- $WINE_LIB/x86_64-windows/*  (PE32+ processes)
#   drive_c/windows/syswow64/  <- $WINE_LIB/i386-windows/*    (PE32 processes)
#   nls/                       <- $WINE_SHARE/nls/*.nls
# Nothing from x86_64-unix: gex replaces the Unix side of Wine entirely.
#
# Every file is checked against wine/legacy32/nt-wine-11.15.manifest (path, size,
# SHA-256). The dist is tied to one Wine release, so a mismatch is an error.
set -euo pipefail

VERSION=11.15
HERE=$(cd "$(dirname "$0")" && pwd)
MANIFEST="$HERE/nt-wine-$VERSION.manifest"
if [ -z "${WINE_LIB:-}" ] || [ -z "${WINE_SHARE:-}" ]; then
    PKG=$("$HERE/../../toolchain/debian-package.sh" WINEHQ_WINE)/opt/wine-devel
    WINE_LIB=${WINE_LIB:-$PKG/lib/wine}
    WINE_SHARE=${WINE_SHARE:-$PKG/share/wine}
fi
STRIP=${LLVM_STRIP:-llvm-strip}

# (source dir, destination dir inside the prefix, glob)
SETS=(
    "$WINE_LIB/x86_64-windows|drive_c/windows/system32|*"
    "$WINE_LIB/i386-windows|drive_c/windows/syswow64|*"
    "$WINE_SHARE/nls|nls|*.nls"
    # The bitmap and TrueType fonts Wine installs in C:\windows\Fonts; the NT
    # layer's GDI text draws with the bitmap ones (nt/gdi/font.rs).
    "$WINE_SHARE/fonts|drive_c/windows/Fonts|*"
)

# SRC as staged at DST: a PE image stripped, anything else as it is
stage_file() {
    local src=$1 dst=$2
    mkdir -p "$(dirname "$dst")"
    case $src in
    */*-windows/*) "$STRIP" --strip-all -o "$dst.tmp" "$src" 2>/dev/null || cp -f "$src" "$dst.tmp" ;;
    *) cp -f "$src" "$dst.tmp" ;;
    esac
    mv -f "$dst.tmp" "$dst"
}

list_files() {
    local set src dst glob f
    for set in "${SETS[@]}"; do
        IFS='|' read -r src dst glob <<<"$set"
        for f in "$src"/$glob; do
            [ -f "$f" ] || continue
            printf '%s|%s\n' "$f" "$dst/$(basename "$f")"
        done
    done
}

if [ "${1:-}" = "--manifest" ]; then
    # Staged into a scratch folder, so the manifest is of the files as staged
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    {
        echo "# Wine $VERSION PE files staged by wine/legacy32/nt-stage-wine.sh: <sha256> <size> <path in prefix>"
        list_files | while IFS='|' read -r src rel; do
            stage_file "$src" "$tmp/$rel"
            printf '%s %s %s\n' "$(sha256sum "$tmp/$rel" | cut -d' ' -f1)" "$(stat -c %s "$tmp/$rel")" "$rel"
        done
    } >"$MANIFEST"
    echo "wrote $MANIFEST ($(grep -vc '^#' "$MANIFEST") files)"
    exit 0
fi

PREFIX=${1:-${GEX_WINE_PREFIX:-$HOME/.cache/gex/wine-$VERSION}}
[ -f "$MANIFEST" ] || { echo "nt-stage-wine: no manifest at $MANIFEST" >&2; exit 1; }

declare -A want_sha want_size
while read -r sha size rel; do
    [[ "$sha" == \#* ]] && continue
    want_sha[$rel]=$sha
    want_size[$rel]=$size
done <"$MANIFEST"

mkdir -p "$PREFIX"
n=0 bad=0
while IFS='|' read -r src rel; do
    if [ -z "${want_sha[$rel]:-}" ]; then
        echo "nt-stage-wine: $src is not in the manifest" >&2
        bad=$((bad + 1))
        continue
    fi
    dst="$PREFIX/$rel"
    if [ ! -f "$dst" ] || [ "$(stat -c %s "$dst")" != "${want_size[$rel]}" ]; then
        stage_file "$src" "$dst"
    fi
    if [ "$(sha256sum "$dst" | cut -d' ' -f1)" != "${want_sha[$rel]}" ]; then
        echo "nt-stage-wine: $rel does not match the Wine $VERSION manifest" >&2
        bad=$((bad + 1))
    fi
    unset "want_sha[$rel]"
    n=$((n + 1))
done < <(list_files)

for rel in "${!want_sha[@]}"; do
    echo "nt-stage-wine: $rel is in the manifest but not in $WINE_LIB or $WINE_SHARE" >&2
    bad=$((bad + 1))
done
if [ "$bad" -gt 0 ]; then
    echo "nt-stage-wine: $bad problem(s) staging from $WINE_LIB and $WINE_SHARE" >&2
    exit 1
fi
# The profile wineboot would make for the user "gex": programs expect its
# folders, the temporary directory above all, to exist.
for d in "AppData/Local/Temp" "AppData/LocalLow" "AppData/Roaming" Desktop Documents Downloads \
    Music Pictures Videos "Saved Games" Favorites Links Contacts Searches; do
    mkdir -p "$PREFIX/drive_c/users/gex/$d"
done
for d in Desktop Documents Downloads Music Pictures Videos; do
    mkdir -p "$PREFIX/drive_c/users/Public/$d"
done
mkdir -p "$PREFIX/drive_c/ProgramData" "$PREFIX/drive_c/Program Files" "$PREFIX/drive_c/Program Files (x86)" \
    "$PREFIX/drive_c/windows/temp"
echo "$VERSION" >"$PREFIX/.wine-version"
echo "staged $n files for Wine $VERSION in $PREFIX"
