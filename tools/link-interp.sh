#!/bin/sh
# Link the zlibc ELF interpreter / libc.so candidate from a static archive.
#
# Two GNU ld behaviors force preprocessing of the archive (measured with
# binutils 2.47, see "Fase 0" in docs/plan.md):
#
#  1. A strong zlibc def plus a weak compiler_builtins def of the same C
#     name (libm today: ceil/floor/round/trunc/copysign/fabs + f32) come
#     out of `-shared` as a LOCAL symbol, silently dropping it from
#     `.dynsym` (and no `--export-dynamic-symbol` / version-script entry
#     promotes it back). Fix: localize (`objcopy -L`) the weak duplicate
#     inside its own archive member. The dup list is computed from the
#     archive on every link, so later waves (sin/cos/...) are covered
#     with zero edits here.
#
#  2. `--whole-archive` drags ~600 mangled Rust internals into `.dynsym`.
#     Fix: `--version-script` with `global` = the full musl baseline
#     (all 1650 names, so the map never needs updating as symbols land)
#     plus the loader entry `_dlstart`; `local: *` hides the rest. Data
#     globals stay preemptible (COPY interposition keeps working);
#     `-Bsymbolic-functions` still binds internal calls locally.
#
# Usage: tools/link-interp.sh <libzlibc.a> <output.so>
set -eu

a=${1:?Usage: tools/link-interp.sh <libzlibc.a> <output.so>}
out=${2:?Usage: tools/link-interp.sh <libzlibc.a> <output.so>}
root=$(dirname "$0")

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
cp "$a" "$tmp/link.a"

# --- 1. weak-dup localize: names defined BOTH strong and weak. ---
nm "$tmp/link.a" 2>/dev/null | grep ' T ' | sed 's/^[0-9a-f]* T //' \
    | LC_ALL=C sort -u > "$tmp/strong.txt"
nm "$tmp/link.a" 2>/dev/null | grep ' W ' | sed 's/^[0-9a-f]* W //' \
    | LC_ALL=C sort -u > "$tmp/weak.txt"
LC_ALL=C comm -12 "$tmp/strong.txt" "$tmp/weak.txt" > "$tmp/dups.txt"
if [ -s "$tmp/dups.txt" ]; then
    mkdir -p "$tmp/m"
    members=$(nm "$tmp/link.a" 2>/dev/null \
        | awk '/\.o:$/{m=$1} / W /{print m" "$3}' \
        | while read -r m s; do
            if grep -qxF "$s" "$tmp/dups.txt"; then echo "${m%:} $s"; fi
          done | awk '{print $1}' | sort -u) || true
    # shellcheck disable=SC2162
    echo "$members" | while read -r m; do
        [ -n "$m" ] || continue
        (cd "$tmp/m" && ar x ../link.a "$m")
        for s in $(cat "$tmp/dups.txt"); do
            if nm "$tmp/m/$m" 2>/dev/null | grep -q " W $s\$"; then
                objcopy -L "$s" "$tmp/m/$m"
            fi
        done
        (cd "$tmp/m" && ar r ../link.a "$m" >/dev/null 2>&1)
    done
fi

# --- 2. version map: baseline + loader entry global, rest local. ---
{
    echo '{global:'
    grep -v '^#' "$root/musl-exports.txt" | sed 's/$/;/'
    echo '_dlstart;'
    echo 'local: *; };'
} > "$tmp/exports.map"

cc -nostdlib -shared -Wl,-e,_dlstart -Wl,-Bsymbolic-functions \
    -o "$out" -Wl,--whole-archive "$tmp/link.a" -Wl,--no-whole-archive \
    -Wl,--version-script,"$tmp/exports.map"
