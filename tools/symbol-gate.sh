#!/bin/sh
# Symbol coverage of zlibc against the real musl x86_64 ABI surface.
#
# Informational today, not a gate: it measures the source-level export
# surface (#[no_mangle] + weak_alias!) against the baseline, which is the
# honest number while there is no cdylib to nm. When the linker packets
# produce libzlibc.so, replace the extraction with `nm -D --defined-only`
# and make this a hard gate.
#
# Baseline provenance: musl git b1efda5b (VERSION 1.2.6), configured
# x86_64 and linked with x86_64-linux-musl-gcc 11.2.1, symbols read from
# lib/libc.so with `nm -D --defined-only`. That is the *dynamic* table:
# the static archive defines 1930 globals, of which 295 are `libc_hidden`
# and deliberately not exported, so 1640 is the real surface.
set -eu

root=$(dirname "$0")/..
baseline=$root/tools/musl-exports.txt
src=$root/src

# zlibc's export surface: every `#[no_mangle]` function plus every weak
# alias name. Four lines of context covers attributes between the marker
# and the signature.
{
    grep -rA4 '#\[no_mangle\]' "$src" --include='*.rs' \
        | grep -oE '\bfn [A-Za-z_][A-Za-z_0-9]*' | sed 's/fn //'
    grep -rhoE 'weak_alias!\([A-Za-z_][A-Za-z_0-9]*' "$src" --include='*.rs' \
        | sed 's/.*(//'
} | sort -u > /tmp/zlibc-syms.$$
trap 'rm -f /tmp/zlibc-syms.$$' EXIT

total=$(grep -vc "^#" "$baseline")
have=$(comm -12 "$baseline" /tmp/zlibc-syms.$$ | wc -l)
pct=$(awk -v h="$have" -v t="$total" 'BEGIN{printf "%.1f", h*100/t}')

echo "musl x86_64 exported symbols: $total"
echo "zlibc implements:            $have ($pct%)"
echo "missing:                     $((total - have))"
echo "--- first 15 missing (sample, not exhaustive) ---"
comm -23 "$baseline" /tmp/zlibc-syms.$$ 2>/dev/null | head -15 || true
