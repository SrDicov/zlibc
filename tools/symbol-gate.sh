#!/bin/sh
# Symbol coverage of zlibc against the real musl x86_64 ABI surface.
#
# Blocking gate: it measures the source-level export surface
# (#[no_mangle] + weak_alias!) against the baseline and fails when the
# count drops below FLOOR. Bump FLOOR in the same commit that adds
# symbols; never lower it.
#
# Baseline provenance: musl git b1efda5b (VERSION 1.2.6), configured
# x86_64 and linked with x86_64-linux-musl-gcc 11.2.1, symbols read from
# lib/libc.so with `nm -D --defined-only`. That is the *dynamic* table:
# the static archive defines 1930 globals, of which 280 are
# `libc_hidden` and deliberately not exported, so 1650 is the real
# surface. True class breakdown (local musl build, `nm -D`):
# T:1418 W:199 D:6 R:3 B:14 V:10.
set -eu
export LC_ALL=C

# Lowest source-level count known green. Fase 0: 117.
FLOOR=207

root=$(dirname "$0")/..
baseline=$root/tools/musl-exports.txt
src=$root/src

# zlibc's export surface: every `#[no_mangle]` item (functions and data)
# plus every weak alias name. Four lines of context covers attributes
# between the marker and the signature.
{
    grep -rA4 '#\[no_mangle\]' "$src" --include='*.rs' \
        | grep -oE '\bfn [A-Za-z_][A-Za-z_0-9]*' | sed 's/fn //'
    grep -rA4 '#\[no_mangle\]' "$src" --include='*.rs' \
        | grep -oE '\bstatic( mut)? [A-Za-z_][A-Za-z_0-9]*' | sed -E 's/static( mut)? //'
    grep -rhoE 'weak_alias!\([A-Za-z_][A-Za-z_0-9]*' "$src" --include='*.rs' \
        | sed 's/.*(//'
    # Macro-emitted C entry points (#[no_mangle] lives inside the macro
    # definition, so the fn-name grep above misses them): va_trampoline!
    # today (printf/fprintf/snprintf in stdio.rs); extend per macro.
    grep -rhoE 'va_trampoline!\([A-Za-z_][A-Za-z_0-9]*' "$src" --include='*.rs' \
        | sed 's/.*(//'
} | sort -u > /tmp/zlibc-syms.$$
trap 'rm -f /tmp/zlibc-syms.$$ /tmp/zlibc-base.$$' EXIT

# Baseline carries `#` comments and is not sorted; normalize both sides
# with the same collation or comm silently miscompares (seen: it
# reported 7 instead of 114).
grep -v '^#' "$baseline" | sort -u > /tmp/zlibc-base.$$

total=$(wc -l < /tmp/zlibc-base.$$)
have=$(comm -12 /tmp/zlibc-base.$$ /tmp/zlibc-syms.$$ | wc -l)
pct=$(awk -v h="$have" -v t="$total" 'BEGIN{printf "%.1f", h*100/t}')

echo "musl x86_64 exported symbols: $total"
echo "zlibc implements:            $have ($pct%)"
echo "missing:                     $((total - have))"
echo "--- first 15 missing (sample, not exhaustive) ---"
comm -23 /tmp/zlibc-base.$$ /tmp/zlibc-syms.$$ 2>/dev/null | head -15 || true

if [ "$have" -eq 0 ]; then
    echo "::error::symbol extraction is vacuous (zero matches, gate would be meaningless)"
    exit 1
fi
if [ "$have" -lt "$FLOOR" ]; then
    echo "::error::symbol count $have below floor $FLOOR"
    exit 1
fi
