#!/bin/sh
# Pre-relocation codegen gate for the ELF interpreter.
#
# Usage: tools/pre-reloc-gate.sh path/to/ld-musl*.so.1
#
# Scans the loader's cold-boot symbol (and only that one) for indirect /
# GOT / PLT transfers. `_dlstart` keeps the one legal tail `jmp *%rax`;
# anything else fails. Anything post-relocation lives in `_dlstart_boot`
# and is never scanned, so relocated helpers (memcpy, decode_*) are free.
set -eu

so=${1:?Usage: tools/pre-reloc-gate.sh <so>}
names=$(nm --defined-only "$so" | awk '{print $NF}')

fail=0
# The pre-reloc skeleton must all resolve (no silent no-op gate).
for f in _dlstart; do
    sym=$(echo "$names" | grep -x "$f" | head -1)
    if [ -z "$sym" ]; then
        echo "::error::pre-reloc fn $f unresolvable (gate would be vacuous)"
        exit 1
    fi
    hits=$(objdump -d --disassemble="$sym" "$so" | grep -E '@plt|@GOTPCREL|call\s+\*|jmp\s+\*|callq|jmpq' || true)
    hits=$(echo "$hits" | grep -v 'jmp.*\*%rax' || true)
    if [ -n "$hits" ]; then
        echo "== $f ($sym) =="
        echo "$hits" | head -8
        fail=1
    fi
done

# Mangled `__dlstart_c` must also have no indirect/GOT transfers.
for f in _dlstart_c _dlstart_boot; do
    sym=$(echo "$names" | grep "$f" | head -1)
    if [ -z "$sym" ]; then
        echo "::warning::pre-reloc fn $f not present (nothing to scan)"
        continue
    fi
    hits=$(objdump -d --disassemble="$sym" "$so" | grep -E '@plt|@GOTPCREL|call\s+\*|jmp\s+\*|callq|jmpq' || true)
    if [ -n "$hits" ]; then
        echo "== $f ($sym) =="
        echo "$hits" | head -8
        fail=1
    fi
done

if [ "$fail" != 0 ]; then exit 1; fi
