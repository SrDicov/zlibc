// Gate 6E, binary (a): minimal dynamic hello. Exercises the whole cold
// path (kernel -> _dlstart -> self-reloc -> LDSO decode -> load_deps ->
// JUMP_SLOT/GLOB_DAT -> CRTJMP -> main) with one moving part: printf.
// Built with musl-gcc and --dynamic-linker pointing at our libc.so;
// see the smoke-6e CI job. Deliberately no TLS, no threads, no COPY —
// those are binaries (c), (d), (e).
#include <stdio.h>

int main(void)
{
	printf("hello from zlibc %d\n", 41);
	return 0;
}
