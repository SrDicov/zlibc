// Gate 6E, binary (e): R_X86_64_COPY. A dynamic executable that reads
// a libc **data** symbol directly takes a COPY of libc's definition into
// its own `.bss`, the loader patches libc-defs-to-app-space (musl
// `do_relocs` `case REL_COPY`, `dynlink.c:442-452`) and the app's own
// shadow wins. `stdout` is exactly the data symbol every real musl
// binary references this way, including via `fprintf`/`fputs`.
#include <stdio.h>

int main(void)
{
	fputs("copy ok\n", stdout);
	fflush(stdout);
	return 0;
}
