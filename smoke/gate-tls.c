// Gate 6E, binary (c): static-initialized thread-local storage. Exercises
// the app's `PT_TLS` -> `__init_tls` -> FS_BASE -> `tls_slot` access
// chain (musl `__dls3` -> `__init_tls`), addressed via the initial-exec
// model (`tp_off` in the TCB), with one moving part: a `__thread` value
// that must read its `.tdata` initializer without printf'd setup.
// Deliberately no threads here — binary (d) covers threading.
#include <stdio.h>

static __thread int tls_slot = 7;

int main(void)
{
	if (tls_slot != 7) {
		printf("tls bad init\n");
		return 1;
	}
	tls_slot = 12;
	printf("tls ok\n");
	return tls_slot == 12 ? 0 : 1;
}
