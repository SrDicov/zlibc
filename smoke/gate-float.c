// Gate Ola 7B (dtoa): exact float formatting on a real boot.
// Expected outputs verified against musl/glibc printf semantics.
#include <stdio.h>

int main(void) {
    printf("[%f][%.2f][%e][%g][%a][%Lf]\n", 3.5, 3.14159, 123456.789, 100000.0, 1.5, 1.5L);
    printf("[%08.3f][%-8.1f!][%+.0f][% .0f][%#g]\n", 3.14159, 2.5, 0.5, 0.5, 100.0);
    printf("[%f][%e][%g]\n", 1.0 / 0.0, -(1.0 / 0.0), 0.0 / 0.0);
    return 0;
}
