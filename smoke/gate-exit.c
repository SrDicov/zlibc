// Gate Ola 7 (exit): prove the termination paths on a real boot.
// Modes by argv[1]: none (atexit handler _exit(42)), "q" (quick_exit
// path, at_quick_exit handler _exit(43)), "a" (abort, dies by SIGABRT).
// Exit codes are the observable: handlers run before any flushing.
#include <stdlib.h>

int __cxa_atexit(void (*func)(void *), void *arg, void *dso);

static void bye_42(void *p) {
    (void)p;
    _Exit(42);
}

static void bye_43(void) {
    _Exit(43);
}

int main(int argc, char **argv) {
    char mode = argc > 1 && argv[1][0] ? argv[1][0] : 0;
    if (mode == 'q') {
        if (at_quick_exit(bye_43) != 0)
            return 1;
        quick_exit(0);
        return 1;
    }
    if (mode == 'a') {
        abort();
        return 1;
    }
    if (__cxa_atexit(bye_42, 0, 0) != 0)
        return 1;
    exit(0);
    return 1;
}
