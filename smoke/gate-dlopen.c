// Gate Ola 7 (dlopen): load libdmod.so at runtime, verify its
// constructor ran, resolve and call both functions, and check the
// NULL-handle and RTLD_NOLOAD-miss paths. Validates dlopen, dlsym on
// the handle closure, queue_ctors/do_init_fini on real objects.
#include <dlfcn.h>
#include <stdio.h>

int main(void) {
    void *h = dlopen("/tmp/zlibc-gate-deps/libdmod.so", RTLD_NOW);
    if (!h) {
        printf("dlopen fail: %s\n", dlerror());
        return 1;
    }
    int (*value)(void) = dlsym(h, "dmod_value");
    int (*ctor)(void) = dlsym(h, "dmod_ctor_check");
    if (!value || !ctor) {
        printf("dlsym fail\n");
        return 1;
    }
    if (value() != 43 || ctor() != 1) {
        printf("bad value %d ctor %d\n", value(), ctor());
        return 1;
    }
    if (dlopen(0, RTLD_NOW) == 0) {
        printf("null handle fail\n");
        return 1;
    }
    dlerror();
    if (dlopen("libghost.so", RTLD_NOLOAD) != 0 || dlerror() == 0) {
        printf("noload fail\n");
        return 1;
    }
    printf("dlopen ok\n");
    return 0;
}
