// Gate Ola 7 (dlopen): load libdmod.so at runtime, verify its
// constructor ran, resolve and call both functions, and check the
// NULL-handle and RTLD_NOLOAD-miss paths. Validates dlopen, dlsym on
// the handle closure, queue_ctors/do_init_fini on real objects.
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>

static int phdr_count;
static int phdr_named;

static int count_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;
    phdr_count++;
    if (info->dlpi_name)
        phdr_named++;
    return 0;
}

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
    // Ola 11C: link-map query, phdr walk and the dladdr stub.
    void *lm = 0;
    if (dlinfo(h, RTLD_DI_LINKMAP, &lm) != 0 || !lm) {
        printf("dlinfo fail\n");
        return 1;
    }
    if (dlinfo(h, 999, &lm) == 0) {
        printf("dlinfo req fail\n");
        return 1;
    }
    if (dl_iterate_phdr(count_cb, 0) != 0 || phdr_count < 3 || phdr_named < 2) {
        printf("iterate fail %d/%d\n", phdr_count, phdr_named);
        return 1;
    }
    Dl_info di;
    if (dladdr(value, &di) != 0) {
        printf("dladdr fail\n");
        return 1;
    }
    printf("dlopen ok\n");
    return 0;
}
