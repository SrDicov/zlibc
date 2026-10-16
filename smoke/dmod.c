// Gate Ola 7 (dlopen): a shared object with a constructor and two
// exported functions. The gate checks the constructor ran (init order),
// `dlsym` on the handle finds both symbols, and the values are right.
int dmod_ctor_ran = 0;

__attribute__((constructor)) static void dmod_init(void) {
    dmod_ctor_ran = 1;
}

int dmod_value(void) {
    return 43;
}

int dmod_ctor_check(void) {
    return dmod_ctor_ran;
}
