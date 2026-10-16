// Gate Ola 9C (regex/glob): pattern matching on a real boot.
#include <regex.h>
#include <stdio.h>
#include <fnmatch.h>

int main(void) {
    regex_t re;
    if (regcomp(&re, "a+b", REG_EXTENDED) != 0) {
        printf("regcomp fail\n");
        return 1;
    }
    regmatch_t m[1];
    if (regexec(&re, "aaab", 1, m, 0) != 0 || m[0].rm_so != 0 || m[0].rm_eo != 4) {
        printf("regexec fail\n");
        regfree(&re);
        return 1;
    }
    if (regexec(&re, "ccc", 1, m, 0) != REG_NOMATCH) {
        printf("nomatch fail\n");
        regfree(&re);
        return 1;
    }
    regfree(&re);
    if (fnmatch("*.c", "gate.c", 0) != 0 || fnmatch("*.c", "gate.h", 0) == 0) {
        printf("fnmatch fail\n");
        return 1;
    }
    printf("regex ok\n");
    return 0;
}
