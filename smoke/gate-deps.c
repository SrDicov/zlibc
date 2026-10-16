// Gate 6E, binary (deps): a minimal dynamic program that links against
// its own libmine.so through DT_NEEDED and calls into it. Validates
// load_deps, add_syms and reloc_all on a real object.
#include <stdio.h>

int mine_value(void);

int main(void) {
    printf("gate-deps %d\n", mine_value());
    return 0;
}
