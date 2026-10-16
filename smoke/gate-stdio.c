// Gate Ola 8C (stdio): file lifecycle + scanf on a real boot.
#include <stdio.h>
#include <string.h>

int main(void) {
    // fopen/fputs/fgets/fclose + ftell/rewind.
    FILE *f = fopen("/tmp/zlibc-gate-stdio.txt", "w+");
    if (!f) {
        printf("fopen fail\n");
        return 1;
    }
    if (fputs("hello", f) < 0) {
        printf("fputs fail\n");
        return 1;
    }
    rewind(f);
    char buf[16];
    if (!fgets(buf, sizeof buf, f) || buf[0] != 'h' || buf[1] != 'e' || buf[2] != 'l' || buf[3] != 'l' || buf[4] != 'o' || buf[5] != 0) {
        printf("fgets fail [%s]\n", buf);
        return 1;
    }
    if (ftell(f) != 5) {
        printf("ftell fail\n");
        return 1;
    }
    fclose(f);
    // scanf family from strings.
    int a = 0, b = 0, n = 0;
    if (sscanf("11x22", "%d%*c%d%n", &a, &b, &n) != 2 || a != 11 || b != 22 || n != 5) {
        printf("sscanf fail\n");
        return 1;
    }
    double d = 0;
    long double ld = 0;
    if (sscanf("3.14 2.5", "%lf %Lf", &d, &ld) != 2 || d < 3.13 || d > 3.15) {
        printf("scanf float fail\n");
        return 1;
    }
    // popen.
    FILE *p = popen("echo pop", "r");
    if (!p) {
        printf("popen fail\n");
        return 1;
    }
    char out[8] = {0};
    if (!fgets(out, sizeof out, p) || out[0] != 'p' || out[1] != 'o' || out[2] != 'p') {
        printf("popen read fail\n");
        pclose(p);
        return 1;
    }
    int st = pclose(p);
    if (st != 0) {
        printf("pclose fail %d\n", st);
        return 1;
    }
    printf("stdio ok\n");
    return 0;
}
