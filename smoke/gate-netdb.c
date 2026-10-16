// Gate Ola 10 (netdb/passwd/sysconf): resolver helpers, user database,
// resource limits and crypt on a real boot.
#include <arpa/inet.h>
#include <grp.h>
#include <net/if.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <unistd.h>

// musl's crypt.h is absent from some toolchains; declare directly.
char *crypt(const char *, const char *);

int main(void) {
    // Byte order + address parse roundtrip.
    if (htons(0x1234) != 0x3412) {
        printf("endian fail\n");
        return 1;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, "127.0.0.1", &a) != 1 || a.s_addr != 0x0100007f) {
        printf("pton fail\n");
        return 1;
    }
    char nb[16];
    if (!inet_ntop(AF_INET, &a, nb, sizeof nb) || strcmp(nb, "127.0.0.1") != 0) {
        printf("ntop fail [%s]\n", nb);
        return 1;
    }
    // Loopback interface resolves both ways.
    if (if_nametoindex("lo") == 0) {
        printf("nametoindex fail\n");
        return 1;
    }
    // Root user + group parse.
    struct passwd *pw = getpwnam("root");
    if (!pw || pw->pw_uid != 0) {
        printf("pwnam fail\n");
        return 1;
    }
    struct group *gr = getgrnam("root");
    if (!gr || gr->gr_gid != 0) {
        printf("grnam fail\n");
        return 1;
    }
    // Resource limits + system name.
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0 || rl.rlim_cur == 0) {
        printf("rlimit fail\n");
        return 1;
    }
    struct utsname u;
    if (uname(&u) != 0 || !u.release[0]) {
        printf("uname fail\n");
        return 1;
    }
    if (sysconf(_SC_PAGESIZE) != 4096 || sysconf(_SC_CLK_TCK) != 100) {
        printf("sysconf fail\n");
        return 1;
    }
    // DES crypt is deterministic and salt-prefixed.
    char *h = crypt("pw", "aa");
    if (!h || strncmp(h, "aa", 2) != 0 || strlen(h) != 13) {
        printf("crypt fail [%s]\n", h ? h : "(null)");
        return 1;
    }
    printf("netdb ok\n");
    return 0;
}
