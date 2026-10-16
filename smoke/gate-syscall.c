// Gate Ola 7C (syscalls): exercise the new POSIX wrappers on a real
// boot, including errno paths. Prints one line on success.
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    // getpid/getppid sanity.
    if (getpid() <= 0 || getppid() <= 0) {
        printf("pid fail\n");
        return 1;
    }
    // pipe + dup2 + write/read.
    int p[2];
    if (pipe(p) != 0) {
        printf("pipe fail\n");
        return 1;
    }
    int q = dup2(p[1], 100);
    if (q != 100) {
        printf("dup2 fail %d\n", q);
        return 1;
    }
    if (write(q, "hi", 2) != 2) {
        printf("write fail\n");
        return 1;
    }
    char back[2];
    if (read(p[0], back, 2) != 2 || back[0] != 'h' || back[1] != 'i') {
        printf("read fail\n");
        return 1;
    }
    close(q);
    close(p[0]);
    close(p[1]);
    // open/write/pread/lseek/stat/fstat + errno on missing file.
    int fd = open("/tmp/zlibc-gate-syscall.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("open fail\n");
        return 1;
    }
    if (write(fd, "abcd", 4) != 4) {
        printf("write2 fail\n");
        return 1;
    }
    if (lseek(fd, 1, SEEK_SET) != 1) {
        printf("lseek fail\n");
        return 1;
    }
    char one;
    if (pread(fd, &one, 1, 2) != 1 || one != 'c') {
        printf("pread fail\n");
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size != 4) {
        printf("fstat fail\n");
        return 1;
    }
    close(fd);
    if (stat("/tmp/zlibc-gate-syscall.tmp", &st) != 0 || st.st_size != 4) {
        printf("stat fail\n");
        return 1;
    }
    if (open("/tmp/zlibc-gate-nope.tmp", O_RDONLY) != -1) {
        printf("errno fail\n");
        return 1;
    }
    // getopt smoke.
    extern int optind;
    char *av[] = {"prog", "-b", "x", 0};
    int c = getopt(3, av, "ab:");
    if (c != 'b') {
        printf("getopt fail %d\n", c);
        return 1;
    }
    printf("syscall ok\n");
    return 0;
}
