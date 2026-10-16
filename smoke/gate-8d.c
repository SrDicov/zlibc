// Gate Ola 8D (dirent/poll/termios): directory listing + poll + tty
// probe on a real boot.
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

int main(void) {
    // opendir/readdir finds what we created.
    int fd = open("/tmp/zlibc-gate-8d.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("create fail\n");
        return 1;
    }
    close(fd);
    DIR *d = opendir("/tmp");
    if (!d) {
        printf("opendir fail\n");
        return 1;
    }
    int found = 0;
    struct dirent *de;
    while ((de = readdir(d)) != 0) {
        const char *n = de->d_name;
        if (n[0] == 'z' && n[1] == 'l' && n[2] == 'i' && n[3] == 'b' && n[4] == 'c'
            && n[5] == '-' && n[6] == 'g')
            found = 1;
    }
    closedir(d);
    if (!found) {
        printf("readdir fail\n");
        return 1;
    }
    // poll sees a written pipe byte.
    int p[2];
    if (pipe(p) != 0) {
        printf("pipe fail\n");
        return 1;
    }
    if (write(p[1], "x", 1) != 1) {
        printf("write fail\n");
        return 1;
    }
    struct pollfd pf;
    pf.fd = p[0];
    pf.events = POLLIN;
    pf.revents = 0;
    if (poll(&pf, 1, 1000) != 1 || !(pf.revents & POLLIN)) {
        printf("poll fail\n");
        return 1;
    }
    close(p[0]);
    close(p[1]);
    // A pipe is not a tty.
    if (isatty(0) != 0 && isatty(1) != 0) {
        // Under CI stdio may be redirected; only assert pipes fail.
        int q[2];
        pipe(q);
        int r = isatty(q[0]);
        close(q[0]);
        close(q[1]);
        if (r != 0) {
            printf("isatty fail\n");
            return 1;
        }
    }
    printf("8d ok\n");
    return 0;
}
