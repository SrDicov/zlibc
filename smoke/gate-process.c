// Gate Ola 8B (process): fork/exec/wait/system on a real boot.
// Exit code is the verdict: 0 = all paths behaved.
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    // fork + waitpid decode.
    pid_t p = fork();
    if (p < 0) {
        printf("fork fail\n");
        return 1;
    }
    if (p == 0)
        _Exit(7);
    int st = 0;
    if (waitpid(p, &st, 0) != p || !WIFEXITED(st) || WEXITSTATUS(st) != 7) {
        printf("waitpid fail\n");
        return 1;
    }
    // execvp in child.
    p = fork();
    if (p < 0) {
        printf("fork2 fail\n");
        return 1;
    }
    if (p == 0) {
        char *av[] = {"true", 0};
        execvp("true", av);
        _Exit(99);
    }
    if (waitpid(p, &st, 0) != p || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("execvp fail\n");
        return 1;
    }
    // system().
    int r = system("exit 3");
    if (!WIFEXITED(r) || WEXITSTATUS(r) != 3) {
        printf("system fail %d\n", r);
        return 1;
    }
    // posix_spawn.
    extern int posix_spawn(pid_t *, const char *, void *, void *, char *const *, char *const *);
    extern char **environ;
    pid_t sp = 0;
    char *av2[] = {"true", 0};
    if (posix_spawn(&sp, "/bin/true", 0, 0, av2, environ) != 0 || sp <= 0) {
        printf("spawn fail\n");
        return 1;
    }
    if (waitpid(sp, &st, 0) != sp || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("spawn wait fail\n");
        return 1;
    }
    printf("process ok\n");
    return 0;
}
