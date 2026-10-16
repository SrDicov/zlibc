// Gate Ola 9C (time): clock/calendar formatting on a real boot.
#include <stdio.h>
#include <time.h>

int main(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0 || ts.tv_sec < 1577836800) {
        printf("clock fail\n");
        return 1;
    }
    time_t t = 0;
    struct tm tm;
    if (!gmtime_r(&t, &tm) || tm.tm_year != 70 || tm.tm_mday != 1) {
        printf("gmtime fail\n");
        return 1;
    }
    char buf[32];
    if (strftime(buf, sizeof buf, "%Y-%m-%d", &tm) != 10 || buf[0] != '1' || buf[1] != '9') {
        printf("strftime fail [%s]\n", buf);
        return 1;
    }
    if (timegm(&tm) != 0) {
        printf("timegm fail\n");
        return 1;
    }
    printf("time ok\n");
    return 0;
}
