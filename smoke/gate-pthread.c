// Gate 6E, binary (d): two real threads. Exercises `pthread_create` ->
// clone syscall, per-thread TCB / TLS setup, `pthread_mutex_lock` ->
// futex wake, and `pthread_join`. Each worker adds 11 under the lock so
// shared ends at 20 + 22 = 42; interleavings (both threads surviving a
// serialize) all converge there.
#include <pthread.h>
#include <stdio.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int shared = 20;

static void *worker(void *arg)
{
	(void)arg;
	pthread_mutex_lock(&mu);
	shared += 11;
	pthread_mutex_unlock(&mu);
	return 0;
}

int main(void)
{
	pthread_t t1;
	pthread_t t2;
	if (pthread_create(&t1, 0, worker, 0) != 0) {
		printf("pth create1 failed\n");
		return 1;
	}
	if (pthread_create(&t2, 0, worker, 0) != 0) {
		printf("pth create2 failed\n");
		return 1;
	}
	if (pthread_join(t1, 0) != 0 || pthread_join(t2, 0) != 0) {
		printf("pth join failed\n");
		return 1;
	}
	if (shared != 42) {
		printf("pth bad sum %d\n", shared);
		return 1;
	}
	printf("pth ok\n");
	return 0;
}
