// Gate Ola 11A (threads/sync): once, TSD, rwlock, barrier, spin,
// semaphores and C11 threads on a real boot.
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <threads.h>

static pthread_once_t once_ctl = PTHREAD_ONCE_INIT;
static int once_n = 0;
static pthread_key_t key;
static pthread_barrier_t bar;
static pthread_spinlock_t spin;
static sem_t sem;
static int hits = 0;

static void do_once(void)
{
	once_n++;
}

static void *worker(void *arg)
{
	(void)arg;
	pthread_once(&once_ctl, do_once);
	pthread_setspecific(key, (void *)0x77);
	if (pthread_getspecific(key) != (void *)0x77)
		return (void *)1;
	pthread_spin_lock(&spin);
	hits++;
	pthread_spin_unlock(&spin);
	sem_post(&sem);
	pthread_barrier_wait(&bar);
	return 0;
}

static int c11_fn(void *arg)
{
	(void)arg;
	return 7;
}

int main(void)
{
	if (pthread_key_create(&key, 0) != 0) {
		printf("key fail\n");
		return 1;
	}
	if (pthread_barrier_init(&bar, 0, 3) != 0) {
		printf("barrier init fail\n");
		return 1;
	}
	if (pthread_spin_init(&spin, 0) != 0) {
		printf("spin init fail\n");
		return 1;
	}
	if (sem_init(&sem, 0, 0) != 0) {
		printf("sem init fail\n");
		return 1;
	}
	pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;
	if (pthread_rwlock_rdlock(&rw) != 0 || pthread_rwlock_unlock(&rw) != 0) {
		printf("rwlock fail\n");
		return 1;
	}
	if (pthread_rwlock_wrlock(&rw) != 0 || pthread_rwlock_unlock(&rw) != 0) {
		printf("rwlock w fail\n");
		return 1;
	}
	pthread_t t1, t2;
	if (pthread_create(&t1, 0, worker, 0) != 0 || pthread_create(&t2, 0, worker, 0) != 0) {
		printf("create fail\n");
		return 1;
	}
	if (sem_wait(&sem) != 0 || sem_wait(&sem) != 0) {
		printf("sem wait fail\n");
		return 1;
	}
	int v = -1;
	if (sem_getvalue(&sem, &v) != 0 || v != 0) {
		printf("sem value fail %d\n", v);
		return 1;
	}
	int sr = pthread_barrier_wait(&bar);
	if (sr != 0 && sr != PTHREAD_BARRIER_SERIAL_THREAD) {
		printf("barrier fail %d\n", sr);
		return 1;
	}
	if (pthread_join(t1, 0) != 0 || pthread_join(t2, 0) != 0) {
		printf("join fail\n");
		return 1;
	}
	if (once_n != 1 || hits != 2) {
		printf("once/hits fail %d %d\n", once_n, hits);
		return 1;
	}
	thrd_t ct;
	int crc = -1;
	if (thrd_create(&ct, c11_fn, 0) != thrd_success || thrd_join(ct, &crc) != thrd_success
	    || crc != 7) {
		printf("c11 fail\n");
		return 1;
	}
	if (pthread_key_delete(key) != 0 || pthread_barrier_destroy(&bar) != 0
	    || pthread_spin_destroy(&spin) != 0 || sem_destroy(&sem) != 0
	    || pthread_rwlock_destroy(&rw) != 0) {
		printf("destroy fail\n");
		return 1;
	}
	printf("sync ok\n");
	return 0;
}
