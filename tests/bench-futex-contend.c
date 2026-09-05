/*
 * Contended-lock workload: what shape of futex traffic does a real thread pool
 * produce? Mutex ping-pong under genuine contention plus a condvar
 * producer/consumer, which between them are what glibc and musl locking
 * actually issue.
 */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static long shared;
static int ready;

static void *mutex_worker(void *arg)
{
    long n = (long) arg;
    for (long i = 0; i < n; i++) {
        pthread_mutex_lock(&mu);
        shared++;
        pthread_mutex_unlock(&mu);
    }
    return NULL;
}

static void *consumer(void *arg)
{
    long n = (long) arg;
    for (long i = 0; i < n; i++) {
        pthread_mutex_lock(&mu);
        while (!ready)
            pthread_cond_wait(&cv, &mu);
        ready = 0;
        pthread_cond_signal(&cv);
        pthread_mutex_unlock(&mu);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    int nthreads = argc > 2 ? atoi(argv[2]) : 4;
    pthread_t t[16];

    if (nthreads > 16)
        nthreads = 16;

    /* Checked, because a silent spawn failure makes this print a number that
     * looks like a result. The mutex phase would undercount shared and still
     * say "phase done", and the join below would be handed an indeterminate
     * pthread_t, which is undefined rather than merely wrong.
     */
    for (int i = 0; i < nthreads; i++) {
        int rc = pthread_create(&t[i], NULL, mutex_worker, (void *) iters);
        if (rc != 0) {
            fprintf(stderr, "pthread_create: %s\n", strerror(rc));
            return 1;
        }
    }
    for (int i = 0; i < nthreads; i++)
        pthread_join(t[i], NULL);
    fprintf(stderr, "mutex phase done, shared=%ld\n", shared);

    pthread_t c;
    int rc = pthread_create(&c, NULL, consumer, (void *) iters);
    if (rc != 0) {
        fprintf(stderr, "pthread_create: %s\n", strerror(rc));
        return 1;
    }
    for (long i = 0; i < iters; i++) {
        pthread_mutex_lock(&mu);
        while (ready)
            pthread_cond_wait(&cv, &mu);
        ready = 1;
        pthread_cond_signal(&cv);
        pthread_mutex_unlock(&mu);
    }
    pthread_join(c, NULL);
    fprintf(stderr, "condvar phase done\n");
    return 0;
}
