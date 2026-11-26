/* tso: the guest of test/page/tso.test.js. `tso-mp ROUNDS tear`: a
 * misaligned 8-byte word (offset 4 in a cache line, which x86 writes and
 * reads whole) is written all-zero or all-ones and read by the other
 * thread; any other value is a torn access. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define N 4096
/* One cache line per slot; volatile so the guest compiler keeps the order
 * (x86 compiles each to a plain mov). */
static volatile int data[N * 16], flag[N * 16];
static int go, done_;
static int rounds;
static long bad, seen;
static int tear;
static _Alignas(64) unsigned char line[64];
static volatile uint64_t *word(void) { return (volatile uint64_t *)(line + 4); }
static void barrier(int *w, int target) {
    __atomic_add_fetch(w, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(w, __ATOMIC_SEQ_CST) < target) { }
}
static void *writer(void *_) {
    for (int r = 0; r < rounds; r++) {
        int tag = r + 1;
        barrier(&go, 2 * (r + 1));
        if (tear) for (int i = 0; i < N * 4; i++) *word() = (i & 1) ? ~(uint64_t)0 : 0;
        else for (int i = 0; i < N; i++) { data[i * 16] = tag; flag[i * 16] = tag; }
        barrier(&done_, 2 * (r + 1));
    }
    return 0;
}
int main(int argc, char **argv) {
    rounds = atoi(argv[1]);
    tear = argc > 2 && !strcmp(argv[2], "tear");
    pthread_t t;
    pthread_create(&t, 0, writer, 0);
    for (int r = 0; r < rounds; r++) {
        int tag = r + 1;
        barrier(&go, 2 * (r + 1));
        if (tear) for (int i = 0; i < N * 4; i++) {
            uint64_t v = *word();
            seen++;
            if (v != 0 && v != ~(uint64_t)0) bad++;
        }
        else for (int i = 0; i < N; i++) {
            int f = flag[i * 16];
            int d = data[i * 16];
            if (f == tag) { seen++; if (d != tag) bad++; }
        }
        barrier(&done_, 2 * (r + 1));
    }
    pthread_join(t, 0);
    printf("mp %ld of %ld\n", bad, seen);
    return 0;
}
