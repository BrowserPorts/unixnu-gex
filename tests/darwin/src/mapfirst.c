// A file's private mapping reads the file's bytes on every access: the
// first touch of each page (the pmap enters it then) by any kind of load,
// scalar, pair, vector, and the string and copy routines that read ahead
// in 16 and 32 byte strides, including accesses that begin on a page
// already entered and end on one that is not, read what read(2) reads.
// The file is mapped as dyld maps an image: the whole file read-only
// first, then its segments over a reservation, a writable one fixed up
// (each word read, then written) in one tight loop and made read-only,
// then the first view unmapped. The loop's first touches of each page (a
// read, then a write) are faults in the middle of its body: the loop goes
// on from each with every register as the instruction left it, the ones
// the body writes after the faulting access included.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 0x4000UL
#define PAGES 24
#define SIZE (PAGES * PAGE)

static int bad(const char *what, long got, long want) {
    printf("mapfirst: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

static unsigned char *want;

// The file's contents: on each page, a NUL-terminated string at its start
// and nonzero bytes after it, so a string that starts near a page's end
// runs into the next page.
static void fill(unsigned char *b) {
    for (size_t i = 0; i < SIZE; i++) b[i] = (unsigned char)(0x21 + (i * 7 + i / PAGE) % 90);
    for (size_t p = 0; p < PAGES; p++) {
        b[p * PAGE + 40] = 0;
    }
}

// Every page of `m` (the file's bytes from `off`, `n` pages) read by the
// routines a program uses: each must read the file's bytes.
static int check(const unsigned char *m, size_t off, size_t n, const char *how) {
    char what[96];
    for (size_t p = 0; p < n; p++) {
        const unsigned char *pg = m + p * PAGE, *w = want + off + p * PAGE;
        // A string that starts 24 bytes before the page's end and runs
        // into the next page: begins on a page, ends on the next.
        if (p + 1 < n) {
            size_t len = strlen((const char *)pg + PAGE - 24), wl = strlen((const char *)w + PAGE - 24);
            snprintf(what, sizeof what, "%s: strlen across page %zu", how, p);
            if (len != wl) return bad(what, (long)len, (long)wl);
        }
        snprintf(what, sizeof what, "%s: strlen at page %zu", how, p);
        if (strlen((const char *)pg) != 40) return bad(what, (long)strlen((const char *)pg), 40);
        snprintf(what, sizeof what, "%s: strcmp at page %zu", how, p);
        if (strcmp((const char *)pg + 3, (const char *)w + 3) != 0) return bad(what, 1, 0);
        if (memcmp(pg, w, PAGE) != 0) {
            size_t i = 0;
            while (pg[i] == w[i]) i++;
            snprintf(what, sizeof what, "%s: page %zu's byte %#zx (of the word %#lx)", how, p, i, (unsigned long)*(const uint64_t *)(pg + (i & ~7UL)));
            return bad(what, pg[i], w[i]);
        }
        unsigned char copy[PAGE];
        memcpy(copy, pg + 8, PAGE - 8);
        snprintf(what, sizeof what, "%s: memcpy of page %zu", how, p);
        if (memcmp(copy, w + 8, PAGE - 8) != 0) return bad(what, 1, 0);
    }
    return 0;
}

struct job {
    const unsigned char *m;
    size_t off, n;
    int rc;
};

static void *reader(void *arg) {
    struct job *j = arg;
    j->rc = check(j->m, j->off, j->n, "a thread");
    return NULL;
}

int main(void) {
    char path[] = "/private/var/tmp/mapfirst.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return bad("mkstemp", errno, 0);
    want = malloc(SIZE);
    fill(want);
    if (write(fd, want, SIZE) != (ssize_t)SIZE) return bad("write", errno, 0);
    close(fd);
    fd = open(path, O_RDONLY);
    if (fd < 0) return bad("open", errno, 0);

    // The whole file, read-only, as dyld first looks at an image.
    unsigned char *view = mmap(NULL, SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (view == MAP_FAILED) return bad("mmap of the whole file", errno, 0);
    if (view[0] != want[0]) return bad("the view's first byte", view[0], want[0]);

    // The image's reservation, then its segments over it: text (16 pages,
    // read-only), data (8 pages, written then read-only).
    vm_address_t base = 0;
    if (vm_allocate(mach_task_self(), &base, SIZE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return bad("vm_allocate", 0, 0);
    unsigned char *text = mmap((void *)base, 16 * PAGE, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, 0);
    unsigned char *data = mmap((void *)(base + 16 * PAGE), 8 * PAGE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, 16 * PAGE);
    if (text == MAP_FAILED || data == MAP_FAILED) return bad("mmap of a segment", errno, 0);
    // Fixups, as dyld applies them: each word read, then written changed,
    // every 64 bytes of the data pages, in one loop (a page's first access
    // is the read, its first store the next, both in the loop's body).
    uint64_t slide = (uint64_t)(uintptr_t)text;
    for (size_t o = 48; o < 8 * PAGE; o += 64) {
        volatile uint64_t *w = (volatile uint64_t *)(data + o);
        *w = *w + slide;
    }
    for (size_t o = 48; o < 8 * PAGE; o += 64) {
        uint64_t f;
        memcpy(&f, want + 16 * PAGE + o, 8);
        f += slide;
        memcpy(want + 16 * PAGE + o, &f, 8);
    }
    if (mprotect(data, 8 * PAGE, PROT_READ) != 0) return bad("mprotect", errno, 0);
    if (munmap(view, SIZE) != 0) return bad("munmap of the view", errno, 0);

    // Text read by two threads at once, data by this one.
    struct job a = { text, 0, 8, 0 }, b = { text + 8 * PAGE, 8 * PAGE, 8, 0 };
    pthread_t ta, tb;
    pthread_create(&ta, NULL, reader, &a);
    pthread_create(&tb, NULL, reader, &b);
    int rc = check(data, 16 * PAGE, 8, "data");
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    if (rc || a.rc || b.rc) return 1;
    // Read again, every page entered now.
    if (check(text, 0, 16, "text again") || check(data, 16 * PAGE, 8, "data again")) return 1;
    unlink(path);
    printf("mapfirst ok\n");
    return 0;
}
