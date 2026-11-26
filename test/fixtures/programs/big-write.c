/* write(2) with a count far past its small buffer, and writes far past a
 * file's end: each gives a count or an error, never kills the kernel. The
 * kernel is wasm32, so a guest's length or offset is wider than its
 * `usize`: a write of 1286 bytes far past a file's end grew the file's block
 * list past what a Vec can hold (a "capacity overflow" panic in the global
 * kernel, which took every process with it), and a write past 4 GiB of an
 * in-memory file wrapped to its start. core/big-write runs this as each
 * ABI's program (x86-64 and aarch64, static) and as wasm32 (rt-bigwrite).
 *
 *   big-write DIR   prints one line a case and "big-write ok" */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>

static int bad;

static void counted(const char *what, int fd, size_t count) {
    static char small[16] = "0123456789abcdef";
    errno = 0;
    ssize_t n = write(fd, small, count);
    /* EFAULT (or, as Linux does, the bytes written before the fault) */
    int ok = n < 0 ? errno == EFAULT : (size_t)n <= count;
    printf("%s: %s\n", what, n < 0 ? strerror(errno) : ok ? "a count" : "too many");
    bad |= !ok;
}

static void far(const char *dir, const char *what, int64_t off) {
    char p[256], buf[1286], got[1286] = {0}, head[5] = {0};
    snprintf(p, sizeof p, "%s/big-write.tmp", dir);
    int f = open(p, O_RDWR | O_CREAT | O_TRUNC, 0644);
    write(f, "head", 4);
    memset(buf, 'x', sizeof buf);
    errno = 0;
    ssize_t n = pwrite(f, buf, sizeof buf, off);
    const char *r;
    if (n < 0) {
        /* too big for this file system, or no room for it */
        r = errno == EFBIG || errno == ENOSPC || errno == EINVAL ? "refused" : "wrong error";
        bad |= *r == 'w';
    } else {
        struct stat st;
        pread(f, got, sizeof got, off);
        pread(f, head, 4, 0);
        fstat(f, &st);
        /* the length too: a write wrapped to 32 bits reads back from where
         * it landed, but leaves the file short */
        r = n == (ssize_t)sizeof buf && !memcmp(got, buf, sizeof buf) && !strcmp(head, "head") && st.st_size == off + (off_t)sizeof buf ? "there" : "elsewhere";
        bad |= *r == 'e';
    }
    printf("%s past the end: %s\n", what, r);
    close(f);
    unlink(p);
}

/* the same on a memfd, and its length set far out */
static void memfd(const char *what, int64_t off) {
    char buf[1286], got[1286] = {0};
    int f = memfd_create("big-write", 0);
    memset(buf, 'y', sizeof buf);
    errno = 0;
    ssize_t n = pwrite(f, buf, sizeof buf, off);
    const char *r;
    if (n < 0) {
        r = errno == EFBIG || errno == ENOSPC || errno == EINVAL ? "refused" : "wrong error";
    } else {
        struct stat st;
        pread(f, got, sizeof got, off);
        fstat(f, &st);
        r = n == (ssize_t)sizeof buf && !memcmp(got, buf, sizeof buf) && st.st_size == off + (off_t)sizeof buf ? "there" : "elsewhere";
    }
    bad |= *r == 'w' || *r == 'e';
    errno = 0;
    int t = ftruncate(f, off);
    int tok = t == 0 || errno == EFBIG || errno == ENOSPC || errno == EINVAL;
    bad |= !tok;
    printf("memfd %s: write %s, ftruncate %s\n", what, r, t == 0 ? "done" : tok ? "refused" : "wrong error");
    close(f);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    int pf[2], nul = open("/dev/null", O_WRONLY);
    char p[256];
    snprintf(p, sizeof p, "%s/big-write.cnt", dir);
    int f = open(p, O_RDWR | O_CREAT | O_TRUNC, 0644);
    pipe(pf);
    fcntl(pf[1], F_SETFL, O_NONBLOCK);
    const size_t counts[] = {SIZE_MAX, SIZE_MAX / 2, (size_t)1 << 31, (size_t)UINT32_MAX};
    for (int i = 0; i < 4; i++) {
        char w[64];
        snprintf(w, sizeof w, "count %d to a file", i);
        counted(w, f, counts[i]);
        snprintf(w, sizeof w, "count %d to a pipe", i);
        counted(w, pf[1], counts[i]);
        snprintf(w, sizeof w, "count %d to /dev/null", i);
        counted(w, nul, counts[i]);
    }
    close(f);
    unlink(p);
    far(dir, "2 GiB", (int64_t)1 << 31);
    far(dir, "4 GiB", ((int64_t)1 << 32) + 100);
    far(dir, "5 GiB", ((int64_t)5 << 30) + 100);
    far(dir, "2 TiB", (int64_t)1 << 41);
    /* with 64 KiB blocks (an OPFSFilesystem's), block 2^30 and block
     * 2^32 + 2^29: a block list of 4 GiB, or one whose number wraps to 32
     * bits onto 2 GiB of list */
    far(dir, "64 TiB", (int64_t)1 << 46);
    far(dir, "2^48 + 2^45", ((int64_t)1 << 48) + ((int64_t)1 << 45));
    far(dir, "2^62", (int64_t)1 << 62);
    memfd("2 GiB", (int64_t)1 << 31);
    memfd("4 GiB", ((int64_t)1 << 32) + 100);
    memfd("2^62", (int64_t)1 << 62);
    /* readv with one vector far longer than its buffer */
    {
        static char small[16];
        char p2[256];
        snprintf(p2, sizeof p2, "%s/big-write.rv", dir);
        int g = open(p2, O_RDWR | O_CREAT | O_TRUNC, 0644);
        write(g, "readv", 5);
        lseek(g, 0, SEEK_SET);
        struct iovec v = {small, (size_t)-1 / 2};
        errno = 0;
        ssize_t n = readv(g, &v, 1);
        int ok = n == 5 || (n < 0 && errno == EFAULT) || (n < 0 && errno == EINVAL);
        bad |= !ok;
        printf("readv a huge vector: %s\n", n >= 0 ? "a count" : strerror(errno));
        close(g);
        unlink(p2);
    }
    puts(bad ? "big-write FAILED" : "big-write ok");
    return bad;
}
