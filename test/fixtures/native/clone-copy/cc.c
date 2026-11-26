/* A whole-file copy_file_range in the kernel's file system shares the bytes:
 * 170 MiB copied adds about nothing to what the file system holds (Shmem in
 * /proc/meminfo), and every later change stays in the file it was made to:
 * a write to either, a truncation down and up again, the source renamed
 * and deleted, a copy of a copy. Prints each measure and "ok", or what was
 * wrong. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LEN (170L << 20)

static long shmem_kib(void)
{
    char buf[4096];
    int fd = open("/proc/meminfo", O_RDONLY);
    long n = fd < 0 ? -1 : read(fd, buf, sizeof(buf) - 1);
    char *p;
    if (fd >= 0) close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    if (!(p = strstr(buf, "Shmem:"))) return -1;
    return strtol(p + 6, NULL, 10);
}

/* the directory the files are made in (argv[1], else /tmp) */
static const char *dir = "/tmp";

static const char *P(const char *name)
{
    static char bufs[4][256];
    static int at;
    char *b = bufs[at++ % 4];
    snprintf(b, sizeof(bufs[0]), "%s/%s", dir, name);
    return b;
}

static unsigned char pat(long i) { return (unsigned char)(i * 7 + (i >> 16)); }

static int fail(const char *what)
{
    printf("FAIL %s\n", what);
    return 1;
}

/* the file at `path` is `len` bytes of the pattern but for `n` bytes
 * `with` at `at` and zeros from `zero` on */
static int check(const char *path, long len, long at, const char *with, long zero)
{
    static unsigned char buf[1 << 20];
    long n = with ? (long)strlen(with) : 0, off = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0 || lseek(fd, 0, SEEK_END) != len) { if (fd >= 0) close(fd); return 0; }
    lseek(fd, 0, SEEK_SET);
    while (off < len)
    {
        long got = read(fd, buf, sizeof(buf)), i;
        if (got <= 0) { close(fd); return 0; }
        for (i = 0; i < got; i++)
        {
            long k = off + i;
            unsigned char want = k >= zero ? 0 : (k >= at && k < at + n) ? (unsigned char)with[k - at] : pat(k);
            if (buf[i] != want) { close(fd); printf("  %s: byte %ld is %u, not %u\n", path, k, buf[i], want); return 0; }
        }
        off += got;
    }
    close(fd);
    return 1;
}

static long copy(const char *from, const char *to)
{
    int in = open(from, O_RDONLY), out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    long done = 0, n;
    if (in < 0 || out < 0) return -1;
    while ((n = copy_file_range(in, NULL, out, NULL, LEN * 2, 0)) > 0) done += n;
    close(in);
    close(out);
    return n < 0 ? -1 : done;
}

static int put(const char *path, long at, const char *s)
{
    int fd = open(path, O_WRONLY);
    int ok = fd >= 0 && pwrite(fd, s, strlen(s), at) == (ssize_t)strlen(s);
    if (fd >= 0) close(fd);
    return ok;
}

int main(int argc, char **argv)
{
    static unsigned char buf[1 << 20];
    long i, start, before, after, k;
    int fd;

    if (argc > 1) dir = argv[1];
    start = shmem_kib();
    fd = open(P("cc-a"), O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd < 0) return fail("open cc-a");
    for (k = 0; k < LEN; k += sizeof(buf))
    {
        for (i = 0; i < (long)sizeof(buf); i++) buf[i] = pat(k + i);
        if (write(fd, buf, sizeof(buf)) != sizeof(buf)) return fail("write cc-a");
    }
    close(fd);

    before = shmem_kib();
    if (before < 0) return fail("no Shmem in /proc/meminfo");
    if (copy(P("cc-a"), P("cc-b")) != LEN) return fail("copy_file_range a -> b");
    after = shmem_kib();
    printf("copy added %ld KiB (Shmem %ld -> %ld KiB)\n", after - before, before, after);
    if (!check(P("cc-b"), LEN, 0, NULL, LEN)) return fail("b is a's bytes");

    /* a write to the copy, across a 64 KiB boundary, then to the source */
    if (!put(P("cc-b"), 65534, "COPY")) return fail("write b");
    if (!check(P("cc-b"), LEN, 65534, "COPY", LEN)) return fail("b has its write");
    if (!check(P("cc-a"), LEN, 0, NULL, LEN)) return fail("a without b's write");
    if (!put(P("cc-a"), 5, "SRC")) return fail("write a");
    if (!check(P("cc-a"), LEN, 5, "SRC", LEN)) return fail("a has its write");
    if (!check(P("cc-b"), LEN, 65534, "COPY", LEN)) return fail("b without a's write");
    printf("writes added %ld KiB\n", shmem_kib() - after);

    /* a copy of the copy; the source renamed and deleted */
    if (copy(P("cc-b"), P("cc-c")) != LEN) return fail("copy_file_range b -> c");
    if (rename(P("cc-a"), P("cc-a2")) || unlink(P("cc-a2"))) return fail("rename and unlink a");
    if (!check(P("cc-b"), LEN, 65534, "COPY", LEN)) return fail("b after a went");
    if (!check(P("cc-c"), LEN, 65534, "COPY", LEN)) return fail("c is b's bytes");

    /* truncation of b down and up: zeros where it was cut, c as it was */
    if (truncate(P("cc-b"), 65535) || truncate(P("cc-b"), LEN)) return fail("truncate b");
    if (!check(P("cc-b"), LEN, 65534, "C", 65535)) return fail("b truncated");
    if (!check(P("cc-c"), LEN, 65534, "COPY", LEN)) return fail("c after b's truncation");

    /* O_TRUNC of c and b: nothing left of either */
    close(open(P("cc-c"), O_WRONLY | O_TRUNC));
    unlink(P("cc-b"));
    unlink(P("cc-c"));
    printf("after both went: Shmem %ld KiB (at the start %ld)\n", shmem_kib(), start);
    printf("ok\n");
    return 0;
}
