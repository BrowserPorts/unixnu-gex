// graftdmg and ungraftdmg, as far as a graft goes before AppleImage4
// evaluates its payload. graftdmg: the entitlement (EPERM), the arguments
// copied in (EFAULT), the directory looked up, the image's descriptor
// (EBADF, ENOTSUP for no vnode's), the graft type (EINVAL); then the
// arguments' version (ENOTSUP), the image and the directory on one mount
// (EXDEV), the directory one (ENOTDIR), a manifest and a payload
// descriptor (EINVAL), each read whole whatever it was opened for (none:
// ENODATA, past 16384 bytes: EFBIG). APFS: the superuser (EACCES), the
// Preboot role to keep the volume mounted (ENOTSUP on the System volume),
// and a payload type the graft type does not take, which fails the
// evaluation but not the graft: the image must still be a regular file
// (ENODEV) with something in it (EINVAL). ungraftdmg: no flags and a
// directory (EINVAL), devfs's ENOTSUP, root (EACCES), and EINVAL for a
// directory with no graft.
//
// With no argument the program runs as root; "user" runs it as someone
// else, and "noent" is the program without the entitlement.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct sbc {
    uint32_t version;
    uint32_t fourcc;
    int manifest;
    int user_manifest;
    int payload;
    uint64_t flags;
} __attribute__((aligned(4), packed));

union gda {
    uint8_t max[512];
    struct sbc sbc;
};

#define CC(a, b, c, d) ((uint32_t)(a) << 24 | (uint32_t)(b) << 16 | (uint32_t)(c) << 8 | (uint32_t)(d))

static int graft(int fd, const char *dir, uint32_t type, union gda *g) {
    return syscall(549, fd, dir, type, g);
}

static int ungraft(const char *dir, uint64_t flags) {
    return syscall(555, dir, flags);
}

static const char *what;

static int expect(const char *step, int r, int want) {
    if (r != -1 || errno != want) {
        printf("graftdmg %s: %s: %d errno %d, want errno %d\n", what, step, r, r == -1 ? errno : 0, want);
        fflush(stdout);
        return 1;
    }
    return 0;
}

// A file of `n` bytes, open as `flags`.
static int file(const char *path, size_t n, int flags) {
    unlink(path);
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0644);
    if (fd < 0) return -1;
    static char buf[16385];
    memset(buf, 0x5a, sizeof buf);
    if (n && write(fd, buf, n) != (ssize_t)n) return -1;
    close(fd);
    return open(path, flags);
}

static union gda args(int manifest, int payload, uint32_t cc, uint64_t flags) {
    union gda g;
    memset(&g, 0, sizeof g);
    g.sbc = (struct sbc){1, cc, manifest, -1, payload, flags};
    return g;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "root";
    what = mode;
    char dir[128], dmg[128], im4m[128], hash[128], empty[128], big[128], full[128];
    snprintf(dir, sizeof dir, "/private/var/tmp/gex-graft.%d", getpid());
    if (mkdir(dir, 0755) != 0) return expect("mkdir", -1, 0);
    snprintf(dmg, sizeof dmg, "%s/os.dmg", dir);
    snprintf(im4m, sizeof im4m, "%s/apticket.im4m", dir);
    snprintf(hash, sizeof hash, "%s/os.dmg.root_hash", dir);
    snprintf(empty, sizeof empty, "%s/empty", dir);
    snprintf(big, sizeof big, "%s/big", dir);
    snprintf(full, sizeof full, "%s/full", dir);
    int d = file(dmg, 0, O_RDONLY);
    int m = file(im4m, 25, O_RDONLY);
    int p = file(hash, 229, O_RDONLY);
    int e = file(empty, 0, O_RDONLY);
    int b = file(big, 16385, O_RDONLY);
    int f = file(full, 16384, O_WRONLY);
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY);
    int pipes[2];
    if (d < 0 || m < 0 || p < 0 || e < 0 || b < 0 || f < 0 || dirfd < 0 || pipe(pipes) != 0) return expect("setup", -1, 0);
    union gda os = args(m, p, CC('c', 's', 's', 'y'), 0x2d);
    int bad = 0;

    if (strcmp(mode, "noent") == 0) {
        bad |= expect("graftdmg", graft(d, dir, 1, &os), EPERM);
        bad |= expect("ungraftdmg", ungraft(dir, 0), EPERM);
    } else if (strcmp(mode, "user") == 0) {
        bad |= expect("not root", graft(d, dir, 1, &os), EACCES);
        bad |= expect("ungraft, not root", ungraft(dir, 0), EACCES);
    } else {
        bad |= expect("no arguments", graft(d, dir, 1, NULL), EFAULT);
        bad |= expect("no directory", graft(-1, "/private/var/tmp/gex-graft-none", 1, &os), ENOENT);
        bad |= expect("no image", graft(-1, dir, 1, &os), EBADF);
        bad |= expect("a pipe for an image", graft(pipes[0], dir, 1, &os), ENOTSUP);
        bad |= expect("type 0", graft(d, dir, 0, &os), EINVAL);
        bad |= expect("type 8", graft(d, dir, 8, &os), EINVAL);
        union gda g = os;
        g.sbc.version = 2;
        bad |= expect("version 2", graft(d, dir, 1, &g), ENOTSUP);
        bad |= expect("another mount", graft(d, "/dev", 1, &os), EXDEV);
        bad |= expect("onto a file", graft(d, dmg, 1, &os), ENOTDIR);
        g = args(-1, p, CC('c', 's', 's', 'y'), 0x2d);
        bad |= expect("no manifest", graft(d, dir, 1, &g), EINVAL);
        g = args(m, -1, CC('c', 's', 's', 'y'), 0x2d);
        bad |= expect("no payload", graft(d, dir, 1, &g), EINVAL);
        g = args(999, p, CC('c', 's', 's', 'y'), 0x2d);
        bad |= expect("a closed manifest", graft(d, dir, 1, &g), EBADF);
        g = args(pipes[0], p, CC('c', 's', 's', 'y'), 0x2d);
        bad |= expect("a pipe for a manifest", graft(d, dir, 1, &g), ENOTSUP);
        g = args(e, p, CC('c', 's', 's', 'y'), 0x2d);
        bad |= expect("an empty manifest", graft(d, dir, 1, &g), ENODATA);
        g = args(b, p, CC('c', 's', 's', 'y'), 0x2d);
        bad |= expect("a manifest too big", graft(d, dir, 1, &g), EFBIG);
        g = args(f, e, CC('c', 's', 's', 'y'), 0x2d);
        bad |= expect("an empty payload", graft(d, dir, 1, &g), ENODATA);
        // The largest manifest, from a descriptor open only to write: read,
        // and APFS keeps no System volume mounted until shutdown.
        g = args(f, p, CC('c', 's', 's', 'y'), 0x2d);
        bad |= expect("kept mounted", graft(d, dir, 1, &g), ENOTSUP);
        // A payload type the graft type does not take: the graft goes on
        // without an authenticated payload.
        g = args(m, p, CC('a', 'b', 'c', 'd'), 0x2e);
        bad |= expect("a directory for an image", graft(dirfd, dir, 1, &g), ENODEV);
        bad |= expect("a directory, its own", graft(dirfd, NULL, 1, &g), ENODEV);
        bad |= expect("an empty image", graft(d, dir, 1, &g), EINVAL);
        g = args(m, p, CC('c', 's', 's', 'y'), 0x2e);
        bad |= expect("cssy as type 4", graft(d, dir, 4, &g), EINVAL);
        bad |= expect("ungraft nothing", ungraft(NULL, 0), EINVAL);
        bad |= expect("ungraft with flags", ungraft(dir, 1), EINVAL);
        bad |= expect("ungraft no directory", ungraft("/private/var/tmp/gex-graft-none", 0), ENOENT);
        bad |= expect("ungraft devfs", ungraft("/dev", 0), ENOTSUP);
        bad |= expect("ungraft no graft", ungraft(dir, 0), EINVAL);
    }

    unlink(dmg);
    unlink(im4m);
    unlink(hash);
    unlink(empty);
    unlink(big);
    unlink(full);
    rmdir(dir);
    if (bad) return 1;
    printf("graftdmg %s ok\n", mode);
    return 0;
}
