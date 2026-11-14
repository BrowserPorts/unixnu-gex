// fmount's checks before a filesystem is asked to mount: MNT_ROOTFS and
// MNT_IMGSRC_BY_INDEX are ENOTSUP, MNT_UNION EPERM, a type name longer
// than MFSNAMELEN ENAMETOOLONG, a descriptor that is no vnode's EINVAL, a
// volume's root (or what is mounted on) EBUSY; then mount_common's
// prepare_coveredvp: someone other than root must own the directory
// (EPERM), and it must be one (ENOTDIR). Nothing is mounted by any of
// them: the mount list stays as it was.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

// Declared in a header the SDK leaves out.
extern int fmount(const char *, int, int, void *);

#define MNT_IMGSRC_BY_INDEX 0x20000000

static int bad(const char *what, long got, long want) {
    printf("fmount: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int expect(const char *what, int r, int want) {
    if (r != -1 || errno != want) return bad(what, r == -1 ? errno : 0, want);
    return 0;
}

int main(void) {
    int before = getfsstat(NULL, 0, MNT_NOWAIT);
    if (before < 2) return bad("getfsstat", before, 2);
    char args[0x14c] = {0};
    int root = open("/", O_RDONLY | O_DIRECTORY);
    int dev = open("/dev", O_RDONLY | O_DIRECTORY);
    int tmp = open("/private/var/tmp", O_RDONLY | O_DIRECTORY);
    if (root < 0 || dev < 0 || tmp < 0) return bad("open", errno, 0);
    int p[2];
    if (pipe(p)) return bad("pipe", errno, 0);

    if (expect("MNT_ROOTFS", fmount("apfs", tmp, MNT_ROOTFS, args), ENOTSUP)) return 1;
    if (expect("MNT_IMGSRC_BY_INDEX", fmount("apfs", tmp, MNT_IMGSRC_BY_INDEX, args), ENOTSUP)) return 1;
    if (expect("MNT_UNION", fmount("apfs", tmp, MNT_UNION, args), EPERM)) return 1;
    if (expect("a long type", fmount("apfsapfsapfsapfs", tmp, 0, args), ENAMETOOLONG)) return 1;
    if (expect("a bad descriptor", fmount("apfs", 1000, 0, args), EBADF)) return 1;
    if (expect("a pipe", fmount("apfs", p[0], 0, args), EINVAL)) return 1;
    if (expect("the root", fmount("apfs", root, 0, args), EBUSY)) return 1;
    if (expect("devfs's root", fmount("apfs", dev, 0, args), EBUSY)) return 1;

    // A file that is no directory.
    char path[64];
    snprintf(path, sizeof path, "/private/var/tmp/fmount-%d", getpid());
    int f = open(path, O_RDWR | O_CREAT | O_EXCL, 0644);
    if (f < 0) return bad("creat", errno, 0);
    if (expect("a file", fmount("apfs", f, 0, args), ENOTDIR)) return 1;
    close(f);
    unlink(path);

    // Someone other than root on a directory of root's.
    if (getuid() == 0 && (setgid(20) || setuid(501))) return bad("setuid", errno, 0);
    if (expect("another's directory", fmount("apfs", tmp, 0, args), EPERM)) return 1;

    if (getfsstat(NULL, 0, MNT_NOWAIT) != before) return bad("the mounts after", getfsstat(NULL, 0, MNT_NOWAIT), before);
    printf("fmount ok\n");
    return 0;
}
