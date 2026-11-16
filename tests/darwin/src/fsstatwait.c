// getfsstat's and getfsstat64's flags: each mount's counts are refreshed
// before they are copied out (vfs_update_vfsstat) unless MNT_NOWAIT is
// asked alone; MNT_WAIT and MNT_DWAIT override it. devfs's counts grow with
// a new pty's node: a getfsstat with MNT_NOWAIT still has the ones the last
// refresh (a statfs of /dev) left, one with MNT_WAIT, MNT_DWAIT or no
// flags the new ones, which a later MNT_NOWAIT then has too. Without a
// buffer the mounts are counted, whatever the flags.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MNT_DWAIT 4

static int bad(const char *what, long got, long want) {
    printf("fsstatwait: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

// A raw system call (the library's getfsstat is getfsstat64's).
static long sys3(long n, long a, long b, long c) {
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c;
    register long x16 __asm__("x16") = n, cs __asm__("x9");
    __asm__ volatile("svc #0x80\n cset x9, cs" : "+r"(x0), "+r"(x1), "=r"(cs) : "r"(x2), "r"(x16) : "x3", "x4", "x5", "x6", "x7", "x8", "x10", "x11", "x12", "x13", "x14", "x15", "x17", "memory", "cc");
    if (cs) {
        errno = (int)x0;
        return -1;
    }
    return x0;
}

// devfs's f_files as getfsstat64 (SYS_getfsstat64) with `flags` gives it.
static long devfs_files64(int flags) {
    struct statfs all[64];
    int n = (int)sys3(SYS_getfsstat64, (long)all, (long)sizeof all, flags);
    for (int i = 0; i < n; i++)
        if (!strcmp(all[i].f_fstypename, "devfs")) return (long)all[i].f_files;
    return -1;
}

// The same by getfsstat (SYS_getfsstat), whose struct has 32-bit inodes
// and long counts.
struct statfs32 {
    short f_otype, f_oflags;
    long f_bsize, f_iosize, f_blocks, f_bfree, f_bavail, f_files, f_ffree;
    fsid_t f_fsid;
    uid_t f_owner;
    short f_reserved1, f_type;
    long f_flags, f_reserved2[2];
    char f_fstypename[15], f_mntonname[90], f_mntfromname[90];
    char f_reserved3;
    long f_reserved4[4];
};

static long devfs_files32(int flags) {
    struct statfs32 all[64];
    int n = (int)sys3(SYS_getfsstat, (long)all, (long)sizeof all, flags);
    for (int i = 0; i < n; i++)
        if (!strcmp(all[i].f_fstypename, "devfs")) return all[i].f_files;
    return -1;
}

int main(void) {
    if (sizeof(struct statfs32) != 336) return bad("sizeof(struct statfs32)", (long)sizeof(struct statfs32), 336);
    struct statfs fs;
    if (statfs("/dev", &fs)) return bad("statfs", errno, 0);
    long before = (long)fs.f_files;
    if (devfs_files64(MNT_NOWAIT) != before) return bad("getfsstat64 MNT_NOWAIT", devfs_files64(MNT_NOWAIT), before);

    // A new pty's replica node.
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) return bad("a pty", errno, 0);
    long n = sys3(SYS_getfsstat64, 0, 0, MNT_NOWAIT);
    if (n < 2 || sys3(SYS_getfsstat64, 0, 0, MNT_WAIT) != n || sys3(SYS_getfsstat, 0, 0, 0) != n) return bad("the count", n, 2);

    // Not refreshed: the counts the statfs left.
    if (devfs_files64(MNT_NOWAIT) != before) return bad("getfsstat64 MNT_NOWAIT after", devfs_files64(MNT_NOWAIT), before);
    if (devfs_files32(MNT_NOWAIT) != before) return bad("getfsstat MNT_NOWAIT after", devfs_files32(MNT_NOWAIT), before);
    // MNT_WAIT and MNT_DWAIT override MNT_NOWAIT.
    long after = devfs_files64(MNT_NOWAIT | MNT_WAIT);
    if (after <= before) return bad("getfsstat64 MNT_NOWAIT|MNT_WAIT", after, before + 1);
    if (devfs_files64(MNT_NOWAIT) != after) return bad("getfsstat64 MNT_NOWAIT, refreshed", devfs_files64(MNT_NOWAIT), after);
    if (devfs_files32(MNT_NOWAIT | MNT_DWAIT) != after || devfs_files32(0) != after || devfs_files64(MNT_DWAIT) != after) return bad("a refresh", devfs_files32(MNT_DWAIT), after);
    close(m);
    printf("fsstatwait ok\n");
    return 0;
}
