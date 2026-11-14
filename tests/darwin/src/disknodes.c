// The disks' nodes IOMediaBSDClient makes in /dev: for each medium a block
// node disk<unit><slice> and a character node rdisk<unit><slice>, both
// makedev(1, minor) (devsw_add(-1)'s slot, the first free in both switches
// when IOStorageFamily starts), owned by root:operator with mode 0640, made
// after the pseudo-devices' nodes in the order the media took their
// minors, the block node first. A block node's block size is
// BLKDEV_IOSIZE, a character node's MAXPHYSIO.
//
// The unit numbers and the minors' order are the storage's unmeasured
// stand-ins: disk0 and its partition, the container disk1, its volumes by
// slot.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("disknodes: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

// The entries of /dev: each one's number and type, by name.
static int entry(const char *name, ino_t *ino, int *type) {
    DIR *d = opendir("/dev");
    if (!d) return -1;
    struct dirent *e;
    int found = -1;
    while ((e = readdir(d)))
        if (!strcmp(e->d_name, name)) {
            *ino = e->d_ino;
            *type = e->d_type;
            found = 0;
        }
    closedir(d);
    return found;
}

int main(void) {
    struct statfs fs;
    if (statfs("/dev", &fs)) return bad("statfs", errno, 0);
    const char *media[] = {"disk0", "disk0s1", "disk1", "disk1s1", "disk1s2", "disk1s3", "disk1s4", "disk1s5", "disk1s6", "disk1s7"};
    // The node made before the disks': urandom, the last pseudo-device's
    // (whose own device number is the boot's, not looked at here).
    ino_t prev;
    int type;
    if (entry("urandom", &prev, &type)) return bad("urandom's entry", errno, 0);
    struct stat st;
    for (int i = 0; i < 10; i++) {
        char path[64];
        for (int r = 0; r < 2; r++) {
            snprintf(path, sizeof path, "/dev/%s%s", r ? "r" : "", media[i]);
            if (stat(path, &st)) return bad(path, errno, 0);
            int want = r ? S_IFCHR : S_IFBLK;
            if (st.st_mode != (want | 0640)) return bad(path, st.st_mode, want | 0640);
            if (st.st_uid != 0 || st.st_gid != 5) return bad("a disk's owner", st.st_gid, 5);
            if (major(st.st_rdev) != 1 || minor(st.st_rdev) != i) return bad(path, (long)st.st_rdev, makedev(1, i));
            if (st.st_blksize != (r ? 64 * 1024 : 2048)) return bad("a disk's block size", st.st_blksize, r ? 64 * 1024 : 2048);
            if (st.st_size || st.st_blocks || st.st_nlink != 1) return bad("a disk's size", (long)st.st_size, 0);
            if (st.st_dev != (dev_t)fs.f_fsid.val[0]) return bad("a disk's device", st.st_dev, fs.f_fsid.val[0]);
            if (st.st_ino != prev + 1) return bad("a disk's number", (long)st.st_ino, (long)prev + 1);
            ino_t ino;
            if (entry(path + 5, &ino, &type) || ino != st.st_ino) return bad("a disk's entry", (long)ino, (long)st.st_ino);
            if (type != (r ? DT_CHR : DT_BLK)) return bad("a disk's entry's type", type, r ? DT_CHR : DT_BLK);
            prev = st.st_ino;
        }
    }
    if (stat("/dev/disk1s8", &st) == 0 || errno != ENOENT) return bad("a volume the container has not", errno, ENOENT);

    // Someone not in operator has no access.
    if (getuid() == 0 && (setgid(20) || setuid(501))) return bad("setuid", errno, 0);
    if (open("/dev/disk1s5", O_RDONLY) >= 0 || errno != EACCES) return bad("open by another", errno, EACCES);
    if (open("/dev/rdisk0", O_RDONLY) >= 0 || errno != EACCES) return bad("open by another", errno, EACCES);
    printf("disknodes ok\n");
    return 0;
}
