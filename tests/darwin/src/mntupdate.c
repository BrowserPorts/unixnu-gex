// mount(2)'s update of a mount, by the rules of __mac_mount and
// mount_common: a type name longer than MFSNAMELEN is ENAMETOOLONG, a
// path that is not there ENOENT, MNT_UNION EPERM (no union mounts on a
// release kernel); the root volume's root is always an update, and only
// a read-only one (EPERM); an update must name a mount's root (EINVAL);
// MNT_RELOAD of a writable mount is ENOTSUP; someone other than the
// mount's owner must be root (EPERM); then the MAC policies' check,
// Sandbox's file-mount-update, which the platform profile allows anyone.
// The root, which mount -P 1 has updated on a booted system, is nosuid,
// and that update again changes nothing; devfs's update takes the flags
// asked with MNT_NOSUID, which a release kernel adds to every update.
// It runs as root, as mount -P 1 does, and then as another user.

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

// The flags mount_common clears on an update and sets as asked.
#define SETTABLE (MNT_NOSUID | MNT_NOEXEC | MNT_NODEV | MNT_SYNCHRONOUS | MNT_UNION | MNT_ASYNC | MNT_UNKNOWNPERMISSIONS | \
                  MNT_DONTBROWSE | MNT_AUTOMOUNTED | MNT_DEFWRITE | MNT_NOATIME | MNT_STRICTATIME | MNT_QUARANTINE | MNT_CPROTECT)

static int bad(const char *what, long got, long want) {
    printf("mntupdate: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int expect(const char *what, int r, int want) {
    if (r != -1 || errno != want) return bad(what, r == -1 ? errno : 0, want);
    return 0;
}

static long flags_of(const char *path) {
    struct statfs s;
    if (statfs(path, &s)) return -1;
    return (long)s.f_flags;
}

int main(void) {
    char args[0x14c] = {0};
    long root = flags_of("/"), dev = flags_of("/dev");
    if (root < 0 || dev < 0) return bad("statfs", errno, 0);
    if (!(root & MNT_NOSUID)) return bad("the root's MNT_NOSUID", root, root | MNT_NOSUID);

    if (expect("a long type", mount("apfsapfsapfsapfs", "/", MNT_RDONLY, args), ENAMETOOLONG)) return 1;
    if (expect("no such directory", mount("apfs", "/private/var/tmp/mntupdate-none", MNT_UPDATE | MNT_RDONLY, args), ENOENT)) return 1;
    if (expect("MNT_UNION", mount("apfs", "/", MNT_RDONLY | MNT_UNION, args), EPERM)) return 1;
    if (expect("the root writable", mount("apfs", "/", 0, args), EPERM)) return 1;
    if (expect("the root writable, as an update", mount("apfs", "/", MNT_UPDATE, args), EPERM)) return 1;
    if (expect("no mount's root", mount("apfs", "/private/var/tmp", MNT_UPDATE | MNT_RDONLY, args), EINVAL)) return 1;
    if (expect("a writable mount's reload", mount("devfs", "/dev", MNT_UPDATE | MNT_RELOAD, args), ENOTSUP)) return 1;

    // The MAC policies are asked of root's updates, and the platform
    // profile allows file-mount-update. mount -P 1's update of the root,
    // again (read-only, no device named), leaves it as it is.
    if (mount("apfs", "/", MNT_UPDATE | MNT_RDONLY, args)) return bad("mount -P 1's update of the root", errno, 0);
    if (flags_of("/") != root) return bad("the root's flags after its update", flags_of("/"), root);
    // devfs's update sets what it asks and clears the rest it may set.
    long keep = dev & SETTABLE;
    if (mount("devfs", "/dev", MNT_UPDATE | MNT_NOEXEC | keep, args)) return bad("devfs's update", errno, 0);
    if (flags_of("/dev") != (dev | MNT_NOSUID | MNT_NOEXEC)) return bad("devfs's flags, noexec", flags_of("/dev"), dev | MNT_NOSUID | MNT_NOEXEC);
    if (mount("devfs", "/dev", MNT_UPDATE | keep, args)) return bad("devfs's update back", errno, 0);
    dev |= MNT_NOSUID;
    if (flags_of("/dev") != dev) return bad("devfs's flags, back", flags_of("/dev"), dev);

    // Someone other than the owner (the kernel's mounts are root's).
    if (getuid() == 0 && (setgid(20) || setuid(501))) return bad("setuid", errno, 0);
    if (expect("another's mount", mount("devfs", "/dev", MNT_UPDATE, args), EPERM)) return 1;
    if (expect("another's root", mount("apfs", "/", MNT_RDONLY, args), EPERM)) return 1;

    if (flags_of("/") != root) return bad("the root's flags after", flags_of("/"), root);
    if (flags_of("/dev") != dev) return bad("devfs's flags after", flags_of("/dev"), dev);
    printf("mntupdate ok\n");
    return 0;
}
