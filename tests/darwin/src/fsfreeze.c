// F_FREEZE_FS and F_THAW_FS on an APFS mount (APFS's apfs_vnop_ioctl):
// the superuser or the mount's owner only, the freezing process alone
// thaws, and on the volume it froze.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("fsfreeze: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

int main(void) {
    int r = open("/", O_RDONLY);
    if (r < 0) return bad("open /", errno, 0);
    // Nothing frozen: nothing to thaw.
    if (fcntl(r, F_THAW_FS) == 0 || errno != EINVAL) return bad("thawing an unfrozen volume", errno, EINVAL);
    if (fcntl(r, F_FREEZE_FS)) return bad("freezing /", errno, 0);
    // Another process cannot thaw it.
    pid_t pid = fork();
    if (pid == 0) _exit(fcntl(r, F_THAW_FS) == 0 ? 1 : errno == EINVAL ? 0 : 2);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || st != 0) return bad("a child's thaw", st, 0);
    if (fcntl(r, F_THAW_FS)) return bad("thawing /", errno, 0);
    if (fcntl(r, F_THAW_FS) == 0 || errno != EINVAL) return bad("thawing twice", errno, EINVAL);
    // A descriptor that is not a vnode.
    int p[2];
    if (pipe(p)) return bad("pipe", errno, 0);
    if (fcntl(p[0], F_FREEZE_FS) == 0 || errno != EBADF) return bad("freezing a pipe", errno, EBADF);
    // Not the superuser and not the owner (root's mount).
    if (setuid(501)) return bad("setuid", errno, 0);
    if (fcntl(r, F_FREEZE_FS) == 0 || errno != EACCES) return bad("freezing as a user", errno, EACCES);
    printf("fsfreeze ok\n");
    return 0;
}
