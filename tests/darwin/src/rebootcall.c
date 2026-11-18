// reboot(2) and host_reboot: a caller without root is refused (suser's
// EPERM, before its message is read), and host_reboot through the
// unprivileged host port converts to no host (KERN_INVALID_HOST); then
// "rebootcall ok". As root, with a mode: "panic" (RB_PANIC|RB_QUICK and a
// message) is refused too, the platform profile's system-reboot allowing
// RB_PANIC to initproc alone (EPERM, "rebootcall panic refused"); "halt"
// (RB_HALT|RB_QUICK), "restart" (RB_QUICK) and "hostrestart" (host_reboot
// on the privileged host port) end the system.

#include <errno.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define RB_HALT 0x08
#define RB_QUICK 0x400
#define RB_PANIC 0x800

int reboot(int howto);
int reboot_np(int howto, const char *message);

static int bad(const char *what, long got, long want) {
    printf("rebootcall: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(int argc, char **argv) {
    if (argc == 1) {
        if (getuid() == 0) return bad("uid", 0, 501);
        errno = 0;
        if (reboot(RB_HALT | RB_QUICK) != -1 || errno != EPERM) return bad("reboot as a user", errno, EPERM);
        errno = 0;
        // The message is not read: an address nothing is at is no fault.
        if (reboot_np(RB_PANIC | RB_QUICK, (const char *)8) != -1 || errno != EPERM) return bad("reboot_np as a user", errno, EPERM);
        kern_return_t kr = host_reboot(mach_host_self(), 0);
        if (kr != KERN_INVALID_HOST) return bad("host_reboot on the host port", kr, KERN_INVALID_HOST);
        puts("rebootcall ok");
        return 0;
    }
    const char *mode = argv[1];
    int r = -1;
    if (!strcmp(mode, "panic")) {
        errno = 0;
        if (reboot_np(RB_PANIC | RB_QUICK, "gex rebootcall panic") != -1 || errno != EPERM) return bad("RB_PANIC from a process not initproc", errno, EPERM);
        puts("rebootcall panic refused");
        return 0;
    }
    if (!strcmp(mode, "halt")) r = reboot(RB_HALT | RB_QUICK);
    if (!strcmp(mode, "restart")) r = reboot(RB_QUICK);
    if (!strcmp(mode, "hostrestart")) {
        mach_port_t priv = MACH_PORT_NULL;
        kern_return_t kr = host_get_host_priv_port(mach_host_self(), &priv);
        if (kr != KERN_SUCCESS) return bad("host_get_host_priv_port", kr, KERN_SUCCESS);
        kr = host_reboot(priv, 0);
        return bad("host_reboot returned", kr, 0);
    }
    return bad("the call returned", r == -1 ? errno : r, 0);
}
