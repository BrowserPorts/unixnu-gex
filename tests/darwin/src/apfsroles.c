// APFS's lookups of the container's volumes, as launchd's libignition makes
// them: fsctl APFSIOC_GET_DEV_BY_ROLE on the root (the System volume, in no
// volume group: a lookup in a group is EINVAL, a `where` past 3 too, a role
// no volume has ENOENT; the device path of Preboot from outside any group,
// and of System itself), and sysctl vfs.generic.apfs.edt_fstab (its size
// from max_fs_entries, ENOMEM for less room, then an entry for each of the
// device tree's fstab volumes with its device, mount point, options with
// its type after them, and role).
//
// The device paths are the container's BSD name's, disk1 while the
// storage's units are unmeasured stand-ins.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

// Declared in a header the SDK leaves out.
extern int fsctl(const char *, unsigned long, void *, unsigned int);

#define APFSIOC_GET_DEV_BY_ROLE 0xc1044a50UL

struct dev_by_role {
    uint8_t where;
    uint8_t pad;
    uint16_t role;
    char dev[256];
};
_Static_assert(sizeof(struct dev_by_role) == 0x104, "the command's size");

static int bad(const char *what, long got, long want) {
    printf("apfsroles: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int lookup(uint8_t where, uint16_t role, struct dev_by_role *r) {
    memset(r, 0, sizeof *r);
    r->where = where;
    r->role = role;
    return fsctl("/", APFSIOC_GET_DEV_BY_ROLE, r, 0);
}

int main(void) {
    struct dev_by_role r;
    if (lookup(1, 0x10, &r) != -1 || errno != EINVAL) return bad("a lookup inside a volume group", errno, EINVAL);
    if (lookup(0, 0x10, &r) != -1 || errno != EINVAL) return bad("where 0", errno, EINVAL);
    if (lookup(4, 0x10, &r) != -1 || errno != EINVAL) return bad("where 4", errno, EINVAL);
    if (lookup(2, 0x200, &r) != -1 || errno != ENOENT) return bad("the Scratch role", errno, ENOENT);
    printf("apfsroles errors ok\n");
    if (lookup(2, 0x10, &r) != 0) return bad("Preboot's device", errno, 0);
    printf("preboot %s\n", r.dev);
    if (lookup(3, 0x1, &r) != 0) return bad("System's device", errno, 0);
    printf("system %s\n", r.dev);
    fflush(stdout);

    // sysctlbyname asks for the name's numbers first (sysctl.name2oid).
    size_t len = 0;
    if (sysctlbyname("vfs.generic.apfs.edt_fstab", NULL, &len, NULL, 0) != 0 || len != 7 * 0xec) return bad("edt_fstab's size", (long)len, 7 * 0xec);
    unsigned char fstab[0x938];
    len = 7 * 0xec - 1;
    if (sysctlbyname("vfs.generic.apfs.edt_fstab", fstab, &len, NULL, 0) != -1 || errno != ENOMEM) return bad("edt_fstab short of room", errno, ENOMEM);
    len = sizeof fstab;
    if (sysctlbyname("vfs.generic.apfs.edt_fstab", fstab, &len, NULL, 0) != 0 || len % 0xec != 0) return bad("edt_fstab", errno, 0);
    for (size_t at = 0; at < len; at += 0xec) {
        const unsigned char *e = fstab + at;
        uint32_t role;
        memcpy(&role, e + 0xe8, 4);
        printf("%s %s %s %s %#x\n", (const char *)e, (const char *)e + 0x20, (const char *)e + 0x60, (const char *)e + 0x80, role);
    }
    return 0;
}
