// AppleImage4's ignition blob, as an entitled task reads it: its size, the
// identity the device tree gives it (the IPSW's /chosen, which iBoot would
// fill in: zero), the secure boot level (0, no LocalPolicy), an empty long
// OS version, and the bytes the kext never writes. A write of a whole blob
// takes; a shorter one is refused. The failure blob refuses a short read
// and a short write.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

static int bad(const char *what, long got, long want) {
    printf("ignition: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(void) {
    size_t len = 0;
    if (sysctlbyname("security.mac.img4.ignition_blob", NULL, &len, NULL, 0) != 0 || len != 0x84) return bad("the blob's size", (long)len, 0x84);
    unsigned char b[0x84];
    memset(b, 0xaa, sizeof b);
    len = sizeof b;
    if (sysctlbyname("security.mac.img4.ignition_blob", b, &len, NULL, 0) != 0 || len != 0x84) return bad("the blob", errno, 0);
    uint64_t ecid;
    uint32_t level, chip;
    memcpy(&ecid, b + 0x12, 8);
    memcpy(&level, b + 0x2e, 4);
    memcpy(&chip, b + 0x0a, 4);
    if (b[0] || b[1] || b[0x82] || b[0x83]) return bad("the bytes never written", b[0] | b[1] | b[0x82] | b[0x83], 0);
    // A read with too little room fails whole.
    unsigned char small[8];
    len = sizeof small;
    errno = 0;
    if (sysctlbyname("security.mac.img4.ignition_blob", small, &len, NULL, 0) != -1 || errno != ENOMEM) return bad("a short read", errno, ENOMEM);
    // The node takes a new blob from a task that may read it.
    len = sizeof b;
    unsigned char old[0x84];
    if (sysctlbyname("security.mac.img4.ignition_blob", old, &len, b, sizeof b) != 0 || memcmp(old, b, sizeof b) != 0) return bad("writing the blob", errno, 0);
    errno = 0;
    if (sysctlbyname("security.mac.img4.ignition_blob", NULL, NULL, b, 8) != -1 || errno != EINVAL) return bad("a short write", errno, EINVAL);
    // The failure blob: any call its handler gets through writes NVRAM
    // (not modelled), so only the calls sysctl_handle_opaque fails: a read
    // with too little room, a write of less than the whole blob.
    errno = 0;
    len = sizeof small;
    if (sysctlbyname("security.mac.img4.ignition_failure_blob", small, &len, NULL, 0) != -1 || errno != ENOMEM) return bad("a short read of the failure blob", errno, ENOMEM);
    errno = 0;
    if (sysctlbyname("security.mac.img4.ignition_failure_blob", NULL, NULL, b, 8) != -1 || errno != EINVAL) return bad("a short write of the failure blob", errno, EINVAL);
    char target[64];
    len = sizeof target;
    if (sysctlbyname("hw.target", target, &len, NULL, 0) != 0) return bad("hw.target", errno, 0);
    printf("ignition %s ecid %llX chip %x level %u version \"%s\"\n", target, (unsigned long long)ecid, chip, level, (char *)b + 0x32);
    return 0;
}
