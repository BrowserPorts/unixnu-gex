// gethostuuid (call 142) and the platform's UUID it reads: the platform
// expert device's IOPlatformUUID, which IOResources publishes under the
// same key. argv[1] is the UUID the web device's identity gives (the
// SHA-1 name-space UUID of its /chosen unique-chip-id and chip-id), argv[2]
// "root" or "user" (what the run prints).
//
// - The raw call with no timeout (both halves zero) and with one: the 16
//   bytes, the same each time, the expected UUID.
// - The library's gethostuuid (unavailable to iOS in the SDK, bound by
//   its symbol) agrees.
// - A timeout or a buffer the process cannot reach: EFAULT.
// - IOKit: the platform expert device's IOPlatformUUID and IOResources'
//   are that UUID's upper-case string, and matching IOResources on the
//   IOPlatformUUID resource finds it.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>

extern int lib_gethostuuid(uuid_t, const struct timespec *) __asm__("_gethostuuid");

static long sys2(long n, long a, long b) {
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b;
    register long x16 __asm__("x16") = n, cs __asm__("x9");
    __asm__ volatile("svc #0x80\n cset x9, cs" : "+r"(x0), "+r"(x1), "=r"(cs) : "r"(x16) : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x10", "x11", "x12", "x13", "x14", "x15", "x17", "memory", "cc");
    if (cs) {
        errno = (int)x0;
        return -1;
    }
    return x0;
}

static int bad(const char *what, long got, long want) {
    printf("hostuuid: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

// The entry's string property `key` equal to `want`.
static int has_uuid(io_registry_entry_t e, const char *key, const char *want, const char *what) {
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    CFTypeRef v = IORegistryEntryCreateCFProperty(e, k, kCFAllocatorDefault, 0);
    CFRelease(k);
    if (v == NULL || CFGetTypeID(v) != CFStringGetTypeID()) {
        printf("hostuuid: %s: no string %s\n", what, key);
        return 1;
    }
    char s[64] = {0};
    CFStringGetCString(v, s, sizeof s, kCFStringEncodingUTF8);
    CFRelease(v);
    if (strcmp(s, want) != 0) {
        printf("hostuuid: %s: %s, want %s\n", what, s, want);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) return bad("arguments", argc, 3);
    const char *want = argv[1];
    uuid_t u, v;
    uuid_string_t s;

    struct timespec forever = {0, 0}, soon = {5, 0};
    memset(u, 0, sizeof u);
    if (sys2(142, (long)u, (long)&forever) != 0) return bad("gethostuuid with no timeout", errno, 0);
    uuid_unparse_upper(u, s);
    if (strcmp(s, want) != 0) {
        printf("hostuuid: %s, want %s\n", s, want);
        return 1;
    }
    memset(v, 0, sizeof v);
    if (sys2(142, (long)v, (long)&soon) != 0) return bad("gethostuuid with a timeout", errno, 0);
    if (memcmp(u, v, sizeof u) != 0) return bad("the UUID with a timeout the same", 0, 1);
    memset(v, 0, sizeof v);
    if (lib_gethostuuid(v, &forever) != 0) return bad("the library's gethostuuid", errno, 0);
    if (memcmp(u, v, sizeof u) != 0) return bad("the library's UUID the same", 0, 1);

    // Faults: the timeout's copyin, then the UUID's copyout.
    errno = 0;
    if (sys2(142, (long)v, 8) != -1 || errno != EFAULT) return bad("an unreachable timeout", errno, EFAULT);
    errno = 0;
    if (sys2(142, 8, (long)&forever) != -1 || errno != EFAULT) return bad("an unreachable buffer", errno, EFAULT);

    // IOKit's view.
    mach_port_t main_port = MACH_PORT_NULL;
    if (IOMainPort(MACH_PORT_NULL, &main_port) != KERN_SUCCESS) return bad("the main port", 0, 1);
    io_service_t pe = IOServiceGetMatchingService(main_port, IOServiceMatching("IOPlatformExpertDevice"));
    if (pe == IO_OBJECT_NULL) return bad("the platform expert device", 0, 1);
    if (has_uuid(pe, "IOPlatformUUID", want, "the platform expert device")) return 1;
    IOObjectRelease(pe);
    CFMutableDictionaryRef m = IOServiceMatching("IOResources");
    CFDictionarySetValue(m, CFSTR("IOResourceMatch"), CFSTR("IOPlatformUUID"));
    io_service_t res = IOServiceGetMatchingService(main_port, m);
    if (res == IO_OBJECT_NULL) return bad("IOResources by the IOPlatformUUID resource", 0, 1);
    if (has_uuid(res, "IOPlatformUUID", want, "IOResources")) return 1;
    IOObjectRelease(res);

    printf(strcmp(argv[2], "user") == 0 ? "hostuuid user ok\n" : "hostuuid ok\n");
    return 0;
}
