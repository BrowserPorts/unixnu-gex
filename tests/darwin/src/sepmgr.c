// AppleSEPManager's user client, as init_data_protection reaches it, with no
// sepOS (nothing here supplies one): the manager is the SEP node's driver
// over AppleA7IOPV2 and its nub, the sep node has none of the device-tree
// properties only iBoot would write (sepfw-loaded, has-art), the client
// opens for a task with com.apple.private.applesepmanager.allow (and
// refuses one without it, as sepmgrdeny checks), its dispatch table checks
// the counts of each selector (the NULL entries answer kIOReturnNoCompletion,
// selectors from 84 up kIOReturnUnsupported), the gigalocker's path is
// taken (selector 44) with no SEP running, and the sepOS's load
// (selector 6) answers not ready after the kernel has reported that the
// SEP needs the owner's decrypted sepOS: a strict run stops there ("load").

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOT_READY ((kern_return_t)0xe00002d8)
#define BAD_ARGUMENT ((kern_return_t)0xe00002c2)
#define NO_COMPLETION ((kern_return_t)0xe00002ea)
#define UNSUPPORTED ((kern_return_t)0xe00002c7)

static int bad(const char *what, long got, long want) {
    printf("sepmgr: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static io_service_t manager(mach_port_t main_port) {
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(main_port, IOServiceMatching("AppleSEPManager"), &it) != KERN_SUCCESS) return IO_OBJECT_NULL;
    io_service_t s = IOIteratorNext(it);
    if (s != IO_OBJECT_NULL && IOIteratorNext(it) != IO_OBJECT_NULL) s = IO_OBJECT_NULL;
    IOObjectRelease(it);
    return s;
}

int main(int argc, char **argv) {
    mach_port_t main_port = MACH_PORT_NULL;
    if (IOMainPort(MACH_PORT_NULL, &main_port) != KERN_SUCCESS) return bad("the main port", 0, 1);
    io_service_t svc = manager(main_port);
    if (svc == IO_OBJECT_NULL) return bad("one AppleSEPManager", 0, 1);

#ifdef DENY
    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    if (kr != BAD_ARGUMENT) return bad("an open without the entitlement", kr, BAD_ARGUMENT);
    printf("sepmgrdeny ok\n");
    return 0;
#else
    // The manager sits over the sep node: sep -> AppleA7IOPV2 -> iop-sep-nub (AppleA7IOPNub) -> AppleSEPManager.
    io_registry_entry_t nub = IO_OBJECT_NULL, a7iop = IO_OBJECT_NULL, sep = IO_OBJECT_NULL;
    if (IORegistryEntryGetParentEntry(svc, kIOServicePlane, &nub) != KERN_SUCCESS || !IOObjectConformsTo(nub, "AppleA7IOPNub")) return bad("the manager's nub", 0, 1);
    if (IORegistryEntryGetParentEntry(nub, kIOServicePlane, &a7iop) != KERN_SUCCESS || !IOObjectConformsTo(a7iop, "AppleA7IOPV2") || !IOObjectConformsTo(a7iop, "IOSlaveCPU")) return bad("the nub's driver", 0, 1);
    if (IORegistryEntryGetParentEntry(a7iop, kIOServicePlane, &sep) != KERN_SUCCESS || !IOObjectConformsTo(sep, "AppleARMIODevice")) return bad("the driver's provider", 0, 1);
    if (!IOObjectConformsTo(svc, "IOSlaveProcessor")) return bad("the manager's class", 0, 1);

    // The sep node has no sepfw-loaded and no has-art (iBoot would add them), which seputil searches
    // for on this entry alone (options 0); /chosen's sepfw-load-at-boot and protected-data-access are the IPSW's 1.
    io_registry_entry_t node = IORegistryEntryFromPath(main_port, "IODeviceTree:/arm-io/sep");
    if (node == IO_OBJECT_NULL) return bad("IODeviceTree:/arm-io/sep", 0, 1);
    const CFStringRef absent[] = { CFSTR("sepfw-loaded"), CFSTR("has-art") };
    for (int i = 0; i < 2; i++) {
        CFTypeRef v = IORegistryEntrySearchCFProperty(node, "IODeviceTree", absent[i], kCFAllocatorDefault, 0);
        if (v != NULL) return bad("a property only iBoot writes", 1, 0);
    }
    io_registry_entry_t chosen = IORegistryEntryFromPath(main_port, "IODeviceTree:/chosen");
    const CFStringRef set[] = { CFSTR("sepfw-load-at-boot"), CFSTR("protected-data-access") };
    for (int i = 0; i < 2; i++) {
        CFTypeRef v = IORegistryEntrySearchCFProperty(chosen, "IODeviceTree", set[i], kCFAllocatorDefault, 0);
        if (v == NULL || CFGetTypeID(v) != CFDataGetTypeID() || CFDataGetLength(v) != 4) return bad("a /chosen flag", 0, 1);
        uint32_t w;
        memcpy(&w, CFDataGetBytePtr(v), 4);
        if (w != 1) return bad("the flag's value", w, 1);
    }
    // The manager's own properties its personality and start give.
    CFTypeRef uc = IORegistryEntryCreateCFProperty(svc, CFSTR("IOUserClientClass"), kCFAllocatorDefault, 0);
    if (uc == NULL || CFGetTypeID(uc) != CFStringGetTypeID() || !CFEqual(uc, CFSTR("AppleSEPUserClient"))) return bad("IOUserClientClass", 0, 1);
    CFTypeRef booted = IORegistryEntryCreateCFProperty(svc, CFSTR("sep-booted"), kCFAllocatorDefault, 0);
    if (booted == NULL || booted != kCFBooleanFalse) return bad("sep-booted before any boot", 0, 1);

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS) return bad("IOServiceOpen", kr, 0);

    // The dispatch entries' counts: a wrong count is kIOReturnBadArgument.
    uint64_t scalar[3] = { 0, 0, 0 };
    kr = IOConnectCallScalarMethod(conn, 5, NULL, 0, NULL, NULL);
    if (kr != BAD_ARGUMENT) return bad("selector 5 without its scalar", kr, BAD_ARGUMENT);
    kr = IOConnectCallScalarMethod(conn, 6, scalar, 2, NULL, NULL);
    if (kr != BAD_ARGUMENT) return bad("selector 6 with two scalars", kr, BAD_ARGUMENT);
    // The NULL entries have no function: the counts are checked (all zero), then kIOReturnNoCompletion.
    static const int nulls[] = { 17, 37, 38, 39, 40, 72, 77, 78, 79, 80 };
    for (size_t i = 0; i < sizeof nulls / sizeof nulls[0]; i++) {
        kr = IOConnectCallScalarMethod(conn, nulls[i], NULL, 0, NULL, NULL);
        if (kr != NO_COMPLETION) return bad("a selector with no function", kr, NO_COMPLETION);
    }
    kr = IOConnectCallScalarMethod(conn, 17, scalar, 1, NULL, NULL);
    if (kr != BAD_ARGUMENT) return bad("a NULL entry's count check", kr, BAD_ARGUMENT);
    kr = IOConnectCallScalarMethod(conn, 84, NULL, 0, NULL, NULL);
    if (kr != UNSUPPORTED) return bad("selector 84", kr, UNSUPPORTED);

    // Selector 44, GigalockerInit: a 1024-byte structure holding a C string, which needs no SEP
    // running (the manager keeps the path until the SEP's xART master checks in).
    char path[1024];
    memset(path, 0, sizeof path);
    strcpy(path, "/private/xarts/00000000-0000-4000-8000-000000000005.gl");
    kr = IOConnectCallStructMethod(conn, 44, path, sizeof path, NULL, NULL);
    if (kr != KERN_SUCCESS) return bad("GigalockerInit", kr, 0);
    memset(path, 'x', sizeof path);
    kr = IOConnectCallStructMethod(conn, 44, path, sizeof path, NULL, NULL);
    if (kr != (kern_return_t)0xe00002ca) return bad("an unterminated path", kr, 0xe00002ca);

    // A selector that needs the SEP/OS (ping) is not receptive, and a strict run stops there:
    // "ping" is the first of them.
    if (argc > 1 && strcmp(argv[1], "ping") == 0) {
        printf("sepmgr ping\n");
        fflush(stdout);
        kr = IOConnectCallScalarMethod(conn, 0, NULL, 0, NULL, NULL);
        return bad("ping returned", kr, 0);
    }

    // The sepOS's load (selector 6) with a firmware-sized structure: with no decrypted sepOS
    // given, a run that is not strict is told the SEP is not ready; a strict one stops at "load".
    if (argc > 1 && strcmp(argv[1], "load") == 0) {
        printf("sepmgr load\n");
        fflush(stdout);
    }
    size_t len = 1 << 20;
    void *fw = calloc(1, len);
    scalar[0] = len;
    kr = IOConnectCallMethod(conn, 6, scalar, 3, fw, len, NULL, NULL, NULL, NULL);
    if (kr != NOT_READY) return bad("LoadFirmware with no sepOS", kr, NOT_READY);
    kr = IOConnectCallScalarMethod(conn, 0, NULL, 0, NULL, NULL);
    if (kr != NOT_READY) return bad("ping with no SEP running", kr, NOT_READY);

    IOServiceClose(conn);
    printf("sepmgr ok\n");
    return 0;
#endif
}
