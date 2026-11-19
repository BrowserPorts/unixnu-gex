// The NVRAM variables through IOKit (IODeviceTree:/options, IODTNVRAM)
// and through the system's nvram tool, on the web device's factory NVRAM
// (no variable but the boot-args the kernel makes when there are none).
//
// As root ("root"): the entry is an IODTNVRAM with its services; a data
// variable set (a string given a data variable is stored as data), read,
// listed and deleted; a string variable takes no data and its length is
// bounded; a boolean and a number keep their types; a kernel-only variable
// is neither written nor read; a variable that may never be deleted is
// not, and the delete key that returns its result says so; the system
// namespace takes an allow-listed name but no other; the common service
// answers for its namespace. Then the nvram tool sets, prints and deletes
// a variable. Last, a variable set and a forced sync, which the runner
// finds in the web device's NVRAM image after the run.
//
// As a user ("user"): a variable of full access may be read but not
// written or deleted; a user-writable one may be written and deleted but
// not read.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

// IOKit.framework's IORegistryEntrySetCFProperty, which the iOS SDK's
// header marks unavailable (the system's nvram tool and restored call it).
extern kern_return_t set_cf_property(io_registry_entry_t entry, CFStringRef name, CFTypeRef value) __asm__("_IORegistryEntrySetCFProperty");

#define SYSTEM "40A0DDD2-77F8-4392-B4A3-1E7304206516:"
#define NOT_PRIVILEGED ((kern_return_t)0xe00002c1)
#define BAD_ARGUMENT ((kern_return_t)0xe00002c2)
#define NO_SPACE ((kern_return_t)0xe00002db)

static int bad(const char *what, long got, long want) {
    printf("nvram: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static io_registry_entry_t options;

static kern_return_t set(const char *name, CFTypeRef value) {
    CFStringRef key = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
    kern_return_t kr = set_cf_property(options, key, value);
    CFRelease(key);
    return kr;
}

static kern_return_t set_data(const char *name, const char *bytes, long len) {
    CFDataRef d = CFDataCreate(NULL, (const UInt8 *)bytes, len);
    kern_return_t kr = set(name, d);
    CFRelease(d);
    return kr;
}

static kern_return_t set_string(const char *name, const char *s) {
    CFStringRef v = CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
    kern_return_t kr = set(name, v);
    CFRelease(v);
    return kr;
}

static CFTypeRef get(io_registry_entry_t e, const char *name) {
    CFStringRef key = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
    CFTypeRef v = IORegistryEntryCreateCFProperty(e, key, kCFAllocatorDefault, 0);
    CFRelease(key);
    return v;
}

// Whether `v` is data of `len` bytes `bytes`.
static int is_data(CFTypeRef v, const char *bytes, long len) {
    return v != NULL && CFGetTypeID(v) == CFDataGetTypeID() && CFDataGetLength(v) == len && memcmp(CFDataGetBytePtr(v), bytes, len) == 0;
}

static int is_string(CFTypeRef v, const char *s) {
    char buf[256];
    return v != NULL && CFGetTypeID(v) == CFStringGetTypeID() && CFStringGetCString(v, buf, sizeof buf, kCFStringEncodingUTF8) && strcmp(buf, s) == 0;
}

// The nvram tool's run with `args`: its output into `out`, its status.
static int tool(char *const args[], char *out, size_t room) {
    int p[2];
    if (pipe(p) != 0) return -1;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    posix_spawn_file_actions_addclose(&fa, p[0]);
    pid_t pid;
    if (posix_spawn(&pid, "/usr/sbin/nvram", &fa, NULL, args, environ) != 0) return -1;
    close(p[1]);
    size_t n = 0;
    ssize_t r;
    while (n + 1 < room && (r = read(p[0], out + n, room - 1 - n)) > 0) n += (size_t)r;
    out[n] = 0;
    close(p[0]);
    int st;
    if (waitpid(pid, &st, 0) != pid) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static int user(void) {
    kern_return_t kr;
    if ((kr = set_data("gex-user", "1", 1)) != NOT_PRIVILEGED) return bad("a user's write", kr, NOT_PRIVILEGED);
    // backlight-level is user-writable, but not readable without root: its
    // permission is not full access.
    if ((kr = set_data("backlight-level", "\x10", 1)) != KERN_SUCCESS) return bad("a user's write of backlight-level", kr, 0);
    CFTypeRef v = get(options, "backlight-level");
    if (v != NULL) return bad("a user's read of backlight-level", 1, 0);
    v = get(options, "boot-args");
    if (!is_string(v, "")) return bad("a user's read of boot-args", v != NULL, 1);
    CFRelease(v);
    if ((kr = set_string("IONVRAM-DELETEWRET-PROPERTY", "backlight-level")) != KERN_SUCCESS) return bad("a user's delete of backlight-level", kr, 0);
    if ((kr = set_string("IONVRAM-DELETEWRET-PROPERTY", "boot-args")) != NOT_PRIVILEGED) return bad("a user's delete of boot-args", kr, NOT_PRIVILEGED);
    printf("nvram user ok\n");
    return 0;
}

int main(int argc, char **argv) {
    mach_port_t main_port = MACH_PORT_NULL;
    if (IOMainPort(MACH_PORT_NULL, &main_port) != KERN_SUCCESS) return bad("the main port", 0, 1);
    options = IORegistryEntryFromPath(main_port, "IODeviceTree:/options");
    if (options == IO_OBJECT_NULL) return bad("IODeviceTree:/options", 0, 1);
    if (!IOObjectConformsTo(options, "IODTNVRAM")) return bad("/options as an IODTNVRAM", 0, 1);
    if (argc > 1 && strcmp(argv[1], "user") == 0) return user();

    kern_return_t kr;
    CFTypeRef v;
    // The kernel's boot-args, an empty string.
    v = get(options, "boot-args");
    if (!is_string(v, "")) return bad("boot-args at boot", v != NULL, 1);
    CFRelease(v);

    // A data variable: set, read, as a string given it.
    if ((kr = set_data("gex-data", "a\0\xff", 3)) != KERN_SUCCESS) return bad("setting gex-data", kr, 0);
    v = get(options, "gex-data");
    if (!is_data(v, "a\0\xff", 3)) return bad("gex-data", v != NULL, 1);
    CFRelease(v);
    if ((kr = set_string("gex-data", "xyz")) != KERN_SUCCESS) return bad("gex-data from a string", kr, 0);
    v = get(options, "gex-data");
    if (!is_data(v, "xyz", 3)) return bad("gex-data as data", v != NULL, 1);
    CFRelease(v);

    // A string variable takes no data; boot-args is at most 768 bytes
    // (the system list's limit before BOOT_LINE_LENGTH's).
    if ((kr = set_data("boot-args", "-v", 2)) != BAD_ARGUMENT) return bad("boot-args from data", kr, BAD_ARGUMENT);
    char longer[800];
    memset(longer, 'a', sizeof longer);
    longer[769] = 0;
    if ((kr = set_string("boot-args", longer)) != NO_SPACE) return bad("a boot-args of 769 bytes", kr, NO_SPACE);
    if ((kr = set_string("boot-args", "-v debug=0x14e")) != KERN_SUCCESS) return bad("setting boot-args", kr, 0);
    v = get(options, "boot-args");
    if (!is_string(v, "-v debug=0x14e")) return bad("boot-args", v != NULL, 1);
    CFRelease(v);

    // A boolean and a number.
    if ((kr = set("auto-boot?", kCFBooleanFalse)) != KERN_SUCCESS) return bad("setting auto-boot?", kr, 0);
    if ((kr = set_string("auto-boot?", "true")) != BAD_ARGUMENT) return bad("auto-boot? from a string", kr, BAD_ARGUMENT);
    v = get(options, "auto-boot?");
    if (v != kCFBooleanFalse) return bad("auto-boot?", v != NULL, 1);
    CFRelease(v);
    int n = 4096;
    CFNumberRef num = CFNumberCreate(NULL, kCFNumberIntType, &n);
    if ((kr = set("test-num", num)) != KERN_SUCCESS) return bad("setting test-num", kr, 0);
    CFRelease(num);
    v = get(options, "test-num");
    int got = 0;
    if (v == NULL || CFGetTypeID(v) != CFNumberGetTypeID() || !CFNumberGetValue(v, kCFNumberIntType, &got) || got != 4096) return bad("test-num", got, 4096);
    CFRelease(v);

    // Kernel-only: neither written nor read.
    if ((kr = set_data("nonce-seeds", "x", 1)) != NOT_PRIVILEGED) return bad("writing nonce-seeds", kr, NOT_PRIVILEGED);
    if ((v = get(options, "nonce-seeds")) != NULL) return bad("reading nonce-seeds", 1, 0);
    if ((kr = set_data("krn.gex", "x", 1)) != NOT_PRIVILEGED) return bad("writing a krn. variable", kr, NOT_PRIVILEGED);

    // Never deleted; DELETE answers success, DELETEWRET the refusal.
    if ((kr = set_data("testNeverDel", "1", 1)) != KERN_SUCCESS) return bad("setting testNeverDel", kr, 0);
    if ((kr = set_string("IONVRAM-DELETEWRET-PROPERTY", "testNeverDel")) != NOT_PRIVILEGED) return bad("deleting testNeverDel with its result", kr, NOT_PRIVILEGED);
    if ((kr = set_string("IONVRAM-DELETE-PROPERTY", "testNeverDel")) != KERN_SUCCESS) return bad("deleting testNeverDel", kr, 0);
    if ((v = get(options, "testNeverDel")) == NULL) return bad("testNeverDel after its deletes", 0, 1);
    CFRelease(v);
    if ((kr = set_data("IONVRAM-DELETE-PROPERTY", "x", 1)) != (kern_return_t)0xe00002bc) return bad("a delete named by data", kr, 0xe00002bc);

    // The system namespace: an allow-listed name, which the factory NVRAM
    // (no system region) keeps in the common one, but no other without the
    // system entitlement.
    if ((kr = set_data(SYSTEM "gex-sys", "1", 1)) != NOT_PRIVILEGED) return bad("a system variable", kr, NOT_PRIVILEGED);
    if ((kr = set_data(SYSTEM "root-live-fs", "1", 1)) != KERN_SUCCESS) return bad("the system root-live-fs", kr, 0);
    v = get(options, "root-live-fs");
    if (!is_data(v, "1", 1)) return bad("root-live-fs in the common namespace", v != NULL, 1);
    CFRelease(v);

    // The whole table: the variables a root task may read.
    CFMutableDictionaryRef all = NULL;
    if ((kr = IORegistryEntryCreateCFProperties(options, &all, kCFAllocatorDefault, 0)) != KERN_SUCCESS || all == NULL) return bad("the properties", kr, 0);
    if (!CFDictionaryContainsKey(all, CFSTR("gex-data")) || !CFDictionaryContainsKey(all, CFSTR("boot-args")) || CFDictionaryContainsKey(all, CFSTR("nonce-seeds"))) return bad("the properties' keys", CFDictionaryGetCount(all), 0);
    CFRelease(all);

    // The services: diagnostics, notifier, then the common namespace's.
    io_iterator_t it = IO_OBJECT_NULL;
    if ((kr = IORegistryEntryGetChildIterator(options, kIOServicePlane, &it)) != KERN_SUCCESS) return bad("the services", kr, 0);
    const char *want[] = {"IODTNVRAMDiags", "IODTNVRAMPlatformNotifier", "options-common"};
    io_object_t o, common = IO_OBJECT_NULL;
    int i = 0;
    while ((o = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        io_name_t name;
        if (i >= 3 || IORegistryEntryGetName(o, name) != KERN_SUCCESS || strcmp(name, want[i]) != 0) return bad("a service's name", i, 0);
        if (i == 2) common = o;
        else IOObjectRelease(o);
        i++;
    }
    if (i != 3) return bad("the services' count", i, 3);
    v = get(common, "gex-data");
    if (!is_data(v, "xyz", 3)) return bad("gex-data through options-common", v != NULL, 1);
    CFRelease(v);

    // Deleted.
    if ((kr = set_string("IONVRAM-DELETE-PROPERTY", "gex-data")) != KERN_SUCCESS) return bad("deleting gex-data", kr, 0);
    if ((v = get(options, "gex-data")) != NULL) return bad("gex-data after its delete", 1, 0);

    // The nvram tool.
    char out[4096];
    char *setv[] = {"nvram", "gex-tool=hello", NULL};
    int st = tool(setv, out, sizeof out);
    if (st != 0) return bad("nvram gex-tool=hello", st, 0);
    char *getv[] = {"nvram", "gex-tool", NULL};
    st = tool(getv, out, sizeof out);
    if (st != 0 || strcmp(out, "gex-tool\thello\n") != 0) {
        printf("nvram: nvram gex-tool printed %s", out);
        return bad("nvram gex-tool", st, 0);
    }
    char *delv[] = {"nvram", "-d", "gex-tool", NULL};
    if ((st = tool(delv, out, sizeof out)) != 0) return bad("nvram -d gex-tool", st, 0);
    if ((v = get(options, "gex-tool")) != NULL) return bad("gex-tool after nvram -d", 1, 0);

    // What the runner finds in the image: set and forced to the namespace.
    if ((kr = set_data("gex-synced", "1", 1)) != KERN_SUCCESS) return bad("setting gex-synced", kr, 0);
    if ((kr = set_string("IONVRAM-FORCESYNCNOW-PROPERTY", "1")) != KERN_SUCCESS) return bad("the forced sync", kr, 0);
    printf("nvram ok\n");
    return 0;
}
