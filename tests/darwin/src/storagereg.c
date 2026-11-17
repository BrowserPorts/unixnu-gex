// The internal storage's registry entries from a task: the container's
// medium found by its BSD name, its whole table in one read (the block
// sizes, the namespace's storage features, the encryption block size, its
// open state, size and UUID), every class conforming to OSObject, the
// provider chain up to the controller's PCI nub, the namespace's protocol
// characteristics found up the plane by a recursive search, and disk0 and
// its partition in the device tree plane below the controller's nub.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>

static int bad(const char *what, long got, long want) {
    printf("storagereg: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static long num(CFDictionaryRef d, CFStringRef k) {
    CFNumberRef n = CFDictionaryGetValue(d, k);
    long v = -1;
    if (n == NULL || CFGetTypeID(n) != CFNumberGetTypeID() || !CFNumberGetValue(n, kCFNumberLongType, &v)) return -1;
    return v;
}

static int is_true(CFDictionaryRef d, CFStringRef k) {
    CFTypeRef b = CFDictionaryGetValue(d, k);
    return b == kCFBooleanTrue;
}

static int is_bool(CFDictionaryRef d, CFStringRef k) {
    CFTypeRef b = CFDictionaryGetValue(d, k);
    return b == kCFBooleanTrue || b == kCFBooleanFalse;
}

// Entry `e`'s class is `want`.
static int class_is(io_registry_entry_t e, const char *want) {
    io_name_t c;
    return IOObjectGetClass(e, c) == KERN_SUCCESS && strcmp(c, want) == 0;
}

int main(void) {
    io_registry_entry_t media = IOServiceGetMatchingService(kIOMainPortDefault, IOBSDNameMatching(kIOMainPortDefault, 0, "disk1"));
    if (media == IO_OBJECT_NULL) return bad("disk1 by its BSD name", 0, 1);
    if (!class_is(media, "AppleAPFSMedia")) return bad("disk1's class", 0, 1);
    if (!IOObjectConformsTo(media, "OSObject") || !IOObjectConformsTo(media, "IOMedia")) return bad("disk1 conforming to IOMedia and OSObject", 0, 1);

    CFMutableDictionaryRef p = NULL;
    if (IORegistryEntryCreateCFProperties(media, &p, kCFAllocatorDefault, 0) != KERN_SUCCESS || p == NULL) return bad("disk1's properties", 0, 1);
    if (num(p, CFSTR("Physical Block Size")) != 4096 || num(p, CFSTR("Logical Block Size")) != 4096) return bad("the block sizes", num(p, CFSTR("Physical Block Size")), 4096);
    if (num(p, CFSTR("Preferred Block Size")) != 4096) return bad("the preferred block size", num(p, CFSTR("Preferred Block Size")), 4096);
    if (num(p, CFSTR("EncryptionBlockSize")) <= 0) return bad("EncryptionBlockSize", num(p, CFSTR("EncryptionBlockSize")), 4096);
    if (num(p, CFSTR("Size")) <= 0) return bad("Size", num(p, CFSTR("Size")), 1);
    CFDictionaryRef f = CFDictionaryGetValue(p, CFSTR("IOStorageFeatures"));
    if (f == NULL || CFGetTypeID(f) != CFDictionaryGetTypeID() || CFDictionaryGetCount(f) != 3) return bad("IOStorageFeatures", f ? CFDictionaryGetCount(f) : 0, 3);
    if (!is_bool(f, CFSTR("Unmap")) || !is_true(f, CFSTR("Priority")) || !is_true(f, CFSTR("Barrier"))) return bad("the features' values", 0, 1);
    // Open: the root's container is open, read by its boot opens.
    if (!is_true(p, CFSTR("Open"))) return bad("disk1 open", 0, 1);
    if (!is_true(p, CFSTR("Whole")) || is_true(p, CFSTR("Leaf"))) return bad("whole, not a leaf", 0, 1);
    CFStringRef uuid = CFDictionaryGetValue(p, CFSTR("UUID"));
    if (uuid == NULL || CFGetTypeID(uuid) != CFStringGetTypeID() || CFStringGetLength(uuid) != 36) return bad("the UUID", 0, 1);
    CFRelease(p);

    // Up the IOService plane.
    const char *chain[] = {"AppleAPFSContainerScheme", "IOMedia", "IOGUIDPartitionScheme", "IOMedia", "IOBlockStorageDriver", "IOEmbeddedNVMeBlockDevice", "AppleEmbeddedNVMeController", "IOPCIDevice", "ApplePCIEHostBridge", "IOPCIDevice", "AppleT8011PCIe"};
    io_registry_entry_t e = media, up[16];
    for (int i = 0; i < (int)(sizeof chain / sizeof *chain); i++) {
        if (IORegistryEntryGetParentEntry(e, kIOServicePlane, &up[i]) != KERN_SUCCESS) return bad("a provider", i, 0);
        e = up[i];
        if (!class_is(e, chain[i])) return bad("a provider's class", i, 0);
        if (!IOObjectConformsTo(e, "OSObject")) return bad("a provider conforming to OSObject", i, 0);
    }
    io_name_t name;
    if (IORegistryEntryGetName(up[1], name) != KERN_SUCCESS || strcmp(name, "Container") != 0) return bad("the partition's name", 0, 1);
    io_name_t loc;
    if (IORegistryEntryGetLocationInPlane(up[1], kIOServicePlane, loc) != KERN_SUCCESS || strcmp(loc, "1") != 0) return bad("the partition's location", 0, 1);
    if (IORegistryEntryGetName(up[8], name) != KERN_SUCCESS || strcmp(name, "IOPP") != 0) return bad("the host bridge's name", 0, 1);
    if (IORegistryEntryGetName(up[7], name) != KERN_SUCCESS || strcmp(name, "s3e") != 0) return bad("the controller's nub's name", 0, 1);

    // A recursive search up the parents finds the namespace's.
    CFTypeRef pc = IORegistryEntrySearchCFProperty(media, kIOServicePlane, CFSTR("Protocol Characteristics"), kCFAllocatorDefault, kIORegistryIterateRecursively | kIORegistryIterateParents);
    if (pc == NULL || CFGetTypeID(pc) != CFDictionaryGetTypeID()) return bad("Protocol Characteristics up the plane", 0, 1);
    CFStringRef ic = CFDictionaryGetValue(pc, CFSTR("Physical Interconnect"));
    if (ic == NULL || CFStringCompare(ic, CFSTR("PCI-Express"), 0) != kCFCompareEqualTo) return bad("the interconnect", 0, 1);
    CFRelease(pc);

    // disk0 and its partition in the device tree plane, below s3e's nub.
    io_registry_entry_t whole = up[3], part = up[1], dtp = IO_OBJECT_NULL;
    if (IORegistryEntryGetParentEntry(whole, kIODeviceTreePlane, &dtp) != KERN_SUCCESS || !IOObjectIsEqualTo(dtp, up[7])) return bad("disk0's device tree parent", 0, 1);
    if (IORegistryEntryGetNameInPlane(whole, kIODeviceTreePlane, name) != KERN_SUCCESS || strcmp(name, "disk") != 0) return bad("disk0's device tree name", 0, 1);
    if (IORegistryEntryGetLocationInPlane(whole, kIODeviceTreePlane, loc) != KERN_SUCCESS || strcmp(loc, "1:0") != 0) return bad("disk0's device tree location", 0, 1);
    if (IORegistryEntryGetLocationInPlane(part, kIODeviceTreePlane, loc) != KERN_SUCCESS || strcmp(loc, "1:1") != 0) return bad("the partition's device tree location", 0, 1);
    CFStringRef bsd = IORegistryEntryCreateCFProperty(whole, CFSTR("BSD Name"), kCFAllocatorDefault, 0);
    if (bsd == NULL || CFStringCompare(bsd, CFSTR("disk0"), 0) != kCFCompareEqualTo) return bad("disk0's BSD name", 0, 1);
    CFRelease(bsd);

    printf("storagereg ok\n");
    return 0;
}
