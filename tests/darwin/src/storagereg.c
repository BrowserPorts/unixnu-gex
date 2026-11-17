// The internal storage's registry entries from a task: the container's
// medium found by its BSD name, its whole table in one read (the block
// sizes, the namespace's storage features, the encryption block size, its
// open state, size and UUID), every class conforming to OSObject, the
// provider chain up to the controller's PCI nub, the namespace's protocol
// characteristics found up the plane by a recursive search, and disk0 and
// its partition in the device tree plane below the controller, itself below
// its nub there;
// disk0 matched by its BSD major and minor as numbers, every IOMedia, the
// firmware namespace's whole disk, the controller's children in the order
// it makes them, its storage driver's statistics, and a search up the
// parents for a key no entry has.

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

// Entry `e`'s number property `k`, or -1.
static long num_of(io_registry_entry_t e, CFStringRef k) {
    CFNumberRef n = IORegistryEntryCreateCFProperty(e, k, kCFAllocatorDefault, 0);
    long v = -1;
    if (n != NULL && CFGetTypeID(n) == CFNumberGetTypeID()) CFNumberGetValue(n, kCFNumberLongType, &v);
    if (n != NULL) CFRelease(n);
    return v;
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

    // disk0 and its partition in the device tree plane, below the
    // controller, which is below s3e's nub there.
    io_registry_entry_t whole = up[3], part = up[1], dtp = IO_OBJECT_NULL, cdtp = IO_OBJECT_NULL;
    if (IORegistryEntryGetParentEntry(whole, kIODeviceTreePlane, &dtp) != KERN_SUCCESS || !IOObjectIsEqualTo(dtp, up[6])) return bad("disk0's device tree parent", 0, 1);
    if (IORegistryEntryGetParentEntry(part, kIODeviceTreePlane, &cdtp) != KERN_SUCCESS || !IOObjectIsEqualTo(cdtp, up[6])) return bad("the partition's device tree parent", 0, 1);
    IOObjectRelease(cdtp);
    if (IORegistryEntryGetParentEntry(up[6], kIODeviceTreePlane, &cdtp) != KERN_SUCCESS || !IOObjectIsEqualTo(cdtp, up[7])) return bad("the controller's device tree parent", 0, 1);
    IOObjectRelease(cdtp);
    if (IORegistryEntryGetNameInPlane(whole, kIODeviceTreePlane, name) != KERN_SUCCESS || strcmp(name, "disk") != 0) return bad("disk0's device tree name", 0, 1);
    if (IORegistryEntryGetLocationInPlane(whole, kIODeviceTreePlane, loc) != KERN_SUCCESS || strcmp(loc, "1:0") != 0) return bad("disk0's device tree location", 0, 1);
    if (IORegistryEntryGetLocationInPlane(part, kIODeviceTreePlane, loc) != KERN_SUCCESS || strcmp(loc, "1:1") != 0) return bad("the partition's device tree location", 0, 1);
    CFStringRef bsd = IORegistryEntryCreateCFProperty(whole, CFSTR("BSD Name"), kCFAllocatorDefault, 0);
    if (bsd == NULL || CFStringCompare(bsd, CFSTR("disk0"), 0) != kCFCompareEqualTo) return bad("disk0's BSD name", 0, 1);
    CFRelease(bsd);

    // disk0 by its BSD major and minor, numbers of two sizes.
    long major = num_of(whole, CFSTR("BSD Major")), minor = num_of(whole, CFSTR("BSD Minor"));
    if (major < 0 || minor < 0) return bad("disk0's BSD major and minor", major, 0);
    CFMutableDictionaryRef m = IOServiceMatching("IOMedia");
    int32_t major32 = (int32_t)major;
    int64_t minor64 = minor;
    CFNumberRef nmaj = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &major32);
    CFNumberRef nmin = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &minor64);
    CFDictionarySetValue(m, CFSTR("BSD Major"), nmaj);
    CFDictionarySetValue(m, CFSTR("BSD Minor"), nmin);
    CFRelease(nmaj);
    CFRelease(nmin);
    io_registry_entry_t byno = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (byno == IO_OBJECT_NULL || !IOObjectIsEqualTo(byno, whole)) return bad("disk0 by its BSD major and minor", byno != IO_OBJECT_NULL, 1);

    // Every medium: the disk, its partition, the container and its seven
    // volumes, and the firmware namespace's disk.
    io_iterator_t it;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOMedia"), &it) != KERN_SUCCESS) return bad("the media", 0, 1);
    int media_count = 0;
    for (io_object_t o; (o = IOIteratorNext(it)) != IO_OBJECT_NULL; IOObjectRelease(o)) media_count++;
    IOObjectRelease(it);
    if (media_count != 11) return bad("how many media", media_count, 11);

    // The firmware namespace's whole disk: 8 MiB, a leaf, below NS_02's
    // driver, in the device tree plane at 2:0.
    io_registry_entry_t fw = IOServiceGetMatchingService(kIOMainPortDefault, IOBSDNameMatching(kIOMainPortDefault, 0, "disk2"));
    if (fw == IO_OBJECT_NULL || !class_is(fw, "IOMedia")) return bad("disk2", 0, 1);
    if (num_of(fw, CFSTR("Size")) != 8 << 20) return bad("disk2's size", num_of(fw, CFSTR("Size")), 8 << 20);
    CFTypeRef leaf = IORegistryEntryCreateCFProperty(fw, CFSTR("Leaf"), kCFAllocatorDefault, 0);
    if (leaf != kCFBooleanTrue) return bad("disk2 a leaf", 0, 1);
    io_registry_entry_t fwdrv, fwns;
    if (IORegistryEntryGetParentEntry(fw, kIOServicePlane, &fwdrv) != KERN_SUCCESS || !class_is(fwdrv, "IOBlockStorageDriver")) return bad("disk2's driver", 0, 1);
    if (IORegistryEntryGetParentEntry(fwdrv, kIOServicePlane, &fwns) != KERN_SUCCESS || IORegistryEntryGetName(fwns, name) != KERN_SUCCESS || strcmp(name, "NS_02") != 0) return bad("disk2's namespace", 0, 1);
    if (IORegistryEntryGetLocationInPlane(fw, kIODeviceTreePlane, loc) != KERN_SUCCESS || strcmp(loc, "2:0") != 0) return bad("disk2's device tree location", 0, 1);

    // The controller's children, in the order its start makes them.
    const char *kids[] = {"AppleEmbeddedNVMeTemperatureSensor", "AppleEmbeddedNVMeNVRAM", "NS_01", "NS_02", "AppleEmbeddedNVMeDiagnostics", "NS_06", "NS_07"};
    if (IORegistryEntryGetChildIterator(up[6], kIOServicePlane, &it) != KERN_SUCCESS) return bad("the controller's children", 0, 1);
    int k = 0;
    for (io_object_t o; (o = IOIteratorNext(it)) != IO_OBJECT_NULL; IOObjectRelease(o), k++) {
        if (k >= 7 || IORegistryEntryGetName(o, name) != KERN_SUCCESS || strcmp(name, kids[k]) != 0) return bad("a child of the controller", k, 7);
    }
    IOObjectRelease(it);
    if (k != 7) return bad("how many children the controller has", k, 7);

    // NS_01's driver's statistics: twelve counts.
    CFDictionaryRef st = IORegistryEntryCreateCFProperty(up[4], CFSTR("Statistics"), kCFAllocatorDefault, 0);
    if (st == NULL || CFGetTypeID(st) != CFDictionaryGetTypeID() || CFDictionaryGetCount(st) != 12 || num(st, CFSTR("Operations (Read)")) < 0) return bad("the driver's statistics", st ? CFDictionaryGetCount(st) : 0, 12);
    CFRelease(st);

    // No entry up the plane has Target Disk Mode.
    CFTypeRef tdm = IORegistryEntrySearchCFProperty(media, kIOServicePlane, CFSTR("Target Disk Mode"), kCFAllocatorDefault, kIORegistryIterateRecursively | kIORegistryIterateParents);
    if (tdm != NULL) return bad("Target Disk Mode up the plane", 1, 0);

    printf("storagereg ok\n");
    return 0;
}
