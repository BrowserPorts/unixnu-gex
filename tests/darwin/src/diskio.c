// An open disk node's I/O and ioctls (IOMediaBSDClient's dkreadwrite and
// dkioctl, specfs above them), on the disk0 image the restore made
// (gexc darwin-disk0): the GPT on disk0, the container on its partition
// and on disk1 at the same offsets, a volume's I/O refused without crypto
// state, and the character node's alignment and end-of-media rules.
//
// The geometry is the storage's stand-in: 15,625,000 blocks of 4096 bytes,
// the partition MediaKit lays out from block 6 to block 15,624,994.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// bsd/sys/disk.h, which the iOS SDK does not ship.
#define DKIOCGETBLOCKSIZE _IOR('d', 24, uint32_t)
#define DKIOCSETBLOCKSIZE _IOW('d', 24, uint32_t)
#define DKIOCGETBLOCKCOUNT _IOR('d', 25, uint64_t)
#define DKIOCGETBASE _IOR('d', 73, uint64_t)
#define DKIOCGETFEATURES _IOR('d', 76, uint32_t)
#define DKIOCISSOLIDSTATE _IOR('d', 79, uint32_t)
#define DKIOCGETAPFSFLAVOUR _IOR('d', 91, uint32_t)
#define DK_FEATURE_BARRIER 0x2
#define DK_FEATURE_PRIORITY 0x4
#define DK_FEATURE_UNMAP 0x10
// bsd/sys/conf.h's d_type of a disk.
#define D_DISK 2

static int bad(const char *what, long got, long want) {
    printf("diskio: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static char buf[16384] __attribute__((aligned(4096)));

int main(void) {
    const uint64_t blocks = 15625000, pfirst = 6, plast = 15624994;
    int d0 = open("/dev/rdisk0", O_RDONLY);
    if (d0 < 0) return bad("open rdisk0", errno, 0);
    uint32_t bs = 0;
    uint64_t count = 0;
    if (ioctl(d0, DKIOCGETBLOCKSIZE, &bs) || bs != 4096) return bad("rdisk0 block size", bs, 4096);
    if (ioctl(d0, DKIOCGETBLOCKCOUNT, &count) || count != blocks) return bad("rdisk0 block count", (long)count, (long)blocks);
    int type = 0;
    if (ioctl(d0, FIODTYPE, &type) || type != D_DISK) return bad("FIODTYPE", type, D_DISK);
    uint32_t v = 0;
    if (ioctl(d0, DKIOCGETAPFSFLAVOUR, &v) == 0 || errno != ENOTTY) return bad("rdisk0 APFS flavour", errno, ENOTTY);
    if (ioctl(d0, DKIOCISSOLIDSTATE, &v) || v != 1) return bad("solid state", v, 1);
    if (ioctl(d0, DKIOCSETBLOCKSIZE, &bs) == 0 || errno != EPERM) return bad("setting the block size", errno, EPERM);
    // The GPT's header at LBA 1.
    if (pread(d0, buf, 4096, 4096) != 4096) return bad("reading LBA 1", errno, 0);
    if (memcmp(buf, "EFI PART", 8)) return bad("the GPT's signature", buf[0], 'E');
    // Unaligned, short or at the end.
    if (pread(d0, buf, 4096, 1) >= 0 || errno != EINVAL) return bad("an unaligned read", errno, EINVAL);
    if (pread(d0, buf, 512, 0) >= 0 || errno != EINVAL) return bad("a partial block", errno, EINVAL);
    if (pread(d0, buf, 4096, blocks * 4096) != 0) return bad("a read at the end", errno, 0);
    if (pread(d0, buf, 8192, (blocks - 1) * 4096) != 4096) return bad("a read past the end", errno, 0);

    int p = open("/dev/rdisk0s1", O_RDONLY);
    if (p < 0) return bad("open rdisk0s1", errno, 0);
    uint64_t base = 0;
    if (ioctl(p, DKIOCGETBASE, &base) || base != pfirst * 4096) return bad("the partition's base", (long)base, (long)(pfirst * 4096));
    if (ioctl(p, DKIOCGETBLOCKCOUNT, &count) || count != plast + 1 - pfirst) return bad("the partition's blocks", (long)count, (long)(plast + 1 - pfirst));

    // The container: the partition's bytes, its superblock at 0.
    int c = open("/dev/rdisk1", O_RDONLY);
    if (c < 0) return bad("open rdisk1", errno, 0);
    if (ioctl(c, DKIOCGETAPFSFLAVOUR, &v) || v != 1) return bad("the container's flavour", v, 1);
    if (ioctl(c, DKIOCGETBLOCKCOUNT, &count) || count != plast + 1 - pfirst) return bad("the container's blocks", (long)count, (long)(plast + 1 - pfirst));
    if (ioctl(c, DKIOCGETFEATURES, &v) || v != (DK_FEATURE_UNMAP | DK_FEATURE_PRIORITY | DK_FEATURE_BARRIER)) return bad("the container's features", v, DK_FEATURE_UNMAP | DK_FEATURE_PRIORITY | DK_FEATURE_BARRIER);
    if (pread(c, buf, 4096, 0) != 4096) return bad("the container's block 0", errno, 0);
    if (memcmp(buf + 32, "NXSB", 4)) return bad("the container's magic", buf[32], 'N');
    if (pread(p, buf + 4096, 4096, 0) != 4096 || memcmp(buf, buf + 4096, 4096)) return bad("the partition's block 0", errno, 0);
    if (pread(d0, buf + 4096, 4096, pfirst * 4096) != 4096 || memcmp(buf, buf + 4096, 4096)) return bad("disk0's block 6", errno, 0);
    // A writer of the mounted container: refused.
    if (open("/dev/rdisk1", O_RDWR) >= 0 || errno != EBUSY) return bad("a writer of the container", errno, EBUSY);

    // A volume's medium: no I/O without its crypto state.
    int s = open("/dev/rdisk1s1", O_RDONLY);
    if (s < 0) return bad("open rdisk1s1", errno, 0);
    if (pread(s, buf, 4096, 0) >= 0 || errno != EACCES) return bad("a volume's read", errno, EACCES);
    if (ioctl(s, DKIOCGETAPFSFLAVOUR, &v) || v != 1) return bad("a volume's flavour", v, 1);

    // The block node: through 16 KiB buffers, any offset.
    int b = open("/dev/disk0", O_RDONLY);
    if (b < 0) return bad("open disk0", errno, 0);
    if (pread(b, buf, 8, 4096) != 8 || memcmp(buf, "EFI PART", 8)) return bad("disk0's GPT through the buffer cache", errno, 0);
    if (pread(b, buf, 4, 4096 + 1) != 4 || memcmp(buf, "FI P", 4)) return bad("an unaligned block read", errno, 0);

    close(b);
    close(s);
    close(c);
    close(p);
    close(d0);
    // The last closes closed the media: they open again.
    d0 = open("/dev/rdisk0", O_RDONLY);
    if (d0 < 0) return bad("reopen rdisk0", errno, 0);
    close(d0);
    printf("diskio ok\n");
    return 0;
}
