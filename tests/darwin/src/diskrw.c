// Reads of disk0 through its character node (IOMediaBSDClient's
// dkreadwrite), on the disk0 image the restore made, and what the system
// wrote to it: the GPT's header at block 1, its backup at the disk's last
// block (64 GB in), and the container's superblock at the partition's
// first block, which the kernel's container wrote as it updated the
// container to read-write for the boot's grafts: its flags read back here
// without NX_CLEANLY_UNMOUNTED, which the image's have. No dyld: the
// system's disk with nothing but the program on it.
//
// The geometry is the storage's stand-in: 15,625,000 blocks of 4096 bytes,
// the partition from block 6.
//
// Prints "diskrw gpt 1 backup 1 nx 1", "diskrw xid X clean C" (the
// superblock's o_xid, and 1 when its nx_flags has NX_CLEANLY_UNMOUNTED),
// "diskrw rw E" (E the errno of an open for writing, which the
// container's writer refuses: EBUSY), then "diskrw ok".

#define SYS_exit 1
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_pread 153

#define O_RDONLY 0
#define O_RDWR 2

struct ret {
    long x0;
    long carry;
};

static struct ret bsd(long nr, long a0, long a1, long a2, long a3) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x16 __asm__("x16") = nr;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs"
                     : "+r"(x0), "=r"(carry)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x16)
                     : "memory", "cc");
    return (struct ret){x0, carry};
}

static long err(struct ret r) {
    return r.carry ? r.x0 : 0;
}

static char line[256];
static int at;

static void put(const char *s) {
    while (*s && at < (int)sizeof line) line[at++] = *s++;
}

static void num(unsigned long v) {
    char d[24];
    int n = 0;
    do {
        d[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n && at < (int)sizeof line) line[at++] = d[--n];
}

static void say(void) {
    put("\n");
    bsd(SYS_write, 1, (long)line, at, 0);
    at = 0;
}

static int eq(const unsigned char *a, const unsigned char *b, long n) {
    for (long i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

#define BLOCK 4096
// apfs_raw.h: nx_superblock_t's nx_flags.
#define NX_CLEANLY_UNMOUNTED 0x2
static const unsigned long blocks = 15625000, pfirst = 6;
static unsigned char buf[BLOCK] __attribute__((aligned(BLOCK)));

/// Block `n` of `fd` into `into`: 1 when the whole block was read.
static int block(long fd, unsigned long n, unsigned char *into) {
    struct ret r = bsd(SYS_pread, fd, (long)into, BLOCK, (long)(n * BLOCK));
    return !r.carry && r.x0 == BLOCK;
}

static long all(void) {
    struct ret o = bsd(SYS_open, (long)"/dev/rdisk0", O_RDONLY, 0, 0);
    if (o.carry) return 2;
    long d0 = o.x0;
    int gpt = block(d0, 1, buf) && eq(buf, (const unsigned char *)"EFI PART", 8);
    int backup = block(d0, blocks - 1, buf) && eq(buf, (const unsigned char *)"EFI PART", 8);
    int nx = block(d0, pfirst, buf) && eq(buf + 32, (const unsigned char *)"NXSB", 4);
    unsigned long xid = 0, flags = 0;
    for (int i = 7; i >= 0; i--) xid = xid << 8 | buf[16 + i];
    for (int i = 7; i >= 0; i--) flags = flags << 8 | buf[0x4f0 + i];
    put("diskrw gpt ");
    num(gpt);
    put(" backup ");
    num(backup);
    put(" nx ");
    num(nx);
    say();
    put("diskrw xid ");
    num(xid);
    put(" clean ");
    num((flags & NX_CLEANLY_UNMOUNTED) != 0);
    say();
    struct ret w = bsd(SYS_open, (long)"/dev/rdisk0", O_RDWR, 0, 0);
    put("diskrw rw ");
    num(err(w));
    say();
    if (!w.carry) bsd(SYS_close, w.x0, 0, 0, 0);
    bsd(SYS_close, d0, 0, 0, 0);
    if (!(gpt && backup && nx)) return 5;
    put("diskrw ok");
    say();
    return 0;
}

void start(void) {
    bsd(SYS_exit, all(), 0, 0, 0);
    for (;;) {
    }
}
