// The system's persona registry and jetsam table from two processes: a
// persona one allocates, the other finds by its login and reads; the
// jetsam band and user data one sets for itself, the other finds in the
// priority list. With no argument, both in this one process: "xsys ok".
//
// For a caller that runs it twice at once in one system:
//   xsys make   allocates persona "xsys-shared", puts itself in the
//               foreground band with user data 0x78737973, and waits (at
//               most 20 s) for the persona to be deallocated: "xsys made".
//   xsys find   looks the persona up by its login (until it is there, at
//               most 20 s), reads its info, finds the maker in the
//               priority list with its band and user data, and deallocates
//               the persona: "xsys found".

#define SYS_exit 1
#define SYS_write 4
#define SYS_getpid 20
#define SYS_select 93
#define SYS_memorystatus_control 440
#define SYS_persona 494

#define ESRCH 3

#define OP_ALLOC 1
#define OP_DEALLOC 3
#define OP_INFO 5
#define OP_FIND 7

#define CMD_GET_PRIORITY_LIST 1
#define CMD_SET_PRIORITY_PROPERTIES 2

#define BAND 100
#define USER_DATA 0x78737973UL
#define LOGIN "xsys-shared"
#define TYPE 2

struct ret {
    long x0;
    long carry;
};

static struct ret sys6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x16 __asm__("x16") = nr;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs" : "+r"(x0), "=r"(carry) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16) : "memory", "cc");
    return (struct ret){x0, carry};
}

// struct kpersona_info, version 2 (packed): version, id, type, gid,
// ngroups, groups[16], gmuid, name[256], uid.
struct kpersona_info {
    unsigned int version;
    unsigned int id;
    int type;
    unsigned int gid;
    unsigned int ngroups;
    unsigned int groups[16];
    unsigned int gmuid;
    char name[256];
    unsigned int uid;
} __attribute__((packed));

// memorystatus_priority_entry_t.
struct entry {
    int pid;
    int priority;
    unsigned long user_data;
    int limit;
    unsigned int state;
};

static char line[160];
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
    sys6(SYS_write, 1, (long)line, at, 0, 0, 0);
    at = 0;
}

static int bad(const char *what, unsigned long got) {
    put("xsys: ");
    put(what);
    put(": ");
    num(got);
    say();
    return 1;
}

static int same(const char *a, const char *b) {
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

static void nap(void) {
    long tv[2] = {0, 100000};
    sys6(SYS_select, 0, 0, 0, 0, (long)tv, 0);
}

static void zero(void *p, unsigned long n) {
    volatile char *c = p;
    while (n--) *c++ = 0;
}

static void info_of(struct kpersona_info *k, unsigned int id) {
    zero(k, sizeof *k);
    k->version = 2;
    k->id = id;
}

// The persona whose login is LOGIN: its id, or 0 when there is none (or
// the call failed: its errno in *err).
static unsigned int find(long *err) {
    struct kpersona_info k;
    info_of(&k, (unsigned int)-1);
    const char *n = LOGIN;
    for (int i = 0; n[i]; i++) k.name[i] = n[i];
    unsigned int ids[4] = {0};
    unsigned long len = 4;
    struct ret r = sys6(SYS_persona, OP_FIND, 0, (long)&k, (long)ids, (long)&len, 0);
    *err = r.carry ? r.x0 : 0;
    return r.carry || len != 1 ? 0 : ids[0];
}

static int make(unsigned int *id) {
    struct kpersona_info k;
    info_of(&k, (unsigned int)-1);
    k.type = TYPE;
    k.uid = (unsigned int)-1;
    const char *n = LOGIN;
    for (int i = 0; n[i]; i++) k.name[i] = n[i];
    struct ret r = sys6(SYS_persona, OP_ALLOC, 0, (long)&k, (long)id, 0, 0);
    if (r.carry) return bad("persona alloc", r.x0);
    if (*id < 501) return bad("its id", *id);
    return 0;
}

static int set_band(int pid) {
    struct { int priority; int pad; unsigned long user_data; } p = {BAND, 0, USER_DATA};
    struct ret r = sys6(SYS_memorystatus_control, CMD_SET_PRIORITY_PROPERTIES, pid, 0, (long)&p, sizeof p, 0);
    if (r.carry) return bad("set priority properties", r.x0);
    return 0;
}

// Whether the priority list has process `pid` in BAND with USER_DATA (any
// process but `not` for pid 0): its pid, 0 when not there.
static int listed(int pid, int not) {
    static struct entry list[256];
    struct ret r = sys6(SYS_memorystatus_control, CMD_GET_PRIORITY_LIST, 0, 0, (long)list, sizeof list, 0);
    if (r.carry) return -(int)r.x0;
    for (unsigned long i = 0; i < (unsigned long)r.x0 / sizeof(struct entry); i++) {
        struct entry *e = &list[i];
        if ((pid ? e->pid == pid : e->pid != not) && e->priority == BAND && e->user_data == USER_DATA) return e->pid;
    }
    return 0;
}

static int read_back(unsigned int id) {
    struct kpersona_info k;
    info_of(&k, 0);
    struct ret r = sys6(SYS_persona, OP_INFO, 0, (long)&k, (long)&id, 0, 0);
    if (r.carry) return bad("persona info", r.x0);
    if (k.id != id || k.type != TYPE || !same(k.name, LOGIN)) return bad("its info's id", k.id);
    return 0;
}

static int dealloc(unsigned int id) {
    struct ret r = sys6(SYS_persona, OP_DEALLOC, 0, 0, (long)&id, 0, 0);
    if (r.carry) return bad("persona dealloc", r.x0);
    return 0;
}

static int both(void) {
    int me = (int)sys6(SYS_getpid, 0, 0, 0, 0, 0, 0).x0;
    unsigned int id = 0;
    long err = 0;
    if (make(&id)) return 1;
    if (find(&err) != id) return bad("found", err);
    if (read_back(id)) return 1;
    if (set_band(me)) return 1;
    int got = listed(me, 0);
    if (got != me) return bad("listed", (unsigned long)(long)got);
    if (dealloc(id)) return 1;
    if (find(&err) != 0 || err != ESRCH) return bad("found after its dealloc", err);
    put("xsys ok");
    say();
    return 0;
}

static int maker(void) {
    int me = (int)sys6(SYS_getpid, 0, 0, 0, 0, 0, 0).x0;
    unsigned int id = 0;
    long err = 0;
    if (set_band(me)) return 1;
    if (make(&id)) return 1;
    for (int i = 0; i < 200; i++) {
        if (find(&err) == 0) {
            if (err != ESRCH) return bad("find", err);
            put("xsys made");
            say();
            return 0;
        }
        nap();
    }
    return bad("the persona still there after 20 s", id);
}

static int finder(void) {
    int me = (int)sys6(SYS_getpid, 0, 0, 0, 0, 0, 0).x0;
    long err = 0;
    unsigned int id = 0;
    for (int i = 0; i < 200 && !(id = find(&err)); i++) {
        if (err != ESRCH) return bad("find", err);
        nap();
    }
    if (!id) return bad("no persona after 20 s", err);
    if (read_back(id)) return 1;
    int other = listed(0, me);
    if (other <= 0) return bad("the maker in the priority list", (unsigned long)(long)other);
    if (dealloc(id)) return 1;
    put("xsys found");
    say();
    return 0;
}

int main_entry(long argc, char **argv) {
    int status;
    if (argc > 1 && same(argv[1], "make")) status = maker();
    else if (argc > 1 && same(argv[1], "find")) status = finder();
    else status = both();
    sys6(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) {
    }
}

// The entry: a static program's stack has its argc, then its argv, at sp.
__attribute__((naked)) void start(void) {
    __asm__ volatile("ldr x0, [sp]\n\tadd x1, sp, #8\n\tb _main_entry");
}
