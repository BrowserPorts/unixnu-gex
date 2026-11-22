// A Mach message from one process to another through a port one of them
// set as a host special port (the telemetry port, which a task entitled to
// monitor launchd's events may set: HOST_TELEMETRY_PORT, 20) and the other
// looked up there. With no argument, both in this one process: "xmach ok".
//
// For a caller that runs it twice at once in one system:
//   xmach serve   makes a port, sets it as the telemetry port, and waits
//                 (at most 20 s) for a message on it: "xmach got ID TEXT".
//   xmach send    looks the telemetry port up (until it is set, at most
//                 20 s) and sends it message 4242, "hello across":
//                 "xmach sent".

#define SYS_exit 1
#define SYS_write 4
#define SYS_select 93

#define MACH_port_allocate (-16)
#define MACH_port_insert_right (-21)
#define MACH_reply_port (-26)
#define MACH_task_self (-28)
#define MACH_host_self (-29)
#define MACH_msg2_trap (-47)

#define MACH_PORT_RIGHT_RECEIVE 1
#define MACH_MSG_TYPE_MAKE_SEND 20
#define MACH_MSG_TYPE_COPY_SEND 19
#define MACH_MSG_TYPE_MAKE_SEND_ONCE 21
#define MACH_MSGH_BITS_COMPLEX 0x80000000u

#define MACH64_SEND_MSG 0x1UL
#define MACH64_RCV_MSG 0x2UL
#define MACH64_RCV_TIMEOUT 0x100UL
#define MACH64_SEND_KOBJECT_CALL 0x200000000UL
#define MACH64_SEND_MQ_CALL 0x400000000UL

#define HOST_TELEMETRY_PORT 20
#define MSG_ID 4242

struct ret {
    long x0;
    long carry;
};

static struct ret bsd(long nr, long a0, long a1, long a2) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x16 __asm__("x16") = nr;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs" : "+r"(x0), "=r"(carry) : "r"(x1), "r"(x2), "r"(x16) : "memory", "cc");
    return (struct ret){x0, carry};
}

static long trap4(long nr, long a0, long a1, long a2, long a3) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x16 __asm__("x16") = nr;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x16) : "memory", "cc");
    return x0;
}

static long trap(long nr, long a0, long a1, long a2) {
    return trap4(nr, a0, a1, a2, 0);
}

// mach_msg2_trap(data, options, bits|send_size, remote|local, voucher|id,
// desc_count|rcv_name, rcv_size|priority, timeout), as libsystem_kernel's
// mach_msg makes it.
static long msg2(void *data, unsigned long options, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5, unsigned long a6, unsigned long timeout) {
    register long x0 __asm__("x0") = (long)data;
    register unsigned long x1 __asm__("x1") = options;
    register unsigned long x2 __asm__("x2") = a2;
    register unsigned long x3 __asm__("x3") = a3;
    register unsigned long x4 __asm__("x4") = a4;
    register unsigned long x5 __asm__("x5") = a5;
    register unsigned long x6 __asm__("x6") = a6;
    register unsigned long x7 __asm__("x7") = timeout;
    register long x16 __asm__("x16") = MACH_msg2_trap;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x7), "r"(x16) : "memory", "cc");
    return x0;
}

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
    bsd(SYS_write, 1, (long)line, at);
    at = 0;
}

static int same(const char *a, const char *b) {
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

static void nap(void) {
    long tv[2] = {0, 100000};
    register long x0 __asm__("x0") = 0;
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = (long)tv;
    register long x16 __asm__("x16") = SYS_select;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x16) : "memory", "cc");
}

// host_set_special_port(host_priv, which, port): host_priv routine 413,
// the port as a COPY_SEND descriptor; the reply's RetCode.
static long set_special(unsigned int host, int which, unsigned int port) {
    unsigned int msg[16] = {0};
    unsigned int reply = (unsigned int)trap(MACH_reply_port, 0, 0, 0);
    unsigned int bits = MACH_MSGH_BITS_COMPLEX | MACH_MSG_TYPE_COPY_SEND | (MACH_MSG_TYPE_MAKE_SEND_ONCE << 8);
    msg[0] = bits;
    msg[1] = 52;
    msg[2] = host;
    msg[3] = reply;
    msg[5] = 413;
    msg[6] = 1;                                    // msgh_descriptor_count
    msg[7] = port;                                 // name
    msg[9] = (unsigned int)MACH_MSG_TYPE_COPY_SEND << 16; // pad2, disposition, type 0
    msg[10] = 0;                                   // NDR
    msg[11] = 0;
    msg[12] = (unsigned int)which;
    long kr = msg2(msg, MACH64_SEND_MSG | MACH64_RCV_MSG | MACH64_SEND_KOBJECT_CALL, bits | (52UL << 32), host | ((unsigned long)reply << 32),
                   413UL << 32, 1 | ((unsigned long)reply << 32), sizeof msg, 0);
    if (kr != 0) return kr;
    if (msg[5] != 513) return -1;
    return (int)msg[8];
}

// host_get_special_port(host_priv, node, which): routine 412; the send
// right the reply's descriptor carries (0 for none), or -1.
static long get_special(unsigned int host, int which, unsigned int *port) {
    unsigned int msg[16] = {0};
    unsigned int reply = (unsigned int)trap(MACH_reply_port, 0, 0, 0);
    unsigned int bits = MACH_MSG_TYPE_COPY_SEND | (MACH_MSG_TYPE_MAKE_SEND_ONCE << 8);
    msg[0] = bits;
    msg[1] = 40;
    msg[2] = host;
    msg[3] = reply;
    msg[5] = 412;
    msg[8] = 0;                 // node (the NDR before it)
    msg[9] = (unsigned int)which;
    long kr = msg2(msg, MACH64_SEND_MSG | MACH64_RCV_MSG | MACH64_SEND_KOBJECT_CALL, bits | (40UL << 32), host | ((unsigned long)reply << 32),
                   412UL << 32, (unsigned long)reply << 32, sizeof msg, 0);
    if (kr != 0) return kr;
    if (msg[5] != 512) return -1;
    if (!(msg[0] & MACH_MSGH_BITS_COMPLEX)) return (int)msg[8];
    *port = msg[7];
    return 0;
}

static long make_port(unsigned int *port) {
    unsigned int task = (unsigned int)trap(MACH_task_self, 0, 0, 0);
    long kr = trap(MACH_port_allocate, task, MACH_PORT_RIGHT_RECEIVE, (long)port);
    if (kr != 0) return kr;
    // _kernelrpc_mach_port_insert_right_trap(task, name, poly, polyPoly)
    return trap4(MACH_port_insert_right, task, *port, *port, MACH_MSG_TYPE_MAKE_SEND);
}

static const char text[] = "hello across";

static long send(unsigned int port) {
    unsigned int msg[12] = {0};
    unsigned int bits = MACH_MSG_TYPE_COPY_SEND;
    msg[0] = bits;
    msg[1] = 24 + 16;
    msg[2] = port;
    msg[5] = MSG_ID;
    for (int i = 0; i < (int)sizeof text - 1 && i < 16; i++) ((char *)&msg[6])[i] = text[i];
    return msg2(msg, MACH64_SEND_MSG | MACH64_SEND_MQ_CALL, bits | (40UL << 32), port, (unsigned long)MSG_ID << 32, 0, 0, 0);
}

static long receive(unsigned int port, unsigned int *id, char *got) {
    unsigned int msg[32] = {0};
    long kr = msg2(msg, MACH64_RCV_MSG | MACH64_RCV_TIMEOUT, 0, 0, 0, (unsigned long)port << 32, sizeof msg, 20000);
    if (kr != 0) return kr;
    *id = msg[5];
    for (int i = 0; i < 16; i++) got[i] = ((char *)&msg[6])[i];
    got[16] = 0;
    return 0;
}

void main_entry(long argc, char **argv) {
    long status = 0;
    unsigned int host = (unsigned int)trap(MACH_host_self, 0, 0, 0);
    if (argc < 2) {
        unsigned int port = 0, found = 0, id = 0;
        char got[17];
        long kr = 0;
        if ((kr = make_port(&port))) status = 1;
        else if ((kr = set_special(host, HOST_TELEMETRY_PORT, port))) status = 2;
        else if ((kr = get_special(host, HOST_TELEMETRY_PORT, &found)) || found == 0) status = 3;
        else if ((kr = send(found))) status = 4;
        else if ((kr = receive(port, &id, got)) || id != MSG_ID || !same(got, text)) status = 5;
        if (!status) {
            put("xmach ok");
        } else {
            put("xmach step ");
            num((unsigned long)status);
            put(" ");
            num((unsigned long)kr);
        }
        say();
    } else if (argc == 2 && same(argv[1], "serve")) {
        unsigned int port = 0, id = 0;
        char got[17];
        long kr;
        if (make_port(&port)) status = 1;
        else if ((kr = set_special(host, HOST_TELEMETRY_PORT, port))) {
            put("xmach set ");
            num((unsigned long)kr);
            say();
            status = 2;
        } else if ((kr = receive(port, &id, got))) {
            put("xmach receive ");
            num((unsigned long)kr);
            say();
            status = 3;
        } else {
            put("xmach got ");
            num(id);
            put(" ");
            put(got);
            say();
        }
    } else if (argc == 2 && same(argv[1], "send")) {
        unsigned int found = 0;
        long kr = 0;
        for (int i = 0; i < 200 && found == 0; i++) {
            if ((kr = get_special(host, HOST_TELEMETRY_PORT, &found))) break;
            if (!found) nap();
        }
        if (kr || !found) {
            put("xmach lookup ");
            num((unsigned long)kr);
            say();
            status = 1;
        } else if ((kr = send(found))) {
            put("xmach send ");
            num((unsigned long)kr);
            say();
            status = 2;
        } else {
            put("xmach sent");
            say();
        }
    } else {
        status = 64;
    }
    bsd(SYS_exit, status, 0, 0);
    for (;;) {
    }
}

// The entry: a static program's stack has its argc, then its argv, at sp.
__attribute__((naked)) void start(void) {
    __asm__ volatile("ldr x0, [sp]\n\tadd x1, sp, #8\n\tb _main_entry");
}
