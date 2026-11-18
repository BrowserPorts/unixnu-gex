// Corpses (osfmk/corpses/corpse.c, kern_exit.c): a child that crashes with
// no EXC_CRASH handler becomes a corpse, and its task's EXC_CORPSE_NOTIFY
// handler is sent mach_exception_raise with the corpse's task and thread
// ports (control ports, a corpse's), code[0] EXC_CRASH and code[1] its exit
// reason's namespace and code. The child's end is published first: the
// parent reaps it while it holds the notification. The handler maps the
// corpse's crash information (task_map_corpse_info_64) and finds its items,
// reads the child's memory (vm_read, vm_region_64) and the crashed
// thread's registers from the corpse, is refused what needs a control conversion, and, once it lets go
// of the corpse's port, sees the corpse's thread port die. At most five
// corpses are in flight: a sixth crash while five are held makes none.

#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <limits.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("corpse: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static volatile uint64_t marker = 0x5eed0fc0ffee1234ull;

// The child: tells its parent where the marker is, then stores the
// marker's address to an unmapped page, the address in x20 at the fault.
static int crash(int fd) {
    uint64_t at = (uint64_t)&marker;
    if (write(fd, &at, sizeof at) != sizeof at) return 2;
    close(fd);
    void *p = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) return 3;
    munmap(p, 0x4000);
    register uint64_t x20 __asm__("x20") = at;
    register uint64_t x21 __asm__("x21") = (uint64_t)p;
    __asm__ volatile("str x20, [x21]" : : "r"(x20), "r"(x21) : "memory");
    return 4;
}

#pragma pack(4)
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t ndr;
    exception_type_t exc;
    mach_msg_type_number_t code_count;
    int64_t code[2];
    mach_msg_trailer_t trailer;
} request_t;

typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret;
} reply_t;
#pragma pack()

static char self[PATH_MAX];

// A crashing child whose task's EXC_CORPSE_NOTIFY handler is `port`; its
// pid, and the marker's address in it.
static pid_t spawn_crash(mach_port_t port, uint64_t *marker_at) {
    int fds[2];
    if (pipe(fds)) return -1;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    // (The read end may be fd 3 itself: closed before the write end goes
    // there.)
    posix_spawn_file_actions_addclose(&fa, fds[0]);
    posix_spawn_file_actions_adddup2(&fa, fds[1], 3);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    posix_spawnattr_setexceptionports_np(&at, EXC_MASK_CORPSE_NOTIFY, port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, 0);
    char *args[] = {self, "crash", NULL};
    char *env[] = {NULL};
    pid_t pid;
    if (posix_spawn(&pid, self, &fa, &at, args, env)) return -1;
    close(fds[1]);
    uint64_t a = 0;
    if (read(fds[0], &a, sizeof a) != sizeof a) return -1;
    close(fds[0]);
    if (marker_at) *marker_at = a;
    return pid;
}

static kern_return_t receive(mach_port_t port, request_t *req, mach_msg_timeout_t timeout) {
    memset(req, 0, sizeof *req);
    return mach_msg(&req->head, MACH_RCV_MSG | (timeout ? MACH_RCV_TIMEOUT : 0), 0, sizeof *req, port, timeout, MACH_PORT_NULL);
}

static void reply(request_t *req) {
    reply_t rep;
    memset(&rep, 0, sizeof rep);
    rep.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->head.msgh_bits), 0);
    rep.head.msgh_remote_port = req->head.msgh_remote_port;
    rep.head.msgh_id = req->head.msgh_id + 100;
    rep.head.msgh_size = sizeof rep;
    rep.ndr = NDR_record;
    rep.ret = KERN_SUCCESS;
    mach_msg(&rep.head, MACH_SEND_MSG, sizeof rep, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

// The item of type `ty` in a crash information buffer, and its size.
static const uint8_t *item(const uint8_t *b, uint64_t len, uint32_t ty, uint32_t *size) {
    uint64_t at = 0;
    while (at + 16 <= len) {
        uint32_t t, s;
        memcpy(&t, b + at, 4);
        memcpy(&s, b + at + 4, 4);
        if (t == 0xF19158EDu) return NULL;
        if (t == ty) {
            if (size) *size = s;
            return b + at + 16;
        }
        at += 16 + s;
    }
    return NULL;
}

static int one_corpse(void) {
    mach_port_t port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    uint64_t marker_at = 0;
    pid_t pid = spawn_crash(port, &marker_at);
    if (pid < 0) return bad("spawning", pid, 0);
    request_t req;
    kern_return_t kr = receive(port, &req, 0);
    if (kr) return bad("receiving the notification", kr, 0);
    if (req.head.msgh_id != 2405) return bad("message id", req.head.msgh_id, 2405);
    if (req.exc != EXC_CORPSE_NOTIFY) return bad("exception", req.exc, EXC_CORPSE_NOTIFY);
    if (req.code_count != 2) return bad("code count", req.code_count, 2);
    if (req.code[0] != EXC_CRASH) return bad("code[0]", req.code[0], EXC_CRASH);
    // OS_REASON_SIGNAL's namespace and the signal.
    if (req.code[1] != ((2ll << 32) | SIGSEGV)) return bad("code[1]", req.code[1], (2ll << 32) | SIGSEGV);
    mach_port_t task = req.task.name, thread = req.thread.name;

    // proc_exit came first: the child is reaped while its corpse is held.
    int st = 0;
    if (waitpid(pid, &st, WNOHANG) != pid) return bad("reaping the child before replying", 0, pid);
    if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGSEGV) return bad("child status", st, SIGSEGV);

    mach_vm_address_t kcd = 0;
    mach_vm_size_t kcd_size = 0;
    kr = task_map_corpse_info_64(mach_task_self(), task, &kcd, &kcd_size);
    if (kr) return bad("task_map_corpse_info_64", kr, 0);
    if (kcd_size != 0x4000) return bad("crash information size", kcd_size, 0x4000);
    const uint8_t *b = (const uint8_t *)kcd;
    uint32_t t0;
    memcpy(&t0, b, 4);
    if (t0 != 0xDEADF157u) return bad("TASK_CRASHINFO_BEGIN", t0, 0xDEADF157u);
    // The first items, in populate_corpse_crashinfo's order.
    static const uint32_t order[] = {0xDEADF157u, 0x80E, 0x805, 0x806, 0x81A, 0x802, 0x808, 0x810, 0x809, 0x80B, 0x80C, 0x80D, 0x814, 0x80F, 0x815, 0x812, 0x813, 0x816, 0x83F, 0x81D, 0x827};
    uint64_t at = 0;
    for (unsigned i = 0; i < sizeof order / sizeof order[0]; i++) {
        uint32_t t, s;
        memcpy(&t, b + at, 4);
        memcpy(&s, b + at + 4, 4);
        if (t != order[i]) return bad("item order", t, order[i]);
        at += 16 + s;
    }
    uint32_t sz;
    const uint8_t *p = item(b, kcd_size, 0x805, &sz);
    int32_t cpid;
    if (!p) return bad("TASK_CRASHINFO_PID", 0, 1);
    memcpy(&cpid, p, 4);
    if (cpid != pid) return bad("TASK_CRASHINFO_PID", cpid, pid);
    int64_t codes[2];
    p = item(b, kcd_size, 0x80E, &sz);
    if (!p || sz != 16) return bad("TASK_CRASHINFO_EXCEPTION_CODES", sz, 16);
    memcpy(codes, p, 16);
    // The signal, EXC_BAD_ACCESS and KERN_INVALID_ADDRESS (code[0]), the
    // fault's address (code[1]).
    if (codes[0] != ((SIGSEGV << 24) | (EXC_BAD_ACCESS << 20) | KERN_INVALID_ADDRESS)) return bad("crash code[0]", codes[0], (SIGSEGV << 24) | (EXC_BAD_ACCESS << 20) | KERN_INVALID_ADDRESS);
    p = item(b, kcd_size, 0x838, &sz);
    int32_t etype;
    if (!p) return bad("TASK_CRASHINFO_EXCEPTION_TYPE", 0, 1);
    memcpy(&etype, p, 4);
    if (etype != EXC_CRASH) return bad("TASK_CRASHINFO_EXCEPTION_TYPE", etype, EXC_CRASH);
    uint64_t crashed;
    p = item(b, kcd_size, 0x81A, &sz);
    if (!p) return bad("TASK_CRASHINFO_CRASHED_THREADID", 0, 1);
    memcpy(&crashed, p, 8);
    thread_identifier_info_data_t ti;
    mach_msg_type_number_t n = THREAD_IDENTIFIER_INFO_COUNT;
    kr = thread_info(thread, THREAD_IDENTIFIER_INFO, (thread_info_t)&ti, &n);
    if (kr) return bad("thread_info of the corpse's thread", kr, 0);
    if (ti.thread_id != crashed) return bad("crashed thread id", crashed, ti.thread_id);
    p = item(b, kcd_size, 0x837, &sz);
    uint32_t fork;
    if (!p) return bad("TASK_CRASHINFO_TASK_IS_CORPSE_FORK", 0, 1);
    memcpy(&fork, p, 4);
    if (fork != 0) return bad("TASK_CRASHINFO_TASK_IS_CORPSE_FORK", fork, 0);
    p = item(b, kcd_size, 0x1001, &sz);
    if (!p || sz != 32) return bad("EXIT_REASON_SNAPSHOT", sz, 32);
    vm_deallocate(mach_task_self(), (vm_address_t)kcd, (vm_size_t)kcd_size);

    // The child's memory, read from its corpse.
    vm_offset_t data = 0;
    mach_msg_type_number_t cnt = 0;
    kr = vm_read(task, marker_at, 8, &data, &cnt);
    if (kr) return bad("vm_read of the corpse", kr, 0);
    if (cnt != 8 || *(uint64_t *)data != 0x5eed0fc0ffee1234ull) return bad("the marker read", *(uint64_t *)data, 0x5eed0fc0ffee1234ull);
    vm_deallocate(mach_task_self(), data, cnt);
    vm_address_t raddr = marker_at;
    vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t ri;
    mach_msg_type_number_t rc = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kr = vm_region_64(task, &raddr, &rsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&ri, &rc, &obj);
    if (kr) return bad("vm_region_64 of the corpse", kr, 0);
    if (raddr > marker_at || raddr + rsize <= marker_at) return bad("the marker's region", raddr, marker_at);

    // Its threads, and the crashed one's registers.
    thread_act_array_t threads;
    mach_msg_type_number_t tc = 0;
    kr = task_threads(task, &threads, &tc);
    if (kr) return bad("task_threads of the corpse", kr, 0);
    if (tc != 1) return bad("the corpse's threads", tc, 1);
    mach_port_deallocate(mach_task_self(), threads[0]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads, tc * sizeof(thread_act_t));
    arm_thread_state64_t ts;
    mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&ts, &sc);
    if (kr) return bad("thread_get_state of the corpse's thread", kr, 0);
    if (ts.__x[20] != marker_at) return bad("x20 at the crash", ts.__x[20], marker_at);

    // What a control conversion would need is refused; a thread of a
    // corpse is not active.
    kr = task_suspend(task);
    if (kr != KERN_INVALID_ARGUMENT) return bad("task_suspend of a corpse", kr, KERN_INVALID_ARGUMENT);
    kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&ts, sc);
    if (kr != KERN_INVALID_ARGUMENT) return bad("thread_set_state of a corpse's thread", kr, KERN_INVALID_ARGUMENT);
    kr = thread_suspend(thread);
    if (kr != KERN_TERMINATED) return bad("thread_suspend of a corpse's thread", kr, KERN_TERMINATED);

    reply(&req);

    // The corpse lives while its port has senders: with the last gone, its
    // thread's port dies.
    mach_port_t notify;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify);
    mach_port_t prev = MACH_PORT_NULL;
    kr = mach_port_request_notification(mach_task_self(), thread, MACH_NOTIFY_DEAD_NAME, 0, notify, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
    if (kr) return bad("dead-name request on the corpse's thread", kr, 0);
    struct {
        mach_dead_name_notification_t n;
        mach_msg_trailer_t t;
    } dn;
    memset(&dn, 0, sizeof dn);
    kr = mach_msg(&dn.n.not_header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof dn, notify, 200, MACH_PORT_NULL);
    if (kr != MACH_RCV_TIMED_OUT) return bad("the thread's port while the corpse is held", kr, MACH_RCV_TIMED_OUT);
    mach_port_deallocate(mach_task_self(), task);
    kr = mach_msg(&dn.n.not_header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof dn, notify, 10000, MACH_PORT_NULL);
    if (kr) return bad("the dead-name notification", kr, 0);
    if (dn.n.not_header.msgh_id != MACH_NOTIFY_DEAD_NAME || dn.n.not_port != thread) return bad("dead name", dn.n.not_port, thread);
    mach_port_deallocate(mach_task_self(), thread);
    mach_port_deallocate(mach_task_self(), thread);
    mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
    mach_port_deallocate(mach_task_self(), port);
    mach_port_mod_refs(mach_task_self(), notify, MACH_PORT_RIGHT_RECEIVE, -1);
    return 0;
}

// Five corpses held: a sixth crash makes none; with them let go, a crash
// makes one again.
static int limit(void) {
    mach_port_t port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    request_t held[5];
    for (int i = 0; i < 5; i++) {
        pid_t pid = spawn_crash(port, NULL);
        if (pid < 0) return bad("spawning", i, 0);
        kern_return_t kr = receive(port, &held[i], 10000);
        if (kr) return bad("a held corpse's notification", kr, i);
        waitpid(pid, NULL, 0);
    }
    pid_t pid = spawn_crash(port, NULL);
    if (pid < 0) return bad("spawning the sixth", pid, 0);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFSIGNALED(st)) return bad("the sixth child's end", st, SIGSEGV);
    request_t req;
    kern_return_t kr = receive(port, &req, 500);
    if (kr != MACH_RCV_TIMED_OUT) return bad("a sixth corpse", kr, MACH_RCV_TIMED_OUT);
    for (int i = 0; i < 5; i++) {
        reply(&held[i]);
        mach_port_deallocate(mach_task_self(), held[i].task.name);
        mach_port_deallocate(mach_task_self(), held[i].thread.name);
    }
    pid = spawn_crash(port, NULL);
    if (pid < 0) return bad("spawning after", pid, 0);
    kr = receive(port, &req, 10000);
    if (kr) return bad("a corpse once the others are gone", kr, 0);
    reply(&req);
    mach_port_deallocate(mach_task_self(), req.task.name);
    mach_port_deallocate(mach_task_self(), req.thread.name);
    waitpid(pid, NULL, 0);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "crash")) return crash(3);
    uint32_t len = sizeof self;
    if (_NSGetExecutablePath(self, &len)) return bad("own path", 0, 0);
    if (one_corpse()) return 1;
    if (limit()) return 1;
    printf("corpse ok\n");
    return 0;
}
