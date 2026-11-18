// Corpse forks (osfmk/corpses/corpse.c's task_generate_corpse_internal,
// task.c's task_duplicate_map_and_threads, vm_map_fork in corpse mode).
// A live child's task_generate_corpse of itself gives a corpse (its port
// movable, sent to the parent) whose memory is the child's at the fork (a
// write the child makes after is not the corpse's), whose threads are
// copies of the child's with ids of their own, held for inspection, the
// calling thread's copy the crashed one, and whose crash information says
// it is a fork: the child's pid, exception type and codes 0, no exit time;
// the child goes on. A corpse's own fork is refused. At most five corpses
// are in flight.
// os_fault_with_payload makes a fork corpse for the child's EXC_CORPSE_NOTIFY
// handler, its codes {EXC_GUARD, 0}, its crash information the simulated
// guard's codes and the reason's snapshot; a second fault while the first
// is held is refused (one user fault in flight). A soft memory limit
// crossed makes one for EXC_RESOURCE, its code the high watermark's.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <pthread.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

int os_fault_with_payload(uint32_t reason_namespace, uint64_t reason_code, void *payload, uint32_t payload_size, const char *reason_string, uint64_t reason_flags);
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

#define MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES 7
#define FAULT_NS 9
#define FAULT_CODE 0x1234

static int bad(const char *what, long got, long want) {
    printf("corpsefork: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static volatile uint64_t value = 0x1111;
static char self[PATH_MAX];

#pragma pack(4)
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t task;
    uint64_t addr;
    uint64_t ids[2];
    uint64_t handle;
    mach_msg_trailer_t trailer;
} hello_t;

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

static void *idle(void *arg) {
    (void)arg;
    for (;;) pause();
    return NULL;
}

static int child_cmd(void) {
    char c = 0;
    return read(4, &c, 1) == 1 ? c : -1;
}

static void child_say(int v) {
    (void)!write(3, &v, sizeof v);
}

// The child: "live" forks a corpse of itself and sends its port, the
// value's address and its threads' ids and handle to its bootstrap port,
// then writes the value when told; "fault" makes a user
// fault, and another when told; "soft" crosses a soft memory limit. Each
// ends when told.
static int thread_ident(mach_port_t t, thread_identifier_info_data_t *ti) {
    mach_msg_type_number_t n = THREAD_IDENTIFIER_INFO_COUNT;
    return thread_info(t, THREAD_IDENTIFIER_INFO, (thread_info_t)ti, &n);
}

static int child(const char *how) {
    pthread_t t;
    pthread_create(&t, NULL, idle, NULL);
    if (!strcmp(how, "live")) {
        mach_port_t bp = MACH_PORT_NULL;
        if (task_get_bootstrap_port(mach_task_self(), &bp) || !MACH_PORT_VALID(bp)) return 2;
        hello_t m;
        memset(&m, 0, sizeof m);
        m.head.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
        m.head.msgh_size = sizeof m - sizeof m.trailer;
        m.head.msgh_remote_port = bp;
        m.body.msgh_descriptor_count = 1;
        mach_port_t corpse = MACH_PORT_NULL;
        if (task_generate_corpse(mach_task_self(), &corpse)) return 11;
        thread_identifier_info_data_t a, b;
        mach_port_t me = mach_thread_self();
        if (thread_ident(me, &a) || thread_ident(pthread_mach_thread_np(t), &b)) return 12;
        m.ids[0] = a.thread_id;
        m.ids[1] = b.thread_id;
        m.handle = a.thread_handle;
        m.task.name = corpse;
        m.task.disposition = MACH_MSG_TYPE_MOVE_SEND;
        m.task.type = MACH_MSG_PORT_DESCRIPTOR;
        m.addr = (uint64_t)&value;
        if (mach_msg(&m.head, MACH_SEND_MSG, m.head.msgh_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL)) return 3;
        for (;;) {
            int c = child_cmd();
            if (c == 'w') {
                value = 0x2222;
                child_say((int)value);
            } else {
                return c == 'x' ? 0 : 4;
            }
        }
    }
    if (!strcmp(how, "fault")) {
        int r = os_fault_with_payload(FAULT_NS, FAULT_CODE, NULL, 0, "corpsefork", 0);
        child_say(r ? errno : 0);
        if (child_cmd() != 'f') return 5;
        r = os_fault_with_payload(FAULT_NS, FAULT_CODE, NULL, 0, "corpsefork", 0);
        child_say(r ? errno : 0);
        return child_cmd() == 'x' ? 0 : 6;
    }
    if (!strcmp(how, "soft")) {
        struct {
            int32_t active;
            uint32_t active_attr;
            int32_t inactive;
            uint32_t inactive_attr;
        } p = {48, 0, 48, 0};
        if (memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, getpid(), 0, &p, sizeof p)) return 7;
        char *m = mmap(NULL, 64 << 20, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (m == MAP_FAILED) return 8;
        for (size_t i = 0; i < (64u << 20); i += 4096) m[i] = 1;
        child_say(0);
        return child_cmd() == 'x' ? 0 : 9;
    }
    return 10;
}

typedef struct {
    pid_t pid;
    int cmd, ack;
} kid_t;

// A child running `how`, its EXC_CORPSE_NOTIFY handler `exc` and its
// bootstrap port `boot` (either may be null).
static int spawn_child(const char *how, mach_port_t exc, mach_port_t boot, kid_t *k) {
    int to[2], from[2];
    if (pipe(to) || pipe(from)) return -1;
    // Above 4, so that neither dup2 overwrites the other's source.
    for (int *f = to; f < to + 2; f++) {
        int n = fcntl(*f, F_DUPFD, 10);
        close(*f);
        *f = n;
    }
    for (int *f = from; f < from + 2; f++) {
        int n = fcntl(*f, F_DUPFD, 10);
        close(*f);
        *f = n;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, from[1], 3);
    posix_spawn_file_actions_adddup2(&fa, to[0], 4);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    if (exc) posix_spawnattr_setexceptionports_np(&at, EXC_MASK_CORPSE_NOTIFY, exc, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, 0);
    if (boot) posix_spawnattr_setspecialport_np(&at, boot, TASK_BOOTSTRAP_PORT);
    char *args[] = {self, "child", (char *)how, NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    if (posix_spawn(&k->pid, self, &fa, &at, args, env)) return -1;
    close(to[0]);
    close(from[1]);
    k->cmd = to[1];
    k->ack = from[0];
    return 0;
}

static int tell(kid_t *k, char c) {
    return write(k->cmd, &c, 1) == 1 ? 0 : -1;
}

static int heard(kid_t *k) {
    int v = -1;
    return read(k->ack, &v, sizeof v) == sizeof v ? v : -1;
}

static mach_port_t new_port(void) {
    mach_port_t p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    return p;
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

static uint64_t u64_at(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static uint32_t u32_at(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

// The corpse's crash information, mapped.
static int crashinfo(mach_port_t corpse, const uint8_t **b) {
    mach_vm_address_t kcd = 0;
    mach_vm_size_t size = 0;
    kern_return_t kr = task_map_corpse_info_64(mach_task_self(), corpse, &kcd, &size);
    if (kr) return bad("task_map_corpse_info_64", kr, 0);
    if (size != 0x4000) return bad("crash information size", size, 0x4000);
    *b = (const uint8_t *)kcd;
    return 0;
}

// Releasing the corpse's port ends it: its thread's port dies.
static int release(mach_port_t corpse, mach_port_t thread) {
    mach_port_t notify;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify);
    mach_port_t prev = MACH_PORT_NULL;
    kern_return_t kr = mach_port_request_notification(mach_task_self(), thread, MACH_NOTIFY_DEAD_NAME, 0, notify, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
    if (kr) return bad("dead-name request on the corpse's thread", kr, 0);
    mach_port_deallocate(mach_task_self(), corpse);
    struct {
        mach_dead_name_notification_t n;
        mach_msg_trailer_t t;
    } dn;
    memset(&dn, 0, sizeof dn);
    kr = mach_msg(&dn.n.not_header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof dn, notify, 10000, MACH_PORT_NULL);
    if (kr) return bad("the corpse's end", kr, 0);
    mach_port_deallocate(mach_task_self(), thread);
    mach_port_deallocate(mach_task_self(), thread);
    mach_port_mod_refs(mach_task_self(), notify, MACH_PORT_RIGHT_RECEIVE, -1);
    return 0;
}

// task_generate_corpse, past corpses still being let go.
static kern_return_t generate(task_t task, mach_port_t *corpse) {
    kern_return_t kr = KERN_FAILURE;
    for (int i = 0; i < 200; i++) {
        kr = task_generate_corpse(task, corpse);
        if (kr != KERN_RESOURCE_SHORTAGE) break;
        usleep(10000);
    }
    return kr;
}

static int live(void) {
    mach_port_t boot = new_port();
    kid_t k;
    if (spawn_child("live", 0, boot, &k)) return bad("spawning", 0, 0);
    hello_t h;
    memset(&h, 0, sizeof h);
    kern_return_t kr = mach_msg(&h.head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof h, boot, 10000, MACH_PORT_NULL);
    if (kr) return bad("the child's corpse", kr, 0);
    mach_port_t corpse = h.task.name;
    // The child writes after the fork: its corpse keeps what was there.
    int v = 0;
    if (tell(&k, 'w') || (v = heard(&k)) != 0x2222) {
        int st = 0;
        waitpid(k.pid, &st, 0);
        return bad("the child's write (its status)", st, 0x2222);
    }
    vm_offset_t data = 0;
    mach_msg_type_number_t cnt = 0;
    kr = vm_read(corpse, h.addr, 8, &data, &cnt);
    if (kr || cnt != 8) return bad("vm_read of the corpse", kr, 0);
    if (*(uint64_t *)data != 0x1111) return bad("the corpse's value", *(uint64_t *)data, 0x1111);
    vm_deallocate(mach_task_self(), data, cnt);

    // Its threads: copies of the child's, with ids of their own.
    thread_act_array_t ct;
    mach_msg_type_number_t cn = 0;
    if ((kr = task_threads(corpse, &ct, &cn))) return bad("task_threads of the corpse", kr, 0);
    if (cn != 2) return bad("the corpse's threads", cn, 2);
    thread_identifier_info_data_t c0, c1;
    if ((kr = thread_ident(ct[0], &c0)) || (kr = thread_ident(ct[1], &c1))) return bad("thread_info of the corpse's threads", kr, 0);
    for (int i = 0; i < 2; i++) {
        if (c0.thread_id == h.ids[i] || c1.thread_id == h.ids[i]) return bad("a corpse thread's id", h.ids[i], 0);
    }
    arm_thread_state64_t ts;
    mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
    if ((kr = thread_get_state(ct[1], ARM_THREAD_STATE64, (thread_state_t)&ts, &sc))) return bad("thread_get_state of a corpse thread", kr, 0);
    if (ts.__pc == 0 || ts.__sp == 0) return bad("a corpse thread's registers", ts.__pc, 1);
    kr = thread_suspend(ct[1]);
    if (kr != KERN_TERMINATED) return bad("thread_suspend of a corpse thread", kr, KERN_TERMINATED);

    const uint8_t *b;
    if (crashinfo(corpse, &b)) return 1;
    uint32_t sz;
    const uint8_t *p = item(b, 0x4000, 0x837, &sz);
    if (!p || u32_at(p) != 1) return bad("TASK_CRASHINFO_TASK_IS_CORPSE_FORK", p ? u32_at(p) : -1, 1);
    p = item(b, 0x4000, 0x805, &sz);
    if (!p || (pid_t)u32_at(p) != k.pid) return bad("TASK_CRASHINFO_PID", p ? u32_at(p) : -1, k.pid);
    p = item(b, 0x4000, 0x838, &sz);
    if (!p || u32_at(p) != 0) return bad("TASK_CRASHINFO_EXCEPTION_TYPE", p ? u32_at(p) : -1, 0);
    p = item(b, 0x4000, 0x80E, &sz);
    if (!p || sz != 16 || u64_at(p) != 0 || u64_at(p + 8) != 0) return bad("TASK_CRASHINFO_EXCEPTION_CODES", p ? u64_at(p) : -1, 0);
    // The calling thread's copy is the crashed thread: its TSD base is the
    // caller's.
    p = item(b, 0x4000, 0x81A, &sz);
    if (!p) return bad("TASK_CRASHINFO_CRASHED_THREADID", 0, 1);
    uint64_t crashed = u64_at(p);
    thread_identifier_info_data_t *cc = crashed == c0.thread_id ? &c0 : crashed == c1.thread_id ? &c1 : NULL;
    if (!cc) return bad("the crashed thread among the corpse's", crashed, c0.thread_id);
    if (cc->thread_handle != h.handle) return bad("the crashed thread's handle", cc->thread_handle, h.handle);
    // rusage_info_v6: a start time, no exit time.
    p = item(b, 0x4000, 0x808, &sz);
    if (!p || u64_at(p + 80) == 0 || u64_at(p + 88) != 0) return bad("ri_proc_exit_abstime", p ? u64_at(p + 88) : -1, 0);
    if (item(b, 0x4000, 0x1001, &sz)) return bad("an exit reason snapshot", 1, 0);
    vm_deallocate(mach_task_self(), (vm_address_t)b, 0x4000);

    // A corpse is no task to fork.
    mach_port_t again = MACH_PORT_NULL;
    kr = task_generate_corpse(corpse, &again);
    if (kr != KERN_INVALID_ARGUMENT) return bad("task_generate_corpse of a corpse", kr, KERN_INVALID_ARGUMENT);

    // The child goes on.
    int st = 0;
    if (waitpid(k.pid, &st, WNOHANG) != 0) return bad("the child after the fork", st, 0);
    if (tell(&k, 'w') || heard(&k) != 0x2222) return bad("the child, after", 0, 0);
    mach_port_deallocate(mach_task_self(), ct[1]);
    if (release(corpse, ct[0])) return 1;
    if (tell(&k, 'x')) return bad("ending the child", 0, 0);
    if (waitpid(k.pid, &st, 0) != k.pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("the child's end", st, 0);
    return 0;
}

// At most five corpses in flight: a sixth fork is refused until they go.
static int limit(void) {
    mach_port_t held[5], again;
    for (int i = 0; i < 5; i++) {
        kern_return_t kr = generate(mach_task_self(), &held[i]);
        if (kr) return bad("a held fork", kr, i);
    }
    kern_return_t kr = task_generate_corpse(mach_task_self(), &again);
    if (kr != KERN_RESOURCE_SHORTAGE) return bad("a sixth fork", kr, KERN_RESOURCE_SHORTAGE);
    for (int i = 0; i < 5; i++) mach_port_deallocate(mach_task_self(), held[i]);
    kr = generate(mach_task_self(), &again);
    if (kr) return bad("a fork once the others are gone", kr, 0);
    mach_port_deallocate(mach_task_self(), again);
    return 0;
}

static int own(void) {
    mach_port_t corpse = MACH_PORT_NULL;
    kern_return_t kr = generate(mach_task_self(), &corpse);
    if (kr) return bad("task_generate_corpse of itself", kr, 0);
    thread_identifier_info_data_t me;
    mach_port_t mt = mach_thread_self();
    if (thread_ident(mt, &me)) return bad("thread_info of itself", 0, 0);
    mach_port_deallocate(mach_task_self(), mt);
    const uint8_t *b;
    if (crashinfo(corpse, &b)) return 1;
    uint32_t sz;
    const uint8_t *p = item(b, 0x4000, 0x81A, &sz);
    if (!p) return bad("TASK_CRASHINFO_CRASHED_THREADID", 0, 1);
    uint64_t crashed = u64_at(p);
    vm_deallocate(mach_task_self(), (vm_address_t)b, 0x4000);
    // The calling thread's copy is the crashed thread.
    thread_act_array_t ct;
    mach_msg_type_number_t cn = 0;
    if ((kr = task_threads(corpse, &ct, &cn))) return bad("task_threads of the own corpse", kr, 0);
    int found = 0;
    for (unsigned i = 0; i < cn; i++) {
        thread_identifier_info_data_t ti;
        if (!thread_ident(ct[i], &ti) && ti.thread_id == crashed) {
            if (ti.thread_handle != me.thread_handle) return bad("the crashed thread's handle", ti.thread_handle, me.thread_handle);
            found = 1;
        }
    }
    if (!found) return bad("the crashed thread among the corpse's", crashed, 1);
    mach_port_t th0 = ct[0];
    for (unsigned i = 1; i < cn; i++) mach_port_deallocate(mach_task_self(), ct[i]);
    return release(corpse, th0);
}

static int receive(mach_port_t port, request_t *req) {
    memset(req, 0, sizeof *req);
    kern_return_t kr = mach_msg(&req->head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof *req, port, 20000, MACH_PORT_NULL);
    if (kr) return bad("receiving the notification", kr, 0);
    if (req->head.msgh_id != 2405) return bad("message id", req->head.msgh_id, 2405);
    if (req->exc != EXC_CORPSE_NOTIFY) return bad("exception", req->exc, EXC_CORPSE_NOTIFY);
    if (req->code_count != 2) return bad("code count", req->code_count, 2);
    return 0;
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

static int fault(void) {
    mach_port_t port = new_port();
    kid_t k;
    if (spawn_child("fault", port, 0, &k)) return bad("spawning", 0, 0);
    int r = heard(&k);
    if (r != 0) return bad("os_fault_with_payload", r, 0);
    request_t req;
    if (receive(port, &req)) return 1;
    if (req.code[0] != EXC_GUARD || req.code[1] != 0) return bad("the notification's codes", req.code[0], EXC_GUARD);
    const uint8_t *b;
    if (crashinfo(req.task.name, &b)) return 1;
    uint32_t sz;
    const uint8_t *p = item(b, 0x4000, 0x837, &sz);
    if (!p || u32_at(p) != 1) return bad("TASK_CRASHINFO_TASK_IS_CORPSE_FORK", p ? u32_at(p) : -1, 1);
    p = item(b, 0x4000, 0x838, &sz);
    if (!p || u32_at(p) != EXC_GUARD) return bad("TASK_CRASHINFO_EXCEPTION_TYPE", p ? u32_at(p) : -1, EXC_GUARD);
    p = item(b, 0x4000, 0x80E, &sz);
    // GUARD_TYPE_USER, flavor 0, the namespace its target; the code.
    if (!p || u64_at(p) != ((3ull << 61) | FAULT_NS) || u64_at(p + 8) != FAULT_CODE) return bad("TASK_CRASHINFO_EXCEPTION_CODES", p ? u64_at(p) : -1, (3ull << 61) | FAULT_NS);
    p = item(b, 0x4000, 0x1001, &sz);
    // (struct exit_reason_snapshot is packed: the code follows the
    // namespace.)
    if (!p || sz != 32 || u32_at(p) != FAULT_NS || u64_at(p + 4) != FAULT_CODE) return bad("EXIT_REASON_SNAPSHOT", p ? u64_at(p + 4) : -1, FAULT_CODE);
    p = item(b, 0x4000, 0x805, &sz);
    if (!p || (pid_t)u32_at(p) != k.pid) return bad("TASK_CRASHINFO_PID", p ? u32_at(p) : -1, k.pid);
    // The faulting thread's copy is the crashed thread, the one the
    // notification names.
    thread_identifier_info_data_t ti;
    if (thread_ident(req.thread.name, &ti)) return bad("thread_info of the corpse's thread", 0, 0);
    p = item(b, 0x4000, 0x81A, &sz);
    if (!p || u64_at(p) != ti.thread_id) return bad("TASK_CRASHINFO_CRASHED_THREADID", p ? u64_at(p) : -1, ti.thread_id);
    p = item(b, 0x4000, 0x808, &sz);
    if (!p || u64_at(p + 88) != 0) return bad("ri_proc_exit_abstime", p ? u64_at(p + 88) : -1, 0);
    vm_deallocate(mach_task_self(), (vm_address_t)b, 0x4000);
    int st = 0;
    if (waitpid(k.pid, &st, WNOHANG) != 0) return bad("the child after its fault", st, 0);
    // One user fault in flight: the second is refused.
    if (tell(&k, 'f') || (r = heard(&k)) != EBUSY) return bad("a second user fault", r, EBUSY);
    reply(&req);
    if (release(req.task.name, req.thread.name)) return 1;
    if (tell(&k, 'x') || waitpid(k.pid, &st, 0) != k.pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("the child's end", st, 0);
    mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
    mach_port_deallocate(mach_task_self(), port);
    return 0;
}

static int soft(void) {
    mach_port_t port = new_port();
    kid_t k;
    if (spawn_child("soft", port, 0, &k)) return bad("spawning", 0, 0);
    int r = heard(&k);
    if (r != 0) return bad("the child's memory", r, 0);
    request_t req;
    if (receive(port, &req)) return 1;
    if (req.code[0] != EXC_RESOURCE || req.code[1] != 0) return bad("the notification's codes", req.code[0], EXC_RESOURCE);
    const uint8_t *b;
    if (crashinfo(req.task.name, &b)) return 1;
    uint32_t sz;
    const uint8_t *p = item(b, 0x4000, 0x80E, &sz);
    // RESOURCE_TYPE_MEMORY, FLAVOR_HIGH_WATERMARK, the limit in MB.
    uint64_t want = (3ull << 61) | (1ull << 58) | 48;
    if (!p || u64_at(p) != want || u64_at(p + 8) != 0) return bad("TASK_CRASHINFO_EXCEPTION_CODES", p ? u64_at(p) : -1, want);
    p = item(b, 0x4000, 0x837, &sz);
    if (!p || u32_at(p) != 1) return bad("TASK_CRASHINFO_TASK_IS_CORPSE_FORK", p ? u32_at(p) : -1, 1);
    p = item(b, 0x4000, 0x838, &sz);
    if (!p || u32_at(p) != EXC_RESOURCE) return bad("TASK_CRASHINFO_EXCEPTION_TYPE", p ? u32_at(p) : -1, EXC_RESOURCE);
    vm_deallocate(mach_task_self(), (vm_address_t)b, 0x4000);
    int st = 0;
    if (waitpid(k.pid, &st, WNOHANG) != 0) return bad("the child past a soft limit", st, 0);
    reply(&req);
    if (release(req.task.name, req.thread.name)) return 1;
    if (tell(&k, 'x') || waitpid(k.pid, &st, 0) != k.pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("the child's end", st, 0);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 2 && !strcmp(argv[1], "child")) return child(argv[2]);
    signal(SIGPIPE, SIG_IGN);
    uint32_t len = sizeof self;
    if (_NSGetExecutablePath(self, &len)) return bad("own path", 0, 0);
    if (live()) return 1;
    if (own()) return 1;
    if (limit()) return 1;
    if (fault()) return 1;
    if (soft()) return 1;
    printf("corpsefork ok\n");
    return 0;
}
