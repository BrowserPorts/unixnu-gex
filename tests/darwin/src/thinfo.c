// thread_info by thread.c's thread_info_internal: the count each flavor
// needs (KERN_INVALID_ARGUMENT short of it); THREAD_BASIC_INFO of the
// caller (running, timesharing, no system time on the release kernel,
// which counts a thread's time in the kernel as user time), of a thread
// waiting in read() (waiting, its kernel stack kept, as msleep has no
// continuation), of one waiting in mach_msg's receive (its stack discarded
// at ipc_mqueue_receive_continue), of one made suspended (uninterruptible,
// never run, so no stack, and one user stop), of a suspended one (its stop
// counted), and of a spinning one (its CPU usage); THREAD_IDENTIFIER_INFO
// leaves the caller's count; THREAD_SCHED_RR_INFO of a timesharing thread
// and THREAD_SCHED_FIFO_INFO are KERN_INVALID_POLICY;
// THREAD_DEBUG_INFO_INTERNAL is KERN_NOT_SUPPORTED on a release kernel;
// an unknown flavor is KERN_INVALID_ARGUMENT.

#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static int p[2];
static mach_port_t rcv;
static volatile int stop;
static volatile unsigned long spins;

static int bad(const char *what, long got, long want) {
    printf("thinfo: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static void *reader(void *a) {
    (void)a;
    char c;
    read(p[0], &c, 1);
    return NULL;
}

static void *receiver(void *a) {
    (void)a;
    struct {
        mach_msg_header_t h;
        mach_msg_trailer_t t;
    } m;
    mach_msg(&m.h, MACH_RCV_MSG, 0, sizeof m, rcv, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    return NULL;
}

static void *spin(void *a) {
    (void)a;
    while (!stop) spins++;
    return NULL;
}

static void *nothing(void *a) {
    return a;
}

static kern_return_t basic(thread_act_t th, thread_basic_info_data_t *bi) {
    mach_msg_type_number_t n = THREAD_BASIC_INFO_COUNT;
    kern_return_t kr = thread_info(th, THREAD_BASIC_INFO, (thread_info_t)bi, &n);
    if (!kr && n != THREAD_BASIC_INFO_COUNT) return KERN_FAILURE;
    return kr;
}

// Waits, as long as it takes, for th to be waiting in its call.
static kern_return_t until_waiting(thread_act_t th, thread_basic_info_data_t *bi) {
    kern_return_t kr;
    while (!(kr = basic(th, bi)) && bi->run_state != TH_STATE_WAITING) usleep(1000);
    return kr;
}

int main(void) {
    kern_return_t kr;
    thread_basic_info_data_t bi;
    integer_t w[THREAD_INFO_MAX];
    mach_msg_type_number_t n;
    thread_act_t self = mach_thread_self();

    // Its own.
    if ((kr = basic(self, &bi))) return bad("the caller's basic info", kr, 0);
    if (bi.run_state != TH_STATE_RUNNING) return bad("the caller's run state", bi.run_state, TH_STATE_RUNNING);
    if (bi.policy != POLICY_TIMESHARE) return bad("its policy", bi.policy, POLICY_TIMESHARE);
    if (bi.flags || bi.suspend_count || bi.sleep_time) return bad("its flags, suspend count and sleep time", bi.flags | bi.suspend_count | bi.sleep_time, 0);
    if (bi.system_time.seconds || bi.system_time.microseconds) return bad("its system time", bi.system_time.microseconds, 0);
    if (bi.user_time.microseconds >= 1000000) return bad("its user time's microseconds", bi.user_time.microseconds, 0);
    if (bi.cpu_usage < 0 || bi.cpu_usage > TH_USAGE_SCALE) return bad("its CPU usage", bi.cpu_usage, TH_USAGE_SCALE);

    // The counts.
    n = THREAD_BASIC_INFO_COUNT - 1;
    if ((kr = thread_info(self, THREAD_BASIC_INFO, w, &n)) != KERN_INVALID_ARGUMENT) return bad("basic info short", kr, KERN_INVALID_ARGUMENT);
    n = THREAD_IDENTIFIER_INFO_COUNT - 1;
    if ((kr = thread_info(self, THREAD_IDENTIFIER_INFO, w, &n)) != KERN_INVALID_ARGUMENT) return bad("identifier info short", kr, KERN_INVALID_ARGUMENT);
    n = THREAD_EXTENDED_INFO_COUNT - 1;
    if ((kr = thread_info(self, THREAD_EXTENDED_INFO, w, &n)) != KERN_INVALID_ARGUMENT) return bad("extended info short", kr, KERN_INVALID_ARGUMENT);
    n = POLICY_TIMESHARE_INFO_COUNT - 1;
    if ((kr = thread_info(self, THREAD_SCHED_TIMESHARE_INFO, w, &n)) != KERN_INVALID_ARGUMENT) return bad("timeshare info short", kr, KERN_INVALID_ARGUMENT);
    n = POLICY_RR_INFO_COUNT - 1;
    if ((kr = thread_info(self, THREAD_SCHED_RR_INFO, w, &n)) != KERN_INVALID_ARGUMENT) return bad("RR info short", kr, KERN_INVALID_ARGUMENT);
    n = POLICY_FIFO_INFO_COUNT - 1;
    if ((kr = thread_info(self, THREAD_SCHED_FIFO_INFO, w, &n)) != KERN_INVALID_ARGUMENT) return bad("FIFO info short", kr, KERN_INVALID_ARGUMENT);

    // The policies a timesharing thread is not in, the internal flavor,
    // and one there is none of.
    n = POLICY_RR_INFO_COUNT;
    if ((kr = thread_info(self, THREAD_SCHED_RR_INFO, w, &n)) != KERN_INVALID_POLICY) return bad("RR info", kr, KERN_INVALID_POLICY);
    n = POLICY_FIFO_INFO_COUNT;
    if ((kr = thread_info(self, THREAD_SCHED_FIFO_INFO, w, &n)) != KERN_INVALID_POLICY) return bad("FIFO info", kr, KERN_INVALID_POLICY);
    n = THREAD_INFO_MAX;
    if ((kr = thread_info(self, 6, w, &n)) != KERN_NOT_SUPPORTED) return bad("THREAD_DEBUG_INFO_INTERNAL", kr, KERN_NOT_SUPPORTED);
    n = THREAD_INFO_MAX;
    if ((kr = thread_info(self, 7, w, &n)) != KERN_INVALID_ARGUMENT) return bad("flavor 7", kr, KERN_INVALID_ARGUMENT);

    // The identifier flavor leaves the count as it was given.
    for (int i = 0; i < THREAD_INFO_MAX; i++) w[i] = -1;
    n = THREAD_INFO_MAX;
    if ((kr = thread_info(self, THREAD_IDENTIFIER_INFO, w, &n)) || n != THREAD_INFO_MAX) return bad("identifier info's count", kr ? kr : n, THREAD_INFO_MAX);
    uint64_t tid;
    pthread_threadid_np(NULL, &tid);
    thread_identifier_info_t ii = (thread_identifier_info_t)w;
    if (ii->thread_id != tid) return bad("its thread id", (long)ii->thread_id, (long)tid);
    if (w[THREAD_IDENTIFIER_INFO_COUNT] || w[THREAD_INFO_MAX - 1]) return bad("the words past it", w[THREAD_IDENTIFIER_INFO_COUNT], 0);

    // Waiting in read(): its stack kept; suspended, its stop counted.
    pthread_t t;
    pipe(p);
    pthread_create(&t, NULL, reader, NULL);
    thread_act_t th = pthread_mach_thread_np(t);
    if ((kr = until_waiting(th, &bi))) return bad("a reader's basic info", kr, 0);
    if (bi.flags || bi.suspend_count) return bad("a reader's flags and suspend count", bi.flags | bi.suspend_count << 8, 0);
    thread_suspend(th);
    thread_suspend(th);
    if ((kr = basic(th, &bi)) || bi.suspend_count != 2) return bad("its suspend count, suspended twice", kr ? kr : bi.suspend_count, 2);
    if (bi.run_state != TH_STATE_WAITING || bi.flags) return bad("its run state and flags, suspended", bi.run_state | bi.flags << 8, TH_STATE_WAITING);
    thread_resume(th);
    thread_resume(th);
    write(p[1], "x", 1);
    pthread_join(t, NULL);

    // Waiting in mach_msg's receive: its stack discarded.
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &rcv);
    mach_port_insert_right(mach_task_self(), rcv, rcv, MACH_MSG_TYPE_MAKE_SEND);
    pthread_create(&t, NULL, receiver, NULL);
    th = pthread_mach_thread_np(t);
    if ((kr = until_waiting(th, &bi))) return bad("a receiver's basic info", kr, 0);
    if (bi.flags != TH_FLAGS_SWAPPED) return bad("a receiver's flags", bi.flags, TH_FLAGS_SWAPPED);
    mach_msg_header_t h = {MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0), sizeof h, rcv, MACH_PORT_NULL, 0, 0};
    mach_msg(&h, MACH_SEND_MSG, sizeof h, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    pthread_join(t, NULL);

    // Made suspended: never run.
    if (pthread_create_suspended_np(&t, NULL, nothing, NULL)) return bad("a suspended thread made", 1, 0);
    th = pthread_mach_thread_np(t);
    if ((kr = basic(th, &bi))) return bad("its basic info", kr, 0);
    if (bi.run_state != TH_STATE_UNINTERRUPTIBLE || bi.flags != TH_FLAGS_SWAPPED || bi.suspend_count != 1) return bad("its run state, flags and suspend count", bi.run_state | bi.flags << 8 | bi.suspend_count << 16, TH_STATE_UNINTERRUPTIBLE | TH_FLAGS_SWAPPED << 8 | 1 << 16);
    thread_resume(th);
    pthread_join(t, NULL);

    // Spinning: running, its time and usage counted.
    pthread_create(&t, NULL, spin, NULL);
    th = pthread_mach_thread_np(t);
    while (spins < 1000) usleep(1000);
    uint64_t until = mach_absolute_time() + 24000000;
    while (mach_absolute_time() < until) usleep(10000);
    if ((kr = basic(th, &bi))) return bad("a spinner's basic info", kr, 0);
    if (bi.run_state != TH_STATE_RUNNING || bi.flags) return bad("a spinner's run state and flags", bi.run_state | bi.flags << 8, TH_STATE_RUNNING);
    if (!bi.user_time.seconds && !bi.user_time.microseconds) return bad("a spinner's user time", 0, 1);
    if (bi.cpu_usage <= 0 || bi.cpu_usage > TH_USAGE_SCALE) return bad("a spinner's CPU usage", bi.cpu_usage, TH_USAGE_SCALE);
    stop = 1;
    pthread_join(t, NULL);
    printf("thinfo ok\n");
    return 0;
}
