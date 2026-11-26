/* outgrow: the Windows guest of test/wow64/outgrow. Reserves 3.5 GiB in
 * one block (VirtualAlloc, no address), which the lowered memory has no
 * room for and a 64-bit one has.
 *
 *   outgrow crash      no room: says "outgrow short", then raises an
 *                      access violation no handler takes (gex maps no
 *                      guard at address 0 unless asked to)
 *   outgrow fallback   no room: reserves 64 MiB blocks instead until one
 *                      is refused, says "outgrow fallback ok", then
 *                      reserves 64 KiB at 0x7ff00000, just below Windows'
 *                      old KUSER_SHARED_DATA page, and says "outgrow
 *                      reached 2g" when it got it; exits 0
 *   outgrow thread     fills the memory with 1 MiB blocks (each too small
 *                      for gex to record a refusal) until one is refused
 *                      or 2 GiB are taken, gives the last three back, and
 *                      starts a thread with a 64 KiB stack: in the lowered
 *                      memory gex's own memory for the thread (its
 *                      provider stack) has no room; says "outgrow thread
 *                      ran" from the thread
 *   outgrow retry      says "outgrow retrying", then asks for the 3.5 GiB
 *                      (committed) again and again, as an allocator that
 *                      cannot go on without it does (OpenBLAS's buffers);
 *                      gex ends it at the second ask. Says "outgrow retry
 *                      gave up" and exits 0 if it was never ended
 *   outgrow late M     runs `outgrow M` once, then waits (10 min at most)
 *                      for a run that got the 3.5 GiB, which may be one
 *                      gex had started again, and says "outgrow late done"
 *                      (or "outgrow late timed out")
 *   outgrow twice M    runs `outgrow M` twice, one after the other
 *                      (CreateProcess each), and says how each ended
 *   outgrow each M X.. the same for each program X (a copy of this one),
 *                      each start the moment the one before ends
 *
 * Each run says "outgrow big high" when it got the 3.5 GiB above 4 GiB.
 * gex-nt-arch: x64
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define BIG ((SIZE_T)7 << 29)

static void once(const char *exe, const char *mode) {
    char me[MAX_PATH], cmd[MAX_PATH + 32];
    STARTUPINFOA si = { sizeof si };
    PROCESS_INFORMATION pi;
    DWORD code = 0;

    fflush(stdout);
    if (exe) snprintf(me, sizeof me, "%s", exe);
    else GetModuleFileNameA(NULL, me, sizeof me);
    snprintf(cmd, sizeof cmd, "\"%s\" %s", me, mode);
    if (!CreateProcessA(me, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("outgrow child not started: %lu\n", GetLastError());
        return;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    printf("outgrow child exit %08lx\n", code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

static DWORD WINAPI thread(void *arg) {
    printf("outgrow thread ran\n");
    fflush(stdout);
    return 0;
}

/* "outgrow big", and the event a `late` run waits on, if there is one */
static void big_said(void *p) {
    HANDLE ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, "outgrow-big");
    printf("outgrow big %s\n", (ULONG_PTR)p >= ((ULONG_PTR)1 << 32) ? "high" : "low");
    fflush(stdout);
    if (ev) SetEvent(ev);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "crash";
    void *p;

    if (argc > 2 && !strcmp(argv[1], "late")) {
        HANDLE ev = CreateEventA(NULL, TRUE, FALSE, "outgrow-big");
        once(NULL, argv[2]);
        printf("outgrow late %s\n", WaitForSingleObject(ev, 600000) ? "timed out" : "done");
        return 0;
    }
    if (argc > 2 && !strcmp(argv[1], "twice")) {
        once(NULL, argv[2]);
        once(NULL, argv[2]);
        return 0;
    }
    if (argc > 3 && !strcmp(argv[1], "each")) {
        int i;
        for (i = 3; i < argc; i++) {
            once(argv[i], argv[2]);
            once(argv[i], argv[2]);
        }
        return 0;
    }
    if (!strcmp(mode, "thread")) {
        void *last[3] = { NULL, NULL, NULL };
        HANDLE h;
        int n = 0, i;

        printf("outgrow filling\n");
        fflush(stdout);
        while (n < 2048 && (p = VirtualAlloc(NULL, 1 << 20, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
            last[n % 3] = p;
            n++;
        }
        /* room for the thread's stack and Wine's own for it, not gex's */
        for (i = 0; i < 3; i++)
            if (last[i]) VirtualFree(last[i], 0, MEM_RELEASE);
        h = CreateThread(NULL, 64 << 10, thread, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
        if (!h) {
            printf("outgrow no thread %lu\n", GetLastError());
            return 3;
        }
        WaitForSingleObject(h, INFINITE);
        return 0;
    }
    if (!strcmp(mode, "retry")) {
        int i;

        printf("outgrow retrying\n");
        fflush(stdout);
        for (i = 0; i < 100000; i++) {
            if ((p = VirtualAlloc(NULL, BIG, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
                big_said(p);
                return 0;
            }
        }
        printf("outgrow retry gave up\n");
        return 0;
    }
    p = VirtualAlloc(NULL, BIG, MEM_RESERVE, PAGE_NOACCESS);
    if (p) {
        big_said(p);
        return 0;
    }
    if (!strcmp(mode, "crash")) {
        printf("outgrow short\n");
        fflush(stdout);
        RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, NULL);
    }
    {
        ULONG_PTR top = 0;
        int n = 0;

        while ((p = VirtualAlloc(NULL, 64 << 20, MEM_RESERVE, PAGE_NOACCESS))) {
            if ((ULONG_PTR)p + (64 << 20) > top) top = (ULONG_PTR)p + (64 << 20);
            n++;
        }
        printf("outgrow fallback %s\n", n ? "ok" : "failed");
        /* a block just below the old KUSER page, at its address: the
         * memory then reaches past that page */
        if (VirtualAlloc((void *)0x7ff00000, 0x10000, MEM_RESERVE, PAGE_NOACCESS)) top = 0x7ff10000;
        if (top > 0x7f000000) printf("outgrow reached 2g\n");
    }
    return 0;
}
