/* tlsload: static TLS of a DLL loaded after threads exist, and each thread's
 * own identity. Threads: 6 started before LoadLibrary("tlsdll.dll"), 6 after,
 * 4 threadpool callbacks, and one CreateRemoteThread on this process. Each
 * checks its slot starts at the DLL's initial value, writes its own id, and
 * reads it back across sleeps while the others do the same; and that
 * GetCurrentThreadId matches its TEB's ClientId and NtCurrentTeb matches
 * gs:[0x30]. One line per thread "tlsload KIND ok|bad ...", then
 * "tlsload N bad" and "tlsload done". */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef LONG_PTR (*get_fn)(void);
typedef void (*set_fn)(LONG_PTR);
static get_fn tget;
static set_fn tset;
static HANDLE go;
static volatile LONG bad, ran;

typedef struct { void *pad[8]; HANDLE pid; HANDLE tid; } teb_head; /* ClientId at 0x40 */

static void check(const char *kind)
{
    char *teb = (char *)NtCurrentTeb();
    DWORD me = GetCurrentThreadId();
    DWORD cid = (DWORD)(ULONG_PTR)((teb_head *)teb)->tid;
    void *self = (void *)__readgsqword(0x30);
    LONG_PTR first = tget(), v;
    int i, ok = 1;
    /* a pool thread may have run an earlier callback, which left its id */
    if (first != 0x5eed && !(kind[0] == 'p' && first == (LONG_PTR)me)) ok = 0;
    tset(me);
    for (i = 0; i < 20; i++) {
        Sleep(5);
        if ((v = tget()) != (LONG_PTR)me) { ok = 0; break; }
    }
    if (cid != me || self != teb) ok = 0;
    if (!ok) InterlockedIncrement(&bad);
    InterlockedIncrement(&ran);
    printf("tlsload %s %s tid %lu cid %lu teb %p gs30 %p first %lx last %lx\n", kind, ok ? "ok" : "bad",
           me, cid, teb, self, (long)first, (long)tget());
    fflush(stdout);
}

static DWORD WINAPI early(void *a) { WaitForSingleObject(go, INFINITE); check((const char *)a); return 0; }
static DWORD WINAPI late(void *a) { check((const char *)a); return 0; }
static VOID CALLBACK pool(PTP_CALLBACK_INSTANCE i, void *a) { (void)i; check((const char *)a); }

int main(void)
{
    HANDLE th[32];
    HMODULE dll;
    int n = 0, i;
    go = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < 6; i++) th[n++] = CreateThread(NULL, 0, early, "early", 0, NULL);
    Sleep(50);
    if (!(dll = LoadLibraryA("tlsdll.dll"))) { printf("tlsload no dll %lu\n", GetLastError()); return 1; }
    tget = (get_fn)GetProcAddress(dll, "tls_get");
    tset = (set_fn)GetProcAddress(dll, "tls_set");
    SetEvent(go);
    for (i = 0; i < 6; i++) th[n++] = CreateThread(NULL, 0, late, "late", 0, NULL);
    th[n++] = CreateRemoteThread(GetCurrentProcess(), NULL, 0, late, "remote", 0, NULL);
    for (i = 0; i < 4; i++) TrySubmitThreadpoolCallback(pool, "pool", NULL);
    check("main");
    WaitForMultipleObjects(n, th, TRUE, 30000);
    for (i = 0; i < 200 && ran < n + 5; i++) Sleep(10);
    printf("tlsload %ld ran %ld bad\n", (long)ran, (long)bad);
    printf("tlsload done\n");
    return 0;
}
