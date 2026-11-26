/* shmview.exe: two MapViewOfFile views of one pagefile section in one
 * process, as Firefox's ipc::Shmem has with e10s off (the content side's
 * view and the compositor's): a writer thread copies a record into view A
 * and hands it over with an atomic count in the section's header, a reader
 * thread takes it through view B, checks every byte and gives it back
 * through the count. Meanwhile churn threads make, write, unmap and close
 * other sections (each unmap a write-back) and make system calls. Every
 * record must read back as written, through one range: on gex a wasm
 * memory shows a page at one address only, so the second view is the
 * first's address (or inside it), and a separate copy of the section met
 * the first only when gex read one from the file again.
 * First, threads that used thread-local storage end after a DLL is
 * loaded: gex unmaps their TLS chunks, which Wine had views of, and a
 * section's first view then lands where one was (Firefox: every view of
 * its Shmem a separate copy, its WebRender blobs read with bytes neither
 * side wrote).
 * argv[1]: "same" (B maps what A maps), "whole" (A maps the first page
 * only, B the whole section), "shifted" (both from the second page),
 * "based" (B at an address asked for: a separate copy, as expected, with
 * no handoff), "rdonly" (A read-only, B read-write, written through B and
 * read through A, no handoff; on gex the read-only view reports the
 * read-write protection: one range has one protection, an expected gap),
 * "big" (a 256 MiB section, a page viewed at its start and one at 200 MiB:
 * one range, the second where the first's would reach, no handoff; argv[2]
 * seconds to stay mapped, so the process's memory can be read meanwhile);
 * argv[2]: seconds (default 10).
 * Prints "shmview: MODE N records, M bad" then "N failures". */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SECTION (64 * 1024)
#define REC 491
struct hdr { volatile LONG count; volatile LONG seq; };

static unsigned char *va, *vb;   /* the record's page through each view */
static HANDLE ready, stop;
static volatile LONG done, bad, first_bad_seq = -1, first_bad_at = -1;
static DWORD secs = 10;
static __thread int tls_used;
static HANDLE prime_go;
static void *tls_at[8];

/* a thread that has used its thread-local storage, ended on prime_go */
static DWORD WINAPI primer(void *arg)
{
    tls_used = (int)(ULONG_PTR)arg + 1;
    tls_at[(ULONG_PTR)arg] = (void *)&tls_used;
    WaitForSingleObject(prime_go, INFINITE);
    return tls_used;
}

static void fill(unsigned char *p, LONG seq)
{
    for (int i = 0; i < REC - 8; i++) p[i] = (unsigned char)(seq * 31 + i * 7 + 1);
    ULONGLONG off = REC - 40 + (seq & 7);   /* the trailing index offset, as WebRender's blob has */
    memcpy(p + REC - 8, &off, 8);
}

static DWORD WINAPI writer(void *arg)
{
    struct hdr *h = (struct hdr *)va;
    DWORD end = GetTickCount() + secs * 1000;
    for (LONG seq = 1; GetTickCount() < end; seq++)
    {
        /* recycled once the reader let go, as AllocResourceShmem checks the count */
        while (InterlockedCompareExchange(&h->count, 0, 0) > 1) YieldProcessor();
        fill(va + 64, seq);
        h->seq = seq;
        InterlockedIncrement(&h->count);
        SetEvent(ready);
        while (InterlockedCompareExchange(&h->count, 0, 0) > 1) YieldProcessor();
        InterlockedIncrement(&done);
    }
    SetEvent(stop);
    SetEvent(ready);
    return 0;
}

static DWORD WINAPI reader(void *arg)
{
    struct hdr *h = (struct hdr *)vb;
    unsigned char want[REC];
    for (;;)
    {
        WaitForSingleObject(ready, INFINITE);
        if (WaitForSingleObject(stop, 0) == WAIT_OBJECT_0) break;
        if (InterlockedCompareExchange(&h->count, 0, 0) < 2) continue;
        LONG seq = h->seq;
        fill(want, seq);
        if (memcmp(vb + 64, want, REC))
        {
            int at = 0;
            while (vb[64 + at] == want[at]) at++;
            if (InterlockedIncrement(&bad) == 1) { first_bad_seq = seq; first_bad_at = at; }
        }
        InterlockedDecrement(&h->count);
    }
    return 0;
}

static DWORD WINAPI churn(void *arg)
{
    while (WaitForSingleObject(stop, 0) != WAIT_OBJECT_0)
    {
        HANDLE s = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 8192, NULL);
        unsigned char *p = s ? MapViewOfFile(s, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 8192) : NULL;
        if (p) { memset(p, 0x5a, 8192); UnmapViewOfFile(p); }
        if (s) CloseHandle(s);
        GetTickCount();
        Sleep(0);
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "same";
    HANDLE th[5], dup;
    if (argc > 2) secs = atoi(argv[2]);
    /* threads with TLS, a DLL loaded while they run, then their end */
    {
        HANDLE pt[8];
        prime_go = CreateEventA(NULL, TRUE, FALSE, NULL);
        for (int k = 0; k < 8; k++) pt[k] = CreateThread(NULL, 0, primer, (void *)(ULONG_PTR)k, 0, NULL);
        Sleep(200);
        LoadLibraryA("version.dll");
        SetEvent(prime_go);
        WaitForMultipleObjects(8, pt, TRUE, 20000);
        for (int k = 0; k < 8; k++) CloseHandle(pt[k]);
        /* a view made (Wine looks at what gex unmapped), then the ended
         * threads' TLS must no longer show as Wine's memory */
        HANDLE t = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
        void *tv = t ? MapViewOfFile(t, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 4096) : NULL;
        int stale = 0;
        for (int k = 0; k < 8; k++)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (tls_at[k] && VirtualQuery(tls_at[k], &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
                (!tv || (char *)tls_at[k] < (char *)tv || (char *)tls_at[k] >= (char *)tv + 4096))
                stale++;
        }
        if (tv) UnmapViewOfFile(tv);
        if (t) CloseHandle(t);
        printf("shmview: %d of 8 ended threads' TLS still committed\n", stale);
        if (stale) { printf("shmview FAIL ended threads' TLS still Wine's memory\n1 failures\n"); return 1; }
    }
    HANDLE s = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SECTION, NULL);
    if (!s) { printf("shmview FAIL CreateFileMapping %lu\n1 failures\n", GetLastError()); return 1; }
    DuplicateHandle(GetCurrentProcess(), s, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    if (!strcmp(mode, "same"))
    {
        va = MapViewOfFile(s, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SECTION);
        vb = MapViewOfFile(dup, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SECTION);
    }
    else if (!strcmp(mode, "whole"))
    {
        va = MapViewOfFile(s, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 4096);
        vb = MapViewOfFile(dup, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SECTION);
    }
    else if (!strcmp(mode, "shifted"))
    {
        unsigned char *a = MapViewOfFile(s, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SECTION);
        unsigned char *b = MapViewOfFile(dup, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SECTION);
        va = a ? a + 4096 : NULL;
        vb = b ? b + 4096 : NULL;
    }
    else if (!strcmp(mode, "rdonly"))
    {
        unsigned char *a = MapViewOfFile(s, FILE_MAP_READ, 0, 0, SECTION);
        unsigned char *b = MapViewOfFile(dup, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SECTION);
        int same = 1;
        if (!a || !b) { printf("shmview FAIL MapViewOfFile %lu\n1 failures\n", GetLastError()); return 1; }
        for (int i = 0; i < SECTION; i++) b[i] = (unsigned char)(i * 13 + 5);
        for (int i = 0; i < SECTION; i++) if (a[i] != (unsigned char)(i * 13 + 5)) { same = 0; break; }
        MEMORY_BASIC_INFORMATION mbi;
        printf("shmview: rdonly views %s, written through the second %s\n", a == b ? "one range" : "two ranges",
               same ? "read through the first" : "NOT read through the first");
        if (VirtualQuery(a, &mbi, sizeof(mbi)))
            printf("shmview: rdonly first view reports %s\n", mbi.Protect == PAGE_READONLY ? "PAGE_READONLY" :
                   mbi.Protect == PAGE_READWRITE ? "PAGE_READWRITE (one range, one protection: an expected gap)" : "another protection");
        printf("%d failures\n", same ? 0 : 1);
        return same ? 0 : 1;
    }
    else if (!strcmp(mode, "big"))
    {
        HANDLE big = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 256 << 20, NULL);
        unsigned char *a = big ? MapViewOfFile(big, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 4096) : NULL;
        unsigned char *b = big ? MapViewOfFile(big, FILE_MAP_READ | FILE_MAP_WRITE, 0, 200 << 20, 4096) : NULL;
        if (!a || !b) { printf("shmview FAIL big MapViewOfFile %lu\n1 failures\n", GetLastError()); return 1; }
        a[0] = 0x11; b[0] = 0x22;
        printf("shmview: big views %s\n", b == a + (200 << 20) ? "one range" : "two ranges");
        fflush(stdout);
        Sleep(secs * 1000);
        printf("%d failures\n", b == a + (200 << 20) && a[0] == 0x11 && b[0] == 0x22 ? 0 : 1);
        return 0;
    }
    else
    {
        /* a base address asked for: its own range, a copy (expected) */
        void *want = VirtualAlloc(NULL, SECTION, MEM_RESERVE, PAGE_NOACCESS);
        va = MapViewOfFile(s, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SECTION);
        if (want) VirtualFree(want, 0, MEM_RELEASE);
        vb = want ? MapViewOfFileEx(dup, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SECTION, want) : NULL;
        if (!va || !vb) { printf("shmview FAIL MapViewOfFileEx %lu\n1 failures\n", GetLastError()); return 1; }
        printf("shmview: based views %s (a separate copy, as expected)\n0 failures\n", va == vb ? "one range" : "two ranges");
        return 0;
    }
    if (!va || !vb) { printf("shmview FAIL MapViewOfFile %lu\n1 failures\n", GetLastError()); return 1; }
    printf("shmview: views %s\n", va == vb ? "one range" : "two ranges");
    if (va != vb) { printf("shmview FAIL %s: the views are two ranges\n1 failures\n", mode); return 1; }
    ready = CreateEventA(NULL, FALSE, FALSE, NULL);
    stop = CreateEventA(NULL, TRUE, FALSE, NULL);
    ((struct hdr *)va)->count = 1;   /* the owner's reference */
    th[0] = CreateThread(NULL, 0, reader, NULL, 0, NULL);
    th[1] = CreateThread(NULL, 0, writer, NULL, 0, NULL);
    th[2] = CreateThread(NULL, 0, churn, NULL, 0, NULL);
    th[3] = CreateThread(NULL, 0, churn, NULL, 0, NULL);
    th[4] = CreateThread(NULL, 0, churn, NULL, 0, NULL);
    WaitForMultipleObjects(5, th, TRUE, (secs + 30) * 1000);
    printf("shmview: %s %ld records, %ld bad", mode, done, bad);
    if (bad) printf(" (first at record %ld, byte %ld)", first_bad_seq, first_bad_at);
    printf("\n");
    if (!done) printf("shmview FAIL %s: no record handed over\n", mode);
    printf("%d failures\n", bad || !done ? 1 : 0);
    return bad || !done ? 1 : 0;
}
