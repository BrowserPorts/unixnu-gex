/* gcroots: what a conservative collector's Windows root scan finds (Boehm
 * GC's GC_register_dynamic_libraries and its stack bounds): VirtualQuery of
 * this program's .data and .bss and a loaded DLL's, which must be committed
 * MEM_IMAGE and PAGE_READWRITE (as Windows shows a written page; that scan
 * takes no PAGE_WRITECOPY), VirtualProtect's old protection agreeing, a
 * copy-on-write view of a plain file still PAGE_WRITECOPY, and the TEB's
 * stack bounds around a local. One line each, then "gcroots N bad". */
#include <windows.h>
#include <stdio.h>

static int bad;
static DWORD n_written;
static char page[4096];
int data_var = 1;
int bss_var;

static int writable(DWORD p)
{
    return p == PAGE_READWRITE || p == PAGE_EXECUTE_READWRITE;
}

static void check(const char *what, void *p)
{
    MEMORY_BASIC_INFORMATION m;
    SIZE_T n = VirtualQuery(p, &m, sizeof(m));
    int ok = n && m.State == MEM_COMMIT && m.Type == MEM_IMAGE && writable(m.Protect);
    printf("gcroots %s %p base %p alloc %p size %lx state %lx protect %lx type %lx %s\n", what, p, m.BaseAddress,
           m.AllocationBase, (unsigned long)m.RegionSize, m.State, m.Protect, m.Type, ok ? "ok" : "BAD");
    if (!ok) bad++;
}

static DWORD WINAPI thread(void *arg)
{
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    int local;
    int ok = (char *)&local < (char *)tib->StackBase && (char *)&local >= (char *)tib->StackLimit;
    printf("gcroots stack %s local %p base %p limit %p %s\n", (char *)arg, &local, tib->StackBase, tib->StackLimit, ok ? "ok" : "BAD");
    if (!ok) bad++;
    return 0;
}

int main(void)
{
    HANDLE h;
    SYSTEM_INFO si;
    MEMORY_BASIC_INFORMATION m;
    char *a;
    int images = 0, wimages = 0;

    check("data", &data_var);
    check("bss", &bss_var);
    {
        HMODULE d = LoadLibraryA("gcdll.dll");
        if (!d) { printf("gcroots no gcdll %lu\n", GetLastError()); bad++; }
        else { check("dll-data", GetProcAddress(d, "gcdll_data")); check("dll-bss", GetProcAddress(d, "gcdll_bss")); }
    }
    {
        DWORD old = 0, old2 = 0;
        int ok = VirtualProtect(&data_var, sizeof(data_var), PAGE_READWRITE, &old) && old == PAGE_READWRITE
                 && VirtualProtect(&data_var, sizeof(data_var), old, &old2) && old2 == PAGE_READWRITE;
        printf("gcroots protect old %lx then %lx %s\n", old, old2, ok ? "ok" : "BAD");
        if (!ok) bad++;
    }
    {
        char path[MAX_PATH], *v;
        HANDLE f, s;
        GetTempPathA(sizeof(path), path);
        strcat(path, "gcroots.tmp");
        f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
        WriteFile(f, page, sizeof(page), &n_written, NULL);
        s = CreateFileMappingA(f, NULL, PAGE_WRITECOPY, 0, 0, NULL);
        v = s ? MapViewOfFile(s, FILE_MAP_COPY, 0, 0, 0) : NULL;
        if (v && VirtualQuery(v, &m, sizeof(m)) && m.Protect == PAGE_WRITECOPY && m.Type == MEM_MAPPED)
            printf("gcroots file copy view protect %lx ok\n", m.Protect);
        else { printf("gcroots file copy view %p protect %lx BAD\n", v, v ? m.Protect : 0); bad++; }
        if (v) UnmapViewOfFile(v);
        if (s) CloseHandle(s);
        CloseHandle(f);
    }
    thread("main");
    h = CreateThread(NULL, 0, thread, "thread", 0, NULL);
    WaitForSingleObject(h, INFINITE);
    /* the whole walk, as the collector does it */
    GetSystemInfo(&si);
    for (a = si.lpMinimumApplicationAddress; a < (char *)si.lpMaximumApplicationAddress; a = (char *)m.BaseAddress + m.RegionSize) {
        if (!VirtualQuery(a, &m, sizeof(m))) break;
        if (m.State == MEM_COMMIT && m.Type == MEM_IMAGE) { images++; if (writable(m.Protect)) wimages++; }
        if (!m.RegionSize) break;
    }
    /* the exe's data and the DLL's at least */
    printf("gcroots walk image regions %d writable %d %s\n", images, wimages, wimages >= 2 ? "ok" : "BAD");
    if (wimages < 2) bad++;
    printf("gcroots %d bad\n", bad);
    return bad;
}
