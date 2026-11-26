/* cowcopy [DIR [keep]]: CopyFileW of a 64 MiB file in DIR (C:\cowcopy), then a write to the copy and to the
 * source. Each file keeps its own bytes; under gex's kernel file system the
 * copy shares the source's until written (Wine's CopyFile asks for
 * FSCTL_DUPLICATE_EXTENTS_TO_FILE: copy_file_range), which Shmem in
 * /proc/meminfo (Z:\proc\meminfo) shows. Prints "cowcopy shmem added N KiB"
 * and what the source took ("cowcopy source held N KiB"; -1 where there is
 * no Shmem) and "cowcopy ok", or what was wrong. With "keep" the written copy
 * (b.bin: the pattern, "copy!" at 70000) is left for a reader after. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define LEN (64u << 20)

static long shmem_kib(void)
{
    char buf[4096];
    FILE *f = fopen("Z:\\proc\\meminfo", "rb");
    size_t n;
    char *p;

    if (!f) return -1;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    if (!(p = strstr(buf, "Shmem:"))) return -1;
    return strtol(p + 6, NULL, 10);
}

static unsigned char pat(DWORD i) { return (unsigned char)(i * 7 + (i >> 16)); }

static int check(const WCHAR *name, DWORD at, const char *want, const char *what)
{
    HANDLE h = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    static unsigned char buf[1 << 20];
    DWORD got, i, base = 0;

    if (h == INVALID_HANDLE_VALUE) { printf("cowcopy %s: cannot open (%lu)\n", what, GetLastError()); return 0; }
    while (ReadFile(h, buf, sizeof(buf), &got, NULL) && got)
    {
        for (i = 0; i < got; i++)
        {
            DWORD o = base + i;
            unsigned char w = pat(o);
            if (want && o >= at && o < at + strlen(want)) w = want[o - at];
            if (buf[i] != w) { printf("cowcopy %s: byte %lu is %u, not %u\n", what, o, buf[i], w); CloseHandle(h); return 0; }
        }
        base += got;
    }
    CloseHandle(h);
    if (base != LEN) { printf("cowcopy %s: %lu bytes\n", what, base); return 0; }
    return 1;
}

static int poke(const WCHAR *name, DWORD at, const char *s)
{
    HANDLE h = CreateFileW(name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD done;
    BOOL ok;

    if (h == INVALID_HANDLE_VALUE) return 0;
    SetFilePointer(h, at, NULL, FILE_BEGIN);
    ok = WriteFile(h, s, strlen(s), &done, NULL) && done == strlen(s);
    CloseHandle(h);
    return ok;
}

static WCHAR D[MAX_PATH], A[MAX_PATH], B[MAX_PATH];

int wmain(int argc, WCHAR **argv)
{
    static unsigned char buf[1 << 20];
    HANDLE h;
    DWORD i, j, done;
    long start = shmem_kib(), before, after;

    wcscpy(D, argc > 1 ? argv[1] : L"C:\\cowcopy");
    swprintf(A, MAX_PATH, L"%ls\\a.bin", D);
    swprintf(B, MAX_PATH, L"%ls\\b.bin", D);
    CreateDirectoryW(D, NULL);
    h = CreateFileW(A, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { printf("cowcopy: no source (%lu)\n", GetLastError()); return 1; }
    for (i = 0; i < LEN; i += sizeof(buf))
    {
        for (j = 0; j < sizeof(buf); j++) buf[j] = pat(i + j);
        if (!WriteFile(h, buf, sizeof(buf), &done, NULL) || done != sizeof(buf)) { printf("cowcopy: write failed\n"); return 1; }
    }
    CloseHandle(h);

    before = shmem_kib();
    if (!CopyFileW(A, B, FALSE)) { printf("cowcopy: CopyFileW failed (%lu)\n", GetLastError()); return 1; }
    after = shmem_kib();
    printf("cowcopy source held %ld KiB\n", before < 0 || start < 0 ? -1 : before - start);
    printf("cowcopy shmem added %ld KiB\n", before < 0 || after < 0 ? -1 : after - before);
    if (!check(B, 0, NULL, "the copy")) return 1;
    if (!poke(B, 70000, "copy!") || !poke(A, 5, "source!")) { printf("cowcopy: poke failed\n"); return 1; }
    if (!check(B, 70000, "copy!", "the written copy")) return 1;
    if (!check(A, 5, "source!", "the written source")) return 1;
    DeleteFileW(A);
    if (!check(B, 70000, "copy!", "the copy, its source deleted")) return 1;
    if (argc <= 2 || wcscmp(argv[2], L"keep"))
    {
        DeleteFileW(B);
        RemoveDirectoryW(D);
    }
    printf("cowcopy ok\n");
    return 0;
}
