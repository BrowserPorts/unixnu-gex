/* imagecopy: whether this process's memory holds a copy of Wine's loader's
 * own wasm module, in the loader's image (the first "[image]" mapping in
 * Z:\proc\self\maps, which wasm-elf.py's container puts the module in).
 * With "child", the same of a child it starts. Prints "imagecopy headers N" (1: the ELF headers are there, which
 * dl_iterate_phdr reads), "imagecopy module copies N" (wasm magics in the
 * image) and the process's VmRSS. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    char l[512];
    /* "child": the same in a process Wine starts (an exec), as most are */
    if (argc > 1 && !strcmp(argv[1], "child"))
    {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        char cmd[MAX_PATH + 8];
        DWORD code = 1;
        GetModuleFileNameA(NULL, cmd, MAX_PATH);
        if (!CreateProcessA(cmd, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) { printf("imagecopy: no child (%lu)\n", GetLastError()); return 1; }
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &code);
        return code;
    }
    unsigned long long lo = 0, hi = 0;
    FILE *f = fopen("Z:\\proc\\self\\maps", "r");

    while (f && fgets(l, sizeof(l), f))
        if (strstr(l, "[image]") && sscanf(l, "%llx-%llx", &lo, &hi) == 2) break;
    if (f) fclose(f);
    if (!lo) { printf("imagecopy: no [image] mapping\n"); return 1; }
    {
        const unsigned char *p = (const unsigned char *)(ULONG_PTR)lo;
        static const unsigned char magic[8] = { 0, 'a', 's', 'm', 1, 0, 0, 0 };
        unsigned long long i, copies = 0;
        for (i = 0; i + 8 <= hi - lo; i += 4)
            if (!memcmp(p + i, magic, 8)) copies++;
        printf("imagecopy headers %d\n", !memcmp(p, "\x7f" "ELF", 4));
        printf("imagecopy module copies %llu in %llu KiB\n", copies, (hi - lo) >> 10);
    }
    f = fopen("Z:\\proc\\self\\status", "r");
    while (f && fgets(l, sizeof(l), f)) if (!strncmp(l, "VmRSS", 5)) printf("imagecopy %s", l);
    if (f) fclose(f);
    return 0;
}
