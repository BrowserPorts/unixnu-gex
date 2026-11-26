/* datareach: DLLs whose exports include data (msftedit's and riched20's
 * IIDs, oleacc's), loaded and their data exports read. "datareach NAME
 * ok" or "datareach NAME BAD", then "datareach done". */
#include <windows.h>
#include <stdio.h>

static int bad;

static void one(const char *dll, const char *sym)
{
    HMODULE m = LoadLibraryA(dll);
    const GUID *g = m ? (const GUID *)GetProcAddress(m, sym) : NULL;
    MEMORY_BASIC_INFORMATION mi;
    int ok = g && VirtualQuery(g, &mi, sizeof(mi)) && mi.State == MEM_COMMIT && g->Data1 != 0;
    printf("datareach %s %s\n", dll, ok ? "ok" : "BAD");
    if (!ok) bad++;
}

int main(void)
{
    one("msftedit.dll", "IID_IRichEditOle");
    one("riched20.dll", "IID_IRichEditOle");
    one("oleacc.dll", "IID_IAccessible");
    printf("datareach done\n");
    return bad;
}
