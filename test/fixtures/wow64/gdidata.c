/* A data export of a DLL of Wine's core PE module, through its export
 * table: gdi32's pfnRealizePalette, the hook RealizePalette calls. Set
 * through the address GetProcAddress gives, RealizePalette must call the
 * program's function: the export is gdi32's own variable, not some other
 * memory its RVA reaches (gdidata.test.js pins gdi32 low, as a prefix's
 * dll-bases does). */
#include <windows.h>
#include <stdio.h>

static int called;
static UINT WINAPI hook(HDC hdc) { called++; return 7; }

int main(void)
{
    HMODULE g = GetModuleHandleA("gdi32.dll");
    UINT (WINAPI **p)(HDC) = (void *)GetProcAddress(g, "pfnRealizePalette");
    UINT (WINAPI *was)(HDC);
    HDC dc;
    UINT r;

    printf("gdidata gdi32 %p, pfnRealizePalette at %p\n", g, p);
    if (!p) { printf("gdidata FAIL no pfnRealizePalette\n"); return 1; }
    if (IsBadReadPtr(p, sizeof(*p)) || IsBadWritePtr(p, sizeof(*p))) { printf("gdidata FAIL pfnRealizePalette's address is not memory\n"); return 1; }
    was = *p;
    *p = hook;
    dc = CreateCompatibleDC(NULL);
    r = RealizePalette(dc);
    *p = was;
    DeleteDC(dc);
    if (called != 1 || r != 7) { printf("gdidata FAIL RealizePalette did not call the hook set through the export (called %d, returned %u)\n", called, r); return 1; }
    printf("gdidata ok\n");
    return 0;
}
