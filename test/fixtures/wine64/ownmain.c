/* A gexcc-win program linked against owndll.dll's import library: its
 * calls, a struct by value, and the DLL's data at the DLL's own address,
 * written by each side and read back by the other. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "owndll.h"

/* initialised from the DLL's addresses when the program's data is */
static int *count_at = &own_count;
static struct own_pt *pt_at = &own_pt;

static int failures;

static void check(const char *what, int ok)
{
    printf("%s %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) failures++;
}

int main(void)
{
    struct own_pt p = {3, 4};
    check("call", own_add(1, 2) == 44);
    check("struct by value", own_pt_sum(p) == 34);
    char buf[32];
    check("variadic call", own_vsum(4, 1, 2, 3, 40) == 46);
    check("variadic call's string and 64-bit argument",
          own_vfmt(buf, sizeof buf, "%s %lld", "x", 1ll << 40) == 15 && !strcmp(buf, "x 1099511627776"));
    check("int's address", &own_count == own_count_addr());
    check("struct's address", &own_pt == own_pt_addr() && &own_pt.y == &own_pt_addr()->y);
    check("addresses in the program's data", count_at == own_count_addr() && pt_at == own_pt_addr());
    HMODULE m = GetModuleHandleA("owndll.dll");
    check("GetProcAddress's int", m && (void *)GetProcAddress(m, "own_count") == (void *)&own_count);
    check("GetProcAddress's struct", m && (void *)GetProcAddress(m, "own_pt") == (void *)&own_pt);
    check("int read", own_count == 41);
    own_count = 7;
    check("int written here, read there", own_add(0, 0) == 7);
    own_bump();
    check("int written there, read here", own_count == 107);
    check("struct member written there, read here", own_pt.x == 5 && own_pt.y == 8);
    own_pt.x = 9;
    check("struct member written here, read there", own_pt_addr()->x == 9);
    printf("%d failures\n", failures);
    return 0;
}
