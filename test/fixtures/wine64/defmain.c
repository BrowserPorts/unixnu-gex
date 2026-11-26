/* defdll.dll's exports: a call, and its data written and read on both sides;
 * the dllexports its .def leaves out */
#include <stdio.h>
__declspec(dllimport) int defdll_get(void);
__declspec(dllimport) extern int defdll_val, defdll_val2;
__declspec(dllimport) int defdll_extra(void);
__declspec(dllimport) extern int defdll_extra_val;
int main(void)
{
    int a = defdll_get();
    defdll_val = 43;
    int b = defdll_get();
    int c = defdll_extra() + defdll_extra_val;
    int ok = a == 42 && b == 43 && defdll_val2 == 7 && c == 11;
    printf(ok ? "defdll: ok\n" : "defdll: failed %d %d %d %d\n", a, b, defdll_val2, c);
    return !ok;
}
