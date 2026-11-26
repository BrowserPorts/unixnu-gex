// weak undefined functions are null: a C weak declaration nobody defines,
// and C++'s thread_local init function (_ZTH*) for a thread_local another
// TU defines with no dynamic initializer (ANGLE's gCurrentValidContext)
#include <stdio.h>
extern "C" void wkfunc_maybe(void) __attribute__((weak));
extern thread_local int wkfunc_tl;
int wkfunc_read();
extern "C" __declspec(dllimport) int wkweak_has(void);
int main()
{
    wkfunc_tl = 5;
    printf("wkfunc: %s %d %d\n", wkfunc_maybe ? "set" : "null", wkfunc_read(), wkweak_has());
    return 0;
}
