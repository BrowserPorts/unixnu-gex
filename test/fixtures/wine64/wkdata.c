/* Weak undefined data, tested by its address: it links, even without
 * GEXCC_WIN_UNDEFINED=stub, and its address is null. A weak reference to
 * data a DLL does define (wkdll.dll) reads that data. */
#include <stdio.h>
extern int wkdata_maybe __attribute__((weak));
extern __declspec(dllimport) int wkdata_def __attribute__((weak));
int main(void)
{
    printf("wkdata: %s %d\n", &wkdata_maybe ? "defined" : "null", &wkdata_def ? wkdata_def : -1);
    return 0;
}
