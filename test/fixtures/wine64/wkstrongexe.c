/* a strong reference to a function nothing defines, linked with
 * GEXCC_WIN_UNDEFINED=stub: its address is the stub's, never null */
#include <stdio.h>
extern void wkx(void);
int main(void)
{
    void (*volatile p)(void) = wkx;
    printf("wkstrong: %s\n", p ? "set" : "null");
    return 0;
}
