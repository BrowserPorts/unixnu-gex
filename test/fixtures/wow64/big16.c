/* big16: a reservation with no address of 16 GiB, more than gex's largest
 * memory can hold (a wasm sandbox's), refused; the program goes on.
 * "big16 refused" or "big16 got ADDR", then "big16 done". */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    void *p = VirtualAlloc(NULL, (SIZE_T)16 << 30, MEM_RESERVE, PAGE_NOACCESS);
    if (p) printf("big16 got %p\n", p);
    else printf("big16 refused\n");
    /* asked again: said once */
    VirtualAlloc(NULL, (SIZE_T)16 << 30, MEM_RESERVE, PAGE_NOACCESS);
    printf("big16 done\n");
    return 0;
}
