/* Calls through declarations whose types are not the functions' (their
 * definitions in sigadapt2.c), as Windows x64's slots make them work: the
 * link adapts each one (wcc64, sigadapt.py). */
#include <stdio.h>

extern int sig_counter;
int sig_extra(int, int);            /* defined int sig_extra() */
int sig_missing(int);               /* defined (int a, int b): b is 0 */
int sig_narrow(long long);          /* defined (int) */
void sig_val(void);                 /* defined returning int */
int sig_novalue(void);              /* defined void: 0 */
long long sig_widen(int);           /* defined (long long) */
void *sig_extra_addr(void);         /* &sig_extra where its type is known */
/* an address taken through the mismatched declaration: the function's own */
int (*sig_extra_ptr)(int, int) = sig_extra;

int main(void)
{
    int bad = 0;
    if (sig_extra(1, 2) != 5) bad |= 1;
    if (sig_missing(7) != 700) bad |= 2;
    if (sig_narrow(0x100000005LL) != 5) bad |= 4;
    sig_val();
    if (sig_counter != 1) bad |= 8;
    if (sig_novalue() != 0 || sig_counter != 11) bad |= 16;
    if (sig_widen(-1) != 0xffffffffLL) bad |= 32;
    if ((void *)sig_extra_ptr != sig_extra_addr()) bad |= 64;
    printf(bad ? "sigadapt: failed %d\n" : "sigadapt: ok\n", bad);
    return bad;
}
