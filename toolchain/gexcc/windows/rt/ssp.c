/* The stack protector's guard and failure (-fstack-protector), as MinGW's
 * libssp provides them (gexcc-win): the guard from rand_s at startup. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uintptr_t __stack_chk_guard = (uintptr_t)0x2f8a6c1d5e3b9047ull;

errno_t __cdecl rand_s(unsigned int *);

__attribute__((constructor)) static void gexcc_win_ssp_init(void)
{
    unsigned int a, b;
    if (!rand_s(&a) && !rand_s(&b))
        __stack_chk_guard = ((uintptr_t)a << 32 | b) & ~(uintptr_t)0xff;
}

void __stack_chk_fail(void)
{
    fputs("*** stack smashing detected ***: terminated\n", stderr);
    abort();
}

/* _FORTIFY_SOURCE's checked string calls (MinGW's string.h makes them through
 * __builtin___*_chk), as mingw-w64's crt/ssp: the destination's size first */
#include <string.h>

void __cdecl __chk_fail(void)
{
    fputs("*** buffer overflow detected ***: terminated\n", stderr);
    abort();
}

void *__cdecl __memcpy_chk(void *d, const void *s, size_t n, size_t dn)
{
    if (n > dn) __chk_fail();
    return memcpy(d, s, n);
}

void *__cdecl __memmove_chk(void *d, const void *s, size_t n, size_t dn)
{
    if (n > dn) __chk_fail();
    return memmove(d, s, n);
}

void *__cdecl __mempcpy_chk(void *d, const void *s, size_t n, size_t dn)
{
    if (n > dn) __chk_fail();
    return (char *)memcpy(d, s, n) + n;
}

void *__cdecl __memset_chk(void *d, int c, size_t n, size_t dn)
{
    if (n > dn) __chk_fail();
    return memset(d, c, n);
}

char *__cdecl __strcpy_chk(char *d, const char *s, size_t dn)
{
    size_t n = strlen(s);
    if (n >= dn) __chk_fail();
    return memcpy(d, s, n + 1);
}

char *__cdecl __strncpy_chk(char *d, const char *s, size_t n, size_t dn)
{
    if (n > dn) __chk_fail();
    return strncpy(d, s, n);
}

char *__cdecl __strcat_chk(char *d, const char *s, size_t dn)
{
    size_t a = strlen(d), b = strlen(s);
    if (a + b >= dn) __chk_fail();
    memcpy(d + a, s, b + 1);
    return d;
}

char *__cdecl __strncat_chk(char *d, const char *s, size_t n, size_t dn)
{
    size_t a = strlen(d), b = strnlen(s, n);
    if (a + b >= dn) __chk_fail();
    memcpy(d + a, s, b);
    d[a + b] = 0;
    return d;
}
