/* mingw-w64's ANSI stdio (__USE_MINGW_ANSI_STDIO: printf is __mingw_printf)
 * over the UCRT: C99 snprintf's count past its buffer, %lld and %zu, a
 * long double, sscanf, and a wide format's %s taking a char string */
#define __USE_MINGW_ANSI_STDIO 1
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

int main(void)
{
    char b[8];
    wchar_t w[32];
    long long v = 0;
    int n = snprintf(b, sizeof(b), "%lld-%zu", 1234567890123LL, (size_t)42);
    int k = sscanf("77 x", "%lld", &v);
    int m = swprintf(w, 32, L"%s/%d", "ab", 5);
    double d = strtod("2.5", NULL);
    long double ld = 1.5L;
    printf("mingwstdio: %d %s %d %lld %d %ls %.1f %.2Lf\n", n, b, k, v, m, w, d, ld);
    return 0;
}
