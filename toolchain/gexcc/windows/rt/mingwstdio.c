/* mingw-w64's ANSI stdio entry points (__mingw_printf and the rest, which
 * its headers name under __USE_MINGW_ANSI_STDIO and C++), over the UCRT's
 * __stdio_common_* with ISO behaviour: C99 snprintf, and %s in a wide
 * format a char string. Not mingwex's own pformat and gdtoa: they keep a
 * long double as the x87's 80 bits, and gexcc-win's is a double
 * (-mlong-double-64), which the UCRT's %Lf and strtold take it as. Also
 * ldexpf in mingwldexpf.c. Linked by a mingw-headers install (install.sh). */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <math.h>

#define P_STD _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR
#define P_ISO 0  /* no legacy wide specifiers, no MSVCRT compatibility */
#define S_ISO 0

int __cdecl __mingw_vfprintf(FILE *f, const char *fmt, va_list ap) { return __stdio_common_vfprintf(P_ISO, f, fmt, NULL, ap); }
int __cdecl __mingw_vprintf(const char *fmt, va_list ap) { return __mingw_vfprintf(stdout, fmt, ap); }
int __cdecl __mingw_vsnprintf(char *s, size_t n, const char *fmt, va_list ap) { return __stdio_common_vsprintf(P_STD, s, n, fmt, NULL, ap); }
int __cdecl __mingw_vsprintf(char *s, const char *fmt, va_list ap) { return __stdio_common_vsprintf(P_ISO, s, (size_t)-1, fmt, NULL, ap); }
int __cdecl __mingw_vasprintf(char **out, const char *fmt, va_list ap)
{
    va_list aq;
    int n;
    va_copy(aq, ap);
    n = __mingw_vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);
    if (n < 0 || !(*out = malloc((size_t)n + 1))) return -1;
    return __mingw_vsnprintf(*out, (size_t)n + 1, fmt, ap);
}

int __cdecl __mingw_vfscanf(FILE *f, const char *fmt, va_list ap) { return __stdio_common_vfscanf(S_ISO, f, fmt, NULL, ap); }
int __cdecl __mingw_vscanf(const char *fmt, va_list ap) { return __mingw_vfscanf(stdin, fmt, ap); }
int __cdecl __mingw_vsscanf(const char *s, const char *fmt, va_list ap) { return __stdio_common_vsscanf(S_ISO, s, (size_t)-1, fmt, NULL, ap); }

int __cdecl __mingw_vfwprintf(FILE *f, const wchar_t *fmt, va_list ap) { return __stdio_common_vfwprintf(P_ISO, f, fmt, NULL, ap); }
int __cdecl __mingw_vwprintf(const wchar_t *fmt, va_list ap) { return __mingw_vfwprintf(stdout, fmt, ap); }
int __cdecl __mingw_vsnwprintf(wchar_t *s, size_t n, const wchar_t *fmt, va_list ap) { return __stdio_common_vswprintf(P_STD, s, n, fmt, NULL, ap); }
/* (C99's swprintf: -1 when it does not fit) */
int __cdecl __mingw_vswprintf(wchar_t *s, size_t n, const wchar_t *fmt, va_list ap)
{
    int r = __stdio_common_vswprintf(P_STD, s, n, fmt, NULL, ap);
    return r >= 0 && (size_t)r >= n ? -1 : r;
}
int __cdecl __mingw_vfwscanf(FILE *f, const wchar_t *fmt, va_list ap) { return __stdio_common_vfwscanf(S_ISO, f, fmt, NULL, ap); }
int __cdecl __mingw_vwscanf(const wchar_t *fmt, va_list ap) { return __mingw_vfwscanf(stdin, fmt, ap); }
int __cdecl __mingw_vswscanf(const wchar_t *s, const wchar_t *fmt, va_list ap) { return __stdio_common_vswscanf(S_ISO, s, (size_t)-1, fmt, NULL, ap); }

#define VA(call) { va_list ap; int r; va_start(ap, fmt); r = call; va_end(ap); return r; }
int __cdecl __mingw_printf(const char *fmt, ...) VA(__mingw_vprintf(fmt, ap))
int __cdecl __mingw_fprintf(FILE *f, const char *fmt, ...) VA(__mingw_vfprintf(f, fmt, ap))
int __cdecl __mingw_sprintf(char *s, const char *fmt, ...) VA(__mingw_vsprintf(s, fmt, ap))
int __cdecl __mingw_snprintf(char *s, size_t n, const char *fmt, ...) VA(__mingw_vsnprintf(s, n, fmt, ap))
int __cdecl __mingw_asprintf(char **out, const char *fmt, ...) VA(__mingw_vasprintf(out, fmt, ap))
int __cdecl __mingw_scanf(const char *fmt, ...) VA(__mingw_vscanf(fmt, ap))
int __cdecl __mingw_fscanf(FILE *f, const char *fmt, ...) VA(__mingw_vfscanf(f, fmt, ap))
int __cdecl __mingw_sscanf(const char *s, const char *fmt, ...) VA(__mingw_vsscanf(s, fmt, ap))
int __cdecl __mingw_wprintf(const wchar_t *fmt, ...) VA(__mingw_vwprintf(fmt, ap))
int __cdecl __mingw_fwprintf(FILE *f, const wchar_t *fmt, ...) VA(__mingw_vfwprintf(f, fmt, ap))
int __cdecl __mingw_swprintf(wchar_t *s, size_t n, const wchar_t *fmt, ...) VA(__mingw_vswprintf(s, n, fmt, ap))
int __cdecl __mingw_snwprintf(wchar_t *s, size_t n, const wchar_t *fmt, ...) VA(__mingw_vsnwprintf(s, n, fmt, ap))
int __cdecl __mingw_wscanf(const wchar_t *fmt, ...) VA(__mingw_vwscanf(fmt, ap))
int __cdecl __mingw_fwscanf(FILE *f, const wchar_t *fmt, ...) VA(__mingw_vfwscanf(f, fmt, ap))
int __cdecl __mingw_swscanf(const wchar_t *s, const wchar_t *fmt, ...) VA(__mingw_vswscanf(s, fmt, ap))

double __cdecl __mingw_strtod(const char *s, char **end) { return strtod(s, end); }
float __cdecl __mingw_strtof(const char *s, char **end) { return strtof(s, end); }
long double __cdecl __mingw_strtold(const char *s, char **end) { return strtold(s, end); }
double __cdecl __mingw_wcstod(const wchar_t *s, wchar_t **end) { return wcstod(s, end); }
float __cdecl __mingw_wcstof(const wchar_t *s, wchar_t **end) { return wcstof(s, end); }
long double __cdecl __mingw_wcstold(const wchar_t *s, wchar_t **end) { return wcstold(s, end); }
