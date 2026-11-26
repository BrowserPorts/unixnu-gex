/* time.h for Windows programs (gexcc-win): msvcrt's, with the UCRT's
 * time zone accessors ucrtbase exports and the Windows SDK declares */
#include_next <time.h>
#ifndef GEXCC_WIN_TIME_H
#define GEXCC_WIN_TIME_H
#ifdef __cplusplus
extern "C" {
#endif
errno_t __cdecl _get_daylight(int *);
errno_t __cdecl _get_dstbias(long *);
errno_t __cdecl _get_timezone(long *);
errno_t __cdecl _get_tzname(size_t *, char *, size_t, int);
#ifdef __cplusplus
}
#endif
#endif
