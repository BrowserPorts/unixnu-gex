/* gettimeofday over the system time (include/sys/time.h) */
#include <windows.h>
#include <sys/time.h>

int __cdecl gettimeofday(struct timeval *tv, void *tz)
{
    FILETIME ft;
    ULONGLONG t;
    (void)tz;
    if (!tv) return 0;
    GetSystemTimePreciseAsFileTime(&ft);
    t = (((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10 - 11644473600000000ULL;
    tv->tv_sec = (long)(t / 1000000);
    tv->tv_usec = (long)(t % 1000000);
    return 0;
}
