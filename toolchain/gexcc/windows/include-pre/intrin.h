/* intrin.h for Windows programs (gexcc-win): msvcrt's, with the compiler
 * intrinsics an x64 compiler provides that wasm has no builtins for. The bit
 * scans and interlocked operations are winnt.h's inline definitions. */
#include_next <intrin.h>
#ifndef GEXCC_WIN_INTRIN_H
#define GEXCC_WIN_INTRIN_H
#include <windef.h>
#ifdef __cplusplus
extern "C" {
#endif
static __inline__ unsigned __int64 __umulh(unsigned __int64 a, unsigned __int64 b)
{
    return (unsigned __int64)(((unsigned __int128)a * b) >> 64);
}
static __inline__ __int64 __mulh(__int64 a, __int64 b)
{
    return (__int64)(((__int128)a * b) >> 64);
}
static __inline__ unsigned __int64 _umul128(unsigned __int64 a, unsigned __int64 b, unsigned __int64 *hi)
{
    unsigned __int128 r = (unsigned __int128)a * b;
    *hi = (unsigned __int64)(r >> 64);
    return (unsigned __int64)r;
}
static __inline__ __int64 _mul128(__int64 a, __int64 b, __int64 *hi)
{
    __int128 r = (__int128)a * b;
    *hi = (__int64)(r >> 64);
    return (__int64)r;
}
static __inline__ unsigned __int64 __shiftleft128(unsigned __int64 lo, unsigned __int64 hi, unsigned char n)
{
    n &= 63;
    return n ? (hi << n) | (lo >> (64 - n)) : hi;
}
static __inline__ unsigned __int64 __shiftright128(unsigned __int64 lo, unsigned __int64 hi, unsigned char n)
{
    n &= 63;
    return n ? (lo >> n) | (hi << (64 - n)) : lo;
}
#ifdef __cplusplus
}
#endif
#endif
