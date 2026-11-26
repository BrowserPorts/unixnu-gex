/* immintrin.h for Windows programs (gexcc-win): with clang-cl's identity
 * (_M_X64), the x64 compiler's scalar intrinsics an MSVC project takes from
 * it: the HLE-hinted interlocked operations (the hint is only a hint, so the
 * plain operation), and gexw-intrin.h's _mm_pause and fences. No vector types: wasm code takes the
 * scalar paths, and code written for SSE does not compile. Without that
 * identity it is clang's own header. */
#ifndef _MSC_VER
#include_next <immintrin.h>
#else
#ifndef GEXCC_WIN_IMMINTRIN_H
#define GEXCC_WIN_IMMINTRIN_H
#include <intrin.h>
#include <gexw-intrin.h>
#ifdef __cplusplus
extern "C" {
#endif
#define GEXCC_WIN_HLE(T, S)                                                                                   \
    static __inline__ T _InterlockedExchange##S##_HLEAcquire(T volatile *t, T v) { return _InterlockedExchange##S(t, v); } \
    static __inline__ T _InterlockedExchange##S##_HLERelease(T volatile *t, T v) { return _InterlockedExchange##S(t, v); } \
    static __inline__ T _InterlockedCompareExchange##S##_HLEAcquire(T volatile *t, T x, T c) { return _InterlockedCompareExchange##S(t, x, c); } \
    static __inline__ T _InterlockedCompareExchange##S##_HLERelease(T volatile *t, T x, T c) { return _InterlockedCompareExchange##S(t, x, c); }
GEXCC_WIN_HLE(long, )
GEXCC_WIN_HLE(__int64, 64)
#undef GEXCC_WIN_HLE
#ifdef __cplusplus
}
#endif
#endif
#endif
