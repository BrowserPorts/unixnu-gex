/* The intrinsics an x64 Windows compiler has built in, in portable C, each
 * one clang on wasm lacks (gexcc-win): what mingw-w64's headers name for
 * Windows x64 (their psdk_inc/intrin-impl.h, x86 inline asm there, includes
 * this), and what MSVC provides with no header at all (clang-cl's identity
 * includes it first). mingw-w64's headers include it several times, each
 * time for one group; this defines everything the first time. Port I/O, control and model-specific
 * registers are left out: a program that uses them fails to compile.
 * __readgs* and __writegs* read the TEB, which the x64 GS segment holds. */
#ifndef GEXW_INTRIN_IMPL_H
#define GEXW_INTRIN_IMPL_H

/* (long is 32-bit: LLP64) */
#define __GEXW_LONG32 long

#ifdef __cplusplus
extern "C" {
#endif

/* (as mingw-w64 has them: extern inline, as the C runtime declares some) */
#define __GEXW_INTRIN extern __inline__ __attribute__((__always_inline__,__gnu_inline__))
/* (each one clang does not have as a builtin already: with -fms-extensions
 * it has the target-independent ones, _bittest, _InterlockedAnd ...) */
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

/* (functions, not macros: the SDK headers declare them) */
#if !__has_builtin(_ReadWriteBarrier)
__GEXW_INTRIN void _ReadWriteBarrier(void) { __atomic_signal_fence(__ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_ReadBarrier)
__GEXW_INTRIN void _ReadBarrier(void) { __atomic_signal_fence(__ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_WriteBarrier)
__GEXW_INTRIN void _WriteBarrier(void) { __atomic_signal_fence(__ATOMIC_SEQ_CST); }
#endif

/* bit scans and tests */
#if !__has_builtin(_BitScanForward)
__GEXW_INTRIN unsigned char _BitScanForward(unsigned __GEXW_LONG32 *i, unsigned __GEXW_LONG32 m)
{ if (!m) return 0; *i = __builtin_ctz(m); return 1; }
#endif
#if !__has_builtin(_BitScanReverse)
__GEXW_INTRIN unsigned char _BitScanReverse(unsigned __GEXW_LONG32 *i, unsigned __GEXW_LONG32 m)
{ if (!m) return 0; *i = 31 - __builtin_clz(m); return 1; }
#endif
#if !__has_builtin(_BitScanForward64)
__GEXW_INTRIN unsigned char _BitScanForward64(unsigned __GEXW_LONG32 *i, unsigned __int64 m)
{ if (!m) return 0; *i = __builtin_ctzll(m); return 1; }
#endif
#if !__has_builtin(_BitScanReverse64)
__GEXW_INTRIN unsigned char _BitScanReverse64(unsigned __GEXW_LONG32 *i, unsigned __int64 m)
{ if (!m) return 0; *i = 63 - __builtin_clzll(m); return 1; }
#endif

#define __GEXW_BITTEST(name, T, op) \
  __GEXW_INTRIN unsigned char name(T *b, T o) { unsigned char r = (*b >> o) & 1; op; return r; }
#if !__has_builtin(_bittest)
__GEXW_BITTEST(_bittest, const __GEXW_LONG32, (void)0)
#endif
#if !__has_builtin(_bittestandset)
__GEXW_BITTEST(_bittestandset, __GEXW_LONG32, *b |= (__GEXW_LONG32)1 << o)
#endif
#if !__has_builtin(_bittestandreset)
__GEXW_BITTEST(_bittestandreset, __GEXW_LONG32, *b &= ~((__GEXW_LONG32)1 << o))
#endif
#if !__has_builtin(_bittestandcomplement)
__GEXW_BITTEST(_bittestandcomplement, __GEXW_LONG32, *b ^= (__GEXW_LONG32)1 << o)
#endif
#if !__has_builtin(_bittest64)
__GEXW_BITTEST(_bittest64, const __int64, (void)0)
#endif
#if !__has_builtin(_bittestandset64)
__GEXW_BITTEST(_bittestandset64, __int64, *b |= (__int64)1 << o)
#endif
#if !__has_builtin(_bittestandreset64)
__GEXW_BITTEST(_bittestandreset64, __int64, *b &= ~((__int64)1 << o))
#endif
#if !__has_builtin(_bittestandcomplement64)
__GEXW_BITTEST(_bittestandcomplement64, __int64, *b ^= (__int64)1 << o)
#endif

#define __GEXW_ABITTEST(name, T, f, m) \
  __GEXW_INTRIN unsigned char name(T volatile *b, T o) \
  { return (f(b, m, __ATOMIC_SEQ_CST) >> o) & 1; }
#if !__has_builtin(_interlockedbittestandset)
__GEXW_ABITTEST(_interlockedbittestandset, __GEXW_LONG32, __atomic_fetch_or, (__GEXW_LONG32)1 << o)
#endif
#if !__has_builtin(_interlockedbittestandreset)
__GEXW_ABITTEST(_interlockedbittestandreset, __GEXW_LONG32, __atomic_fetch_and, ~((__GEXW_LONG32)1 << o))
#endif
#if !__has_builtin(_interlockedbittestandcomplement)
__GEXW_ABITTEST(_interlockedbittestandcomplement, __GEXW_LONG32, __atomic_fetch_xor, (__GEXW_LONG32)1 << o)
#endif
#if !__has_builtin(_interlockedbittestandset64)
__GEXW_ABITTEST(_interlockedbittestandset64, __int64, __atomic_fetch_or, (__int64)1 << o)
#endif
#if !__has_builtin(_interlockedbittestandreset64)
__GEXW_ABITTEST(_interlockedbittestandreset64, __int64, __atomic_fetch_and, ~((__int64)1 << o))
#endif
#if !__has_builtin(_interlockedbittestandcomplement64)
__GEXW_ABITTEST(_interlockedbittestandcomplement64, __int64, __atomic_fetch_xor, (__int64)1 << o)
#endif
#define InterlockedBitTestAndSet _interlockedbittestandset
#define InterlockedBitTestAndReset _interlockedbittestandreset
#define InterlockedBitTestAndComplement _interlockedbittestandcomplement
#define InterlockedBitTestAndSet64 _interlockedbittestandset64
#define InterlockedBitTestAndReset64 _interlockedbittestandreset64
#define InterlockedBitTestAndComplement64 _interlockedbittestandcomplement64

/* interlocked operations, all sequentially consistent as on x64 */
#define __GEXW_FETCH(name, T, f) \
  __GEXW_INTRIN T name(T volatile *d, T v) { return f(d, v, __ATOMIC_SEQ_CST); }
#define __GEXW_OPFETCH(name, T, f) \
  __GEXW_INTRIN T name(T volatile *d, T v) { return f(d, v, __ATOMIC_SEQ_CST); }
#if !__has_builtin(_InterlockedAnd8)
__GEXW_FETCH(_InterlockedAnd8, char, __atomic_fetch_and)
#endif
#if !__has_builtin(_InterlockedOr8)
__GEXW_FETCH(_InterlockedOr8, char, __atomic_fetch_or)
#endif
#if !__has_builtin(_InterlockedXor8)
__GEXW_FETCH(_InterlockedXor8, char, __atomic_fetch_xor)
#endif
#if !__has_builtin(_InterlockedAnd16)
__GEXW_FETCH(_InterlockedAnd16, short, __atomic_fetch_and)
#endif
#if !__has_builtin(_InterlockedOr16)
__GEXW_FETCH(_InterlockedOr16, short, __atomic_fetch_or)
#endif
#if !__has_builtin(_InterlockedXor16)
__GEXW_FETCH(_InterlockedXor16, short, __atomic_fetch_xor)
#endif
#if !__has_builtin(_InterlockedAnd)
__GEXW_FETCH(_InterlockedAnd, __GEXW_LONG32, __atomic_fetch_and)
#endif
#if !__has_builtin(_InterlockedOr)
__GEXW_FETCH(_InterlockedOr, __GEXW_LONG32, __atomic_fetch_or)
#endif
#if !__has_builtin(_InterlockedXor)
__GEXW_FETCH(_InterlockedXor, __GEXW_LONG32, __atomic_fetch_xor)
#endif
#if !__has_builtin(_InterlockedExchangeAdd8)
__GEXW_FETCH(_InterlockedExchangeAdd8, char, __atomic_fetch_add)
#endif
#if !__has_builtin(_InterlockedExchangeAdd16)
__GEXW_FETCH(_InterlockedExchangeAdd16, short, __atomic_fetch_add)
#endif
#if !__has_builtin(_InterlockedExchangeAdd)
__GEXW_FETCH(_InterlockedExchangeAdd, __GEXW_LONG32, __atomic_fetch_add)
#endif
#if !__has_builtin(_InterlockedExchange8)
__GEXW_FETCH(_InterlockedExchange8, char, __atomic_exchange_n)
#endif
#if !__has_builtin(_InterlockedExchange16)
__GEXW_FETCH(_InterlockedExchange16, short, __atomic_exchange_n)
#endif
#if !__has_builtin(_InterlockedExchange)
__GEXW_FETCH(_InterlockedExchange, __GEXW_LONG32, __atomic_exchange_n)
#endif
#if !__has_builtin(_InterlockedAdd)
__GEXW_OPFETCH(_InterlockedAdd, __GEXW_LONG32, __atomic_add_fetch)
#endif
#if !__has_builtin(_InterlockedAnd64)
__GEXW_FETCH(_InterlockedAnd64, __int64, __atomic_fetch_and)
#endif
#if !__has_builtin(_InterlockedOr64)
__GEXW_FETCH(_InterlockedOr64, __int64, __atomic_fetch_or)
#endif
#if !__has_builtin(_InterlockedXor64)
__GEXW_FETCH(_InterlockedXor64, __int64, __atomic_fetch_xor)
#endif
#if !__has_builtin(_InterlockedExchangeAdd64)
__GEXW_FETCH(_InterlockedExchangeAdd64, __int64, __atomic_fetch_add)
#endif
#if !__has_builtin(_InterlockedExchange64)
__GEXW_FETCH(_InterlockedExchange64, __int64, __atomic_exchange_n)
#endif
#if !__has_builtin(_InterlockedAdd64)
__GEXW_OPFETCH(_InterlockedAdd64, __int64, __atomic_add_fetch)
#endif

#if !__has_builtin(_InterlockedIncrement16)
__GEXW_INTRIN short _InterlockedIncrement16(short volatile *a) { return __atomic_add_fetch(a, 1, __ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_InterlockedDecrement16)
__GEXW_INTRIN short _InterlockedDecrement16(short volatile *a) { return __atomic_sub_fetch(a, 1, __ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_InterlockedIncrement)
__GEXW_INTRIN __GEXW_LONG32 _InterlockedIncrement(__GEXW_LONG32 volatile *a) { return __atomic_add_fetch(a, 1, __ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_InterlockedDecrement)
__GEXW_INTRIN __GEXW_LONG32 _InterlockedDecrement(__GEXW_LONG32 volatile *a) { return __atomic_sub_fetch(a, 1, __ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_InterlockedIncrement64)
__GEXW_INTRIN __int64 _InterlockedIncrement64(__int64 volatile *a) { return __atomic_add_fetch(a, 1, __ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_InterlockedDecrement64)
__GEXW_INTRIN __int64 _InterlockedDecrement64(__int64 volatile *a) { return __atomic_sub_fetch(a, 1, __ATOMIC_SEQ_CST); }
#endif

#define __GEXW_CAS(name, T) \
  __GEXW_INTRIN T name(T volatile *d, T x, T c) \
  { __atomic_compare_exchange_n(d, &c, x, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return c; }
#if !__has_builtin(_InterlockedCompareExchange8)
__GEXW_CAS(_InterlockedCompareExchange8, char)
#endif
#if !__has_builtin(_InterlockedCompareExchange16)
__GEXW_CAS(_InterlockedCompareExchange16, short)
#endif
#if !__has_builtin(_InterlockedCompareExchange)
__GEXW_CAS(_InterlockedCompareExchange, __GEXW_LONG32)
#endif
#if !__has_builtin(_InterlockedCompareExchange64)
__GEXW_CAS(_InterlockedCompareExchange64, __int64)
#endif
#if !__has_builtin(_InterlockedCompareExchangePointer)
__GEXW_INTRIN void *_InterlockedCompareExchangePointer(void *volatile *d, void *x, void *c)
{ __atomic_compare_exchange_n(d, &c, x, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return c; }
#endif
#if !__has_builtin(_InterlockedExchangePointer)
__GEXW_INTRIN void *_InterlockedExchangePointer(void *volatile *d, void *v)
{ return __atomic_exchange_n(d, v, __ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_InterlockedCompareExchange128)
__GEXW_INTRIN unsigned char _InterlockedCompareExchange128(__int64 volatile *d, __int64 hi, __int64 lo, __int64 *c)
{
  __int128 e = ((__int128)c[1] << 64) | (unsigned __int64)c[0];
  __int128 x = ((__int128)hi << 64) | (unsigned __int64)lo;
  unsigned char r = __atomic_compare_exchange_n((__int128 volatile *)d, &e, x, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  c[0] = (__int64)e; c[1] = (__int64)(e >> 64);
  return r;
}
#endif

/* fences, and the SSE ones winnt.h's macros name */
#if !__has_builtin(__faststorefence)
__GEXW_INTRIN void __faststorefence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_mm_mfence)
__GEXW_INTRIN void _mm_mfence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_mm_lfence)
__GEXW_INTRIN void _mm_lfence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_mm_sfence)
__GEXW_INTRIN void _mm_sfence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
#endif
#if !__has_builtin(_mm_pause)
__GEXW_INTRIN void _mm_pause(void) { }
#endif
#if !__has_builtin(_mm_clflush)
__GEXW_INTRIN void _mm_clflush(void const *p) { (void)p; }
#endif
#define _mm_prefetch(p, h) ((void)(p), (void)(h))
#if !__has_builtin(_mm_getcsr)
__GEXW_INTRIN unsigned int _mm_getcsr(void) { return 0x1f80; }
#endif
#if !__has_builtin(_mm_setcsr)
__GEXW_INTRIN void _mm_setcsr(unsigned int c) { (void)c; }
#endif

/* string moves and stores */
#define __GEXW_STOS(name, T) \
  __GEXW_INTRIN void name(T *d, T v, size_t n) { while (n--) *d++ = v; }
#define __GEXW_MOVS(name, T) \
  __GEXW_INTRIN void name(T *d, T const *s, size_t n) { while (n--) *d++ = *s++; }
#if !__has_builtin(__stosb)
__GEXW_STOS(__stosb, unsigned char)
#endif
#if !__has_builtin(__stosw)
__GEXW_STOS(__stosw, unsigned short)
#endif
#if !__has_builtin(__stosd)
__GEXW_STOS(__stosd, unsigned __GEXW_LONG32)
#endif
#if !__has_builtin(__stosq)
__GEXW_STOS(__stosq, unsigned __int64)
#endif
#if !__has_builtin(__movsb)
__GEXW_MOVS(__movsb, unsigned char)
#endif
#if !__has_builtin(__movsw)
__GEXW_MOVS(__movsw, unsigned short)
#endif
#if !__has_builtin(__movsd)
__GEXW_MOVS(__movsd, unsigned __GEXW_LONG32)
#endif
#if !__has_builtin(__movsq)
__GEXW_MOVS(__movsq, unsigned __int64)
#endif

/* bit counts, rotates, 128-bit arithmetic */
#if !__has_builtin(__popcnt16)
__GEXW_INTRIN unsigned short __popcnt16(unsigned short v) { return __builtin_popcount(v); }
#endif
#if !__has_builtin(__popcnt)
__GEXW_INTRIN unsigned int __popcnt(unsigned int v) { return __builtin_popcount(v); }
#endif
#if !__has_builtin(__popcnt64)
__GEXW_INTRIN unsigned __int64 __popcnt64(unsigned __int64 v) { return __builtin_popcountll(v); }
#endif
#if !__has_builtin(__lzcnt16)
__GEXW_INTRIN unsigned short __lzcnt16(unsigned short v) { return v ? __builtin_clz(v) - 16 : 16; }
#endif
#if !__has_builtin(__lzcnt)
__GEXW_INTRIN unsigned int __lzcnt(unsigned int v) { return v ? __builtin_clz(v) : 32; }
#endif
#if !__has_builtin(__lzcnt64)
__GEXW_INTRIN unsigned __int64 __lzcnt64(unsigned __int64 v) { return v ? __builtin_clzll(v) : 64; }
#endif
#if !__has_builtin(_rotl8)
__GEXW_INTRIN unsigned char _rotl8(unsigned char v, unsigned char s) { s &= 7; return s ? (v << s) | (v >> (8 - s)) : v; }
#endif
#if !__has_builtin(_rotr8)
__GEXW_INTRIN unsigned char _rotr8(unsigned char v, unsigned char s) { s &= 7; return s ? (v >> s) | (v << (8 - s)) : v; }
#endif
#if !__has_builtin(_rotl16)
__GEXW_INTRIN unsigned short _rotl16(unsigned short v, unsigned char s) { s &= 15; return s ? (v << s) | (v >> (16 - s)) : v; }
#endif
#if !__has_builtin(_rotr16)
__GEXW_INTRIN unsigned short _rotr16(unsigned short v, unsigned char s) { s &= 15; return s ? (v >> s) | (v << (16 - s)) : v; }
#endif
#if !__has_builtin(_lrotl)
__GEXW_INTRIN unsigned __GEXW_LONG32 _lrotl(unsigned __GEXW_LONG32 v, int s) { s &= 31; return s ? (v << s) | (v >> (32 - s)) : v; }
#endif
#if !__has_builtin(_lrotr)
__GEXW_INTRIN unsigned __GEXW_LONG32 _lrotr(unsigned __GEXW_LONG32 v, int s) { s &= 31; return s ? (v >> s) | (v << (32 - s)) : v; }
#endif
#if !__has_builtin(__shiftleft128)
__GEXW_INTRIN unsigned __int64 __shiftleft128(unsigned __int64 lo, unsigned __int64 hi, unsigned char n)
{ n &= 63; return n ? (hi << n) | (lo >> (64 - n)) : hi; }
#endif
#if !__has_builtin(__shiftright128)
__GEXW_INTRIN unsigned __int64 __shiftright128(unsigned __int64 lo, unsigned __int64 hi, unsigned char n)
{ n &= 63; return n ? (lo >> n) | (hi << (64 - n)) : lo; }
#endif
#if !__has_builtin(__umulh)
__GEXW_INTRIN unsigned __int64 __umulh(unsigned __int64 a, unsigned __int64 b)
{ return (unsigned __int64)(((unsigned __int128)a * b) >> 64); }
#endif
#if !__has_builtin(__mulh)
__GEXW_INTRIN __int64 __mulh(__int64 a, __int64 b) { return (__int64)(((__int128)a * b) >> 64); }
#endif
#if !__has_builtin(_umul128)
__GEXW_INTRIN unsigned __int64 _umul128(unsigned __int64 a, unsigned __int64 b, unsigned __int64 *hi)
{ unsigned __int128 r = (unsigned __int128)a * b; *hi = (unsigned __int64)(r >> 64); return (unsigned __int64)r; }
#endif
#if !__has_builtin(_mul128)
__GEXW_INTRIN __int64 _mul128(__int64 a, __int64 b, __int64 *hi)
{ __int128 r = (__int128)a * b; *hi = (__int64)(r >> 64); return (__int64)r; }
#endif

/* the CPU: an x64 baseline with nothing optional (cpuid leaf 0 reports no
 * further leaves) */
#if !__has_builtin(__cpuid)
__GEXW_INTRIN void __cpuid(int r[4], int leaf) { (void)leaf; r[0] = r[1] = r[2] = r[3] = 0; }
#endif
#if !__has_builtin(__cpuidex)
__GEXW_INTRIN void __cpuidex(int r[4], int leaf, int sub) { (void)leaf; (void)sub; r[0] = r[1] = r[2] = r[3] = 0; }
#endif
#if !__has_builtin(_xgetbv)
__GEXW_INTRIN unsigned __int64 _xgetbv(unsigned int x) { (void)x; return 0; }
#endif
#if !__has_builtin(__int2c)
__GEXW_INTRIN void __int2c(void) { __builtin_trap(); }
#endif

/* the GS segment: the TEB */
struct _TEB *__stdcall __wine_wasm_current_teb(void);
#define __GEXW_GS(T, sfx) \
  __GEXW_INTRIN T __readgs##sfx(unsigned __GEXW_LONG32 o) { return *(T *)((char *)__wine_wasm_current_teb() + o); } \
  __GEXW_INTRIN void __writegs##sfx(unsigned __GEXW_LONG32 o, T v) { *(T *)((char *)__wine_wasm_current_teb() + o) = v; }
__GEXW_GS(unsigned char, byte)
__GEXW_GS(unsigned short, word)
__GEXW_GS(unsigned __GEXW_LONG32, dword)
__GEXW_GS(unsigned __int64, qword)

#ifdef __cplusplus
}
#endif

#endif /* GEXW_INTRIN_IMPL_H */
