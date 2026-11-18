/* test/native/lockstep: x87 arithmetic through long double (the 80-bit type on i386 and x86-64):
 * add, subtract, multiply, divide and square root, compares, narrowing to double and float, and
 * conversion to integers, in each rounding mode, over normal, tiny, huge, zero, infinite and NaN
 * operands. The checksum takes every result's bits, so a helper that rounds or flags differently
 * on the function tier shows up as a different result. */
#include "kernel.h"
#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
enum { N = 64 };
static long double vals[N];
static uint32_t mix(uint32_t acc, const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; ++i) acc = acc * 16777619u ^ b[i];
    return acc;
}
static uint32_t ld_bits(uint32_t acc, long double v) {
    unsigned char b[10];
    memcpy(b, &v, 10);
    return mix(acc, b, 10);
}
unsigned kernel(int scale) {
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    for (int i = 0; i < N; ++i) {
        long double x = (long double)(i * 2654435761u % 100003u) / 97.0L - 300.0L;
        switch (i % 8) {
        case 0: x = 0.0L; break;
        case 1: x *= 1e-4930L; break;
        case 2: x *= 1e4900L; break;
        case 3: x = (i & 16) ? INFINITY : -INFINITY; break;
        case 4: x = NAN; break;
        default: break;
        }
        vals[i] = x;
    }
    uint32_t acc = 2166136261u;
    for (int r = 0; r < 6 * scale; ++r) {
        for (int m = 0; m < 4; ++m) {
            fesetround(modes[m]);
            for (int i = 0; i < N; ++i) {
                long double a = vals[i], b = vals[(i * 7 + r) % N] + (long double)(r + 1) / 3.0L;
                long double s = a + b, d = a - b, p = a * b, q = a / b;
                long double t = sqrtl(fabsl(p) + 1.0L);
                acc = ld_bits(acc, s);
                acc = ld_bits(acc, d);
                acc = ld_bits(acc, p);
                acc = ld_bits(acc, q);
                acc = ld_bits(acc, t);
                acc = acc * 31u + (a < b) + 2u * (a == b) + 4u * (a > b) + 8u * isunordered(a, b);
                double nd = (double)q;
                float nf = (float)s;
                acc = mix(acc, &nd, sizeof nd);
                acc = mix(acc, &nf, sizeof nf);
                if (isfinite(d) && fabsl(d) < 9e18L) {
                    long long k = llrintl(d);
                    int j = (int)(d / 4096.0L);
                    acc = mix(acc, &k, sizeof k);
                    acc = mix(acc, &j, sizeof j);
                }
                vals[i] = (isfinite(t) ? t : a) * 0.75L + q * 1e-3L;
                if (!isfinite(vals[i]) || fabsl(vals[i]) > 1e4000L) vals[i] = (long double)(i - 32);
            }
        }
    }
    fesetround(FE_TONEAREST);
    return acc;
}
