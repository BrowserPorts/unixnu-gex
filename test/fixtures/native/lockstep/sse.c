/* test/native/lockstep: scalar SSE in loops long enough to poll: float and double add, subtract,
 * multiply, divide, square root, min and max, compares that branch, and conversions to and from
 * integers and between the two widths, with values carried round the loop in registers (an
 * accumulator) and others made fresh each trip. The checksum takes every result's bits, so a
 * register's lane 0 kept apart from the rest of it (gex-cgen's split SSE registers) and joined
 * wrongly at a write-back shows up as a different result. */
#include "kernel.h"
#include <math.h>
#include <stdint.h>
#include <string.h>
enum { N = 512 };
static float fs[N];
static double ds[N];
static int32_t is[N];
static uint32_t bits32(float f) {
    uint32_t u;
    memcpy(&u, &f, sizeof u);
    return u;
}
static uint64_t bits64(double d) {
    uint64_t u;
    memcpy(&u, &d, sizeof u);
    return u;
}
unsigned kernel(int scale) {
    for (int i = 0; i < N; ++i) {
        fs[i] = (float)(i * 37 % 1001) / 13.0f - 30.0f;
        ds[i] = (double)(i * 91 % 2003) / 7.0 - 120.0;
        is[i] = i * 7919 - 1000000;
    }
    uint32_t acc = 2166136261u;
    float fa = 0.0f, fm = -1e30f;
    double da = 0.0, dmin = 1e300;
    for (int r = 0; r < 40 * scale; ++r) {
        for (int i = 0; i < N; ++i) {
            float x = fs[i], y = fs[(i * 5 + r) % N] + 0.5f;
            double p = ds[i], q = ds[(i * 3 + r) % N] - 0.25;
            float f1 = x * y + x / (fabsf(y) + 1.0f);
            double d1 = p * q - p / (fabs(q) + 1.0);
            fa += f1 * 0.001f;
            da += d1 * 1e-6;
            fm = fmaxf(fm, f1);
            dmin = fmin(dmin, d1);
            float sq = sqrtf(fabsf(f1));
            double dq = sqrt(fabs(d1));
            if (f1 > sq) acc = acc * 31u + 1u;
            if (d1 < -dq) acc = acc * 37u + 2u;
            int32_t k = (int32_t)(d1 * 0.5);
            float back = (float)is[i] * 1e-3f;
            double wide = (double)f1;
            float narrow = (float)d1;
            acc = (acc ^ bits32(f1)) * 16777619u;
            acc = (acc ^ (uint32_t)bits64(d1) ^ (uint32_t)(bits64(d1) >> 32)) * 16777619u;
            acc = (acc ^ bits32(sq) ^ (uint32_t)k) * 16777619u;
            acc = (acc ^ (uint32_t)bits64(dq) ^ bits32(back)) * 16777619u;
            acc = (acc ^ (uint32_t)(bits64(wide) >> 16) ^ bits32(narrow)) * 16777619u;
            fs[i] = isfinite(f1) && fabsf(f1) < 1e6f ? f1 * 0.5f : (float)(i - 256);
            ds[i] = isfinite(d1) && fabs(d1) < 1e12 ? d1 * 0.25 : (double)(i - 256);
        }
    }
    acc = (acc ^ bits32(fa) ^ bits32(fm)) * 16777619u;
    acc = (acc ^ (uint32_t)bits64(da) ^ (uint32_t)bits64(dmin)) * 16777619u;
    return acc;
}
