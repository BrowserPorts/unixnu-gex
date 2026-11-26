/* fficall.c's callees, in a DLL: reached through its import (a native
 * function value) and through GetProcAddress (a guest one) */
#include <stdint.h>

struct pt { int x, y; };          /* wasm: by pointer / sret; Win64: in a slot */
struct big { double a, b, c; };   /* by pointer / sret on both */
struct wrapd { double d; };       /* wasm: an f64; Win64: in a slot */
struct trio { char c[3]; };       /* wasm: by pointer; Win64: by pointer */
struct wrapf { float f; };        /* wasm: an f32; Win64: in a slot */

__declspec(dllexport) double mix(int8_t a, uint16_t b, int c, int64_t d, float e, double f, const int *p)
{
    return a + b + c + (double)d + e + f + *p;
}
__declspec(dllexport) struct pt pt_add(struct pt a, struct pt b)
{
    struct pt r = { a.x + b.x, a.y + b.y };
    return r;
}
__declspec(dllexport) struct big big_scale(struct big v, double k)
{
    struct big r = { v.a * k, v.b * k, v.c * k };
    return r;
}
__declspec(dllexport) struct wrapd wrap_half(struct wrapd v)
{
    struct wrapd r = { v.d / 2 };
    return r;
}
__declspec(dllexport) struct wrapf wrapf_mul(struct wrapf v, float k, struct wrapd w)
{
    struct wrapf r = { v.f * k * (float)w.d };
    return r;
}
__declspec(dllexport) int trio_sum(struct trio t, int k)
{
    return t.c[0] + t.c[1] + t.c[2] + k;
}
__declspec(dllexport) float fsum(float a, float b) { return a + b; }
__declspec(dllexport) unsigned char uc_add(unsigned char a, unsigned char b) { return a + b; }
__declspec(dllexport) short s_neg(short a) { return -a; }
__declspec(dllexport) void set_out(int *out, int v) { *out = v; }

/* a callback's caller (fficall's closures) */
__declspec(dllexport) int call_cb(int (*cb)(int, int), int a, int b)
{
    return cb(a, b);
}
