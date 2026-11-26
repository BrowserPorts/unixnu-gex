/* gexcc-win's libffi: ffi_call with mixed integer, floating, pointer and
 * struct-by-value arguments and results, to native function values (a DLL's
 * imports, the program's own variadic one: gex.ffi_thunk's thunks) and to
 * guest ones (GetProcAddress: __gexw_guest_call64); closures called
 * directly, through ffi_call and from a DLL, freed and made again */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <ffi.h>

struct pt { int x, y; };
struct big { double a, b, c; };
struct wrapd { double d; };
struct trio { char c[3]; };
struct wrapf { float f; };
__declspec(dllimport) double mix(int8_t, uint16_t, int, int64_t, float, double, const int *);
__declspec(dllimport) struct pt pt_add(struct pt, struct pt);
__declspec(dllimport) struct big big_scale(struct big, double);
__declspec(dllimport) struct wrapd wrap_half(struct wrapd);
__declspec(dllimport) int trio_sum(struct trio, int);
__declspec(dllimport) struct wrapf wrapf_mul(struct wrapf, float, struct wrapd);
__declspec(dllimport) float fsum(float, float);
__declspec(dllimport) unsigned char uc_add(unsigned char, unsigned char);
__declspec(dllimport) short s_neg(short);
__declspec(dllimport) void set_out(int *, int);
__declspec(dllimport) int call_cb(int (*)(int, int), int, int);
unsigned long long __gexw_ffi_icall_limit(void);

/* the program's own: variable ints and doubles */
static double vsum(int n, ...)
{
    va_list ap;
    double s = 0;
    va_start(ap, n);
    for (int i = 0; i < n; i++) s += (i & 1) ? va_arg(ap, double) : va_arg(ap, int);
    va_end(ap);
    return s;
}

static int fails;

/* the closures' functions */
static void cl_mix(ffi_cif *cif, void *ret, void **a, void *data)
{
    struct pt *p = a[3];
    struct big *b = a[4];
    (void)cif;
    *(double *)ret = *(int *)data + *(int8_t *)a[0] + *(float *)a[1] + *(double *)a[2] + p->x + p->y * 10
                     + b->a + b->b + b->c + (double)*(int64_t *)a[5] + *(uint16_t *)a[6];
}

static void cl_pt(ffi_cif *cif, void *ret, void **a, void *data)
{
    struct pt *p = a[0], r = { p->x + *(int *)a[1] + *(int *)data, p->y + *(int *)a[1] + *(int *)data };
    (void)cif;
    memcpy(ret, &r, sizeof(r));
}

static void cl_big(ffi_cif *cif, void *ret, void **a, void *data)
{
    struct big *b = a[0], r;
    double k = *(double *)a[1];
    (void)cif; (void)data;
    r.a = b->a * k; r.b = b->b * k; r.c = b->c * k;
    memcpy(ret, &r, sizeof(r));
}

static void cl_fsum(ffi_cif *cif, void *ret, void **a, void *data)
{
    (void)cif; (void)data;
    *(float *)ret = *(float *)a[0] + *(float *)a[1];
}

/* vsum's: (int n, ...) of alternating ints and doubles */
static void cl_vsum(ffi_cif *cif, void *ret, void **a, void *data)
{
    double s = 0;
    (void)data;
    for (unsigned i = 1; i < cif->nargs; i++) s += (i & 1) ? *(int *)a[i] : *(double *)a[i];
    *(double *)ret = s;
}

/* (int, int) -> int + *data, for a DLL to call back */
static void cl_add(ffi_cif *cif, void *ret, void **a, void *data)
{
    (void)cif;
    *(ffi_arg *)ret = (ffi_arg)(int64_t)(*(int *)a[0] + *(int *)a[1] + *(int *)data);
}

static ffi_closure *cb_closure;
static ffi_cif cb_cif;
static ffi_type *cb_at[] = { &ffi_type_sint32, &ffi_type_sint32 };
static void *cb_code(int *data)
{
    void *code = NULL;
    cb_closure = ffi_closure_alloc(sizeof(ffi_closure), &code);
    if (ffi_prep_cif(&cb_cif, FFI_DEFAULT_ABI, 2, &ffi_type_sint32, cb_at) != FFI_OK
        || ffi_prep_closure_loc(cb_closure, &cb_cif, cl_add, data, code) != FFI_OK) return NULL;
    return code;
}
#define CHECK(what, cond) do { if (!(cond)) { printf("fficall: FAIL %s %s\n", tag, what); fails++; } } while (0)

static ffi_type *pt_el[] = { &ffi_type_sint32, &ffi_type_sint32, NULL };
static ffi_type pt_t = { 0, 0, FFI_TYPE_STRUCT, pt_el };
static ffi_type *big_el[] = { &ffi_type_double, &ffi_type_double, &ffi_type_double, NULL };
static ffi_type big_t = { 0, 0, FFI_TYPE_STRUCT, big_el };
static ffi_type *wrapd_el[] = { &ffi_type_double, NULL };
static ffi_type wrapd_t = { 0, 0, FFI_TYPE_STRUCT, wrapd_el };
static ffi_type *wrapf_el[] = { &ffi_type_float, NULL };
static ffi_type wrapf_t = { 0, 0, FFI_TYPE_STRUCT, wrapf_el };
static ffi_type *trio_el[] = { &ffi_type_sint8, &ffi_type_sint8, &ffi_type_sint8, NULL };
static ffi_type trio_t = { 0, 0, FFI_TYPE_STRUCT, trio_el };

struct fns { void *mix, *pt_add, *big_scale, *wrap_half, *trio_sum, *fsum, *uc_add, *s_neg, *set_out, *wrapf_mul; };

static void run(const char *tag, const struct fns *f)
{
    ffi_cif cif;
    {
        ffi_type *at[] = { &ffi_type_sint8, &ffi_type_uint16, &ffi_type_sint32, &ffi_type_sint64, &ffi_type_float, &ffi_type_double, &ffi_type_pointer };
        int8_t a = -3; uint16_t b = 60000; int c = -100000; int64_t d = 1LL << 40; float e = 0.5f; double g = 0.25; int k = 7;
        const int *p = &k;
        void *av[] = { &a, &b, &c, &d, &e, &g, &p };
        double r = 0;
        CHECK("mix prep", ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 7, &ffi_type_double, at) == FFI_OK);
        ffi_call(&cif, FFI_FN(f->mix), &r, av);
        CHECK("mix", r == -3 + 60000 - 100000 + 1099511627776.0 + 0.75 + 7);
        ffi_call(&cif, FFI_FN(f->mix), &r, av); /* (the cif's thunk, again) */
        CHECK("mix again", r == -3 + 60000 - 100000 + 1099511627776.0 + 0.75 + 7);
    }
    {
        ffi_type *at[] = { &pt_t, &pt_t };
        struct pt a = { 1, 2 }, b = { 30, 40 }, r = { 0, 0 };
        void *av[] = { &a, &b };
        CHECK("pt prep", ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &pt_t, at) == FFI_OK);
        ffi_call(&cif, FFI_FN(f->pt_add), &r, av);
        CHECK("pt_add", r.x == 31 && r.y == 42 && a.x == 1);
    }
    {
        ffi_type *at[] = { &big_t, &ffi_type_double };
        struct big v = { 1, 2, 3 }, r = { 0, 0, 0 };
        double k = 1.5;
        void *av[] = { &v, &k };
        CHECK("big prep", ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &big_t, at) == FFI_OK && big_t.size == 24);
        ffi_call(&cif, FFI_FN(f->big_scale), &r, av);
        CHECK("big_scale", r.a == 1.5 && r.b == 3 && r.c == 4.5 && v.c == 3);
    }
    /* (a struct of one double: an f64 on wasm, an 8-byte struct in RAX and
     * in an integer slot on Win64, as GexIcall's adapter takes it) */
    {
        ffi_type *at[] = { &wrapd_t };
        struct wrapd v = { 5 }, r = { 0 };
        void *av[] = { &v };
        CHECK("wrapd prep", ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 1, &wrapd_t, at) == FFI_OK);
        ffi_call(&cif, FFI_FN(f->wrap_half), &r, av);
        CHECK("wrap_half", r.d == 2.5);
    }
    {
        /* one float's struct as argument and result, one double's beside it */
        ffi_type *at[] = { &wrapf_t, &ffi_type_float, &wrapd_t };
        struct wrapf v = { 1.5f }, r = { 0 };
        float k = 2;
        struct wrapd w = { 4 };
        void *av[] = { &v, &k, &w };
        CHECK("wrapf prep", ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 3, &wrapf_t, at) == FFI_OK);
        ffi_call(&cif, FFI_FN(f->wrapf_mul), &r, av);
        CHECK("wrapf_mul", r.f == 12);
    }
    {
        ffi_type *at[] = { &trio_t, &ffi_type_sint32 };
        struct trio t = { { 1, 2, 3 } };
        int k = 100;
        ffi_arg r = 0;
        void *av[] = { &t, &k };
        CHECK("trio prep", ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_sint32, at) == FFI_OK && trio_t.size == 3);
        ffi_call(&cif, FFI_FN(f->trio_sum), &r, av);
        CHECK("trio_sum", (int)r == 106);
    }
    {
        ffi_type *at[] = { &ffi_type_float, &ffi_type_float };
        float a = 1.25f, b = 2.5f, r = 0;
        void *av[] = { &a, &b };
        ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_float, at);
        ffi_call(&cif, FFI_FN(f->fsum), &r, av);
        CHECK("fsum", r == 3.75f);
    }
    {
        ffi_type *at[] = { &ffi_type_uint8, &ffi_type_uint8 };
        unsigned char a = 200, b = 100;
        ffi_arg r = 12345;
        void *av[] = { &a, &b };
        ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_uint8, at);
        ffi_call(&cif, FFI_FN(f->uc_add), &r, av);
        CHECK("uc_add", r == 44);
    }
    {
        ffi_type *at[] = { &ffi_type_sint16 };
        short a = 5;
        ffi_arg r = 0;
        void *av[] = { &a };
        ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 1, &ffi_type_sint16, at);
        ffi_call(&cif, FFI_FN(f->s_neg), &r, av);
        CHECK("s_neg", (ffi_sarg)r == -5);
    }
    {
        ffi_type *at[] = { &ffi_type_pointer, &ffi_type_sint32 };
        int out = 0, v = 99;
        int *po = &out;
        void *av[] = { &po, &v };
        ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_void, at);
        ffi_call(&cif, FFI_FN(f->set_out), NULL, av);
        CHECK("set_out", out == 99);
    }
}

int main(void)
{
    const char *tag = "main";
    unsigned long long lim = __gexw_ffi_icall_limit();
    struct fns native = { (void *)mix, (void *)pt_add, (void *)big_scale, (void *)wrap_half, (void *)trio_sum,
                          (void *)fsum, (void *)uc_add, (void *)s_neg, (void *)set_out, (void *)wrapf_mul };
    HMODULE h = GetModuleHandleA("ffidll.dll");
    struct fns guest = { 0 };
    void **g = (void **)&guest;
    static const char *names[] = { "mix", "pt_add", "big_scale", "wrap_half", "trio_sum", "fsum", "uc_add", "s_neg", "set_out", "wrapf_mul" };
    for (int i = 0; i < 10; i++) g[i] = (void *)GetProcAddress(h, names[i]);
    CHECK("native values", (uintptr_t)native.mix < lim && (uintptr_t)vsum < lim);
    CHECK("guest values", guest.mix && (uintptr_t)guest.mix >= lim);
    run("native", &native);
    run("guest", &guest);
    {
        /* a variadic native call: (int n, ...) with ints and doubles */
        ffi_cif cif;
        ffi_type *at[] = { &ffi_type_sint32, &ffi_type_sint32, &ffi_type_double, &ffi_type_sint32, &ffi_type_double };
        int n = 4, a = 10, c = -3;
        double b = 0.5, d = 0.25, r = 0;
        void *av[] = { &n, &a, &b, &c, &d };
        tag = "var";
        CHECK("prep", ffi_prep_cif_var(&cif, FFI_DEFAULT_ABI, 1, 5, &ffi_type_double, at) == FFI_OK);
        ffi_call(&cif, FFI_FN(vsum), &r, av);
        CHECK("vsum", r == 7.75);
    }
    {
        /* closures: mixed arguments and a double result; a struct results
         * in RAX, by sret and in XMM0 */
        ffi_cif c1, c2, c3, c4;
        ffi_type *a1[] = { &ffi_type_sint8, &ffi_type_float, &ffi_type_double, &pt_t, &big_t, &ffi_type_sint64, &ffi_type_uint16 };
        ffi_type *a2[] = { &pt_t, &ffi_type_sint32 };
        ffi_type *a3[] = { &big_t, &ffi_type_double };
        ffi_type *a4[] = { &ffi_type_float, &ffi_type_float };
        void *k1, *k2, *k3, *k4;
        ffi_closure *l1 = ffi_closure_alloc(sizeof(ffi_closure), &k1), *l2 = ffi_closure_alloc(sizeof(ffi_closure), &k2);
        ffi_closure *l3 = ffi_closure_alloc(sizeof(ffi_closure), &k3), *l4 = ffi_closure_alloc(sizeof(ffi_closure), &k4);
        int base = 1000;
        tag = "closure";
        CHECK("prep", ffi_prep_cif(&c1, FFI_DEFAULT_ABI, 7, &ffi_type_double, a1) == FFI_OK
              && ffi_prep_cif(&c2, FFI_DEFAULT_ABI, 2, &pt_t, a2) == FFI_OK
              && ffi_prep_cif(&c3, FFI_DEFAULT_ABI, 2, &big_t, a3) == FFI_OK
              && ffi_prep_cif(&c4, FFI_DEFAULT_ABI, 2, &ffi_type_float, a4) == FFI_OK);
        CHECK("bind", ffi_prep_closure_loc(l1, &c1, cl_mix, &base, k1) == FFI_OK
              && ffi_prep_closure_loc(l2, &c2, cl_pt, &base, k2) == FFI_OK
              && ffi_prep_closure_loc(l3, &c3, cl_big, NULL, k3) == FFI_OK
              && ffi_prep_closure_loc(l4, &c4, cl_fsum, NULL, k4) == FFI_OK);
        CHECK("guest value", (uintptr_t)k1 >= lim);
        {
            struct pt p = { 3, 4 }, q;
            struct big b = { 1, 2, 3 }, rb;
            double r = ((double (*)(int8_t, float, double, struct pt, struct big, int64_t, uint16_t))k1)(-2, 1.5f, 0.25, p, b, 1LL << 40, 65535);
            CHECK("direct mix", r == 1000 - 2 + 1.5 + 0.25 + 3 + 40 + 6 + 1099511627776.0 + 65535);
            q = ((struct pt (*)(struct pt, int))k2)(p, 10);
            CHECK("direct pt", q.x == 1013 && q.y == 1014);
            rb = ((struct big (*)(struct big, double))k3)(b, 2);
            CHECK("direct big", rb.a == 2 && rb.b == 4 && rb.c == 6);
            CHECK("direct float", ((float (*)(float, float))k4)(1.25f, 2.5f) == 3.75f);
        }
        {
            /* through ffi_call (a guest value: call_guest) */
            struct pt p = { 5, 6 }, q = { 0, 0 };
            int m = 1;
            void *av[] = { &p, &m };
            ffi_call(&c2, FFI_FN(k2), &q, av);
            CHECK("ffi_call pt", q.x == 1006 && q.y == 1007);
        }
        /* from a DLL: a callback it calls */
        CHECK("from dll", call_cb((int (*)(int, int))cb_code(&base), 7, 8) == 1015);
        {
            /* a variadic closure, (int n, ...) of ints and doubles, through
             * ffi_call (Win64 has each variable double in both registers) */
            ffi_cif cv;
            ffi_type *av_t[] = { &ffi_type_sint32, &ffi_type_sint32, &ffi_type_double, &ffi_type_sint32, &ffi_type_double };
            void *kv;
            ffi_closure *lv = ffi_closure_alloc(sizeof(ffi_closure), &kv);
            int n = 4, a = 10, c = -3;
            double b = 0.5, d = 0.25, r = 0;
            void *av[] = { &n, &a, &b, &c, &d };
            CHECK("var prep", ffi_prep_cif_var(&cv, FFI_DEFAULT_ABI, 1, 5, &ffi_type_double, av_t) == FFI_OK
                  && ffi_prep_closure_loc(lv, &cv, cl_vsum, NULL, kv) == FFI_OK);
            ffi_call(&cv, FFI_FN(kv), &r, av);
            CHECK("var closure", r == 7.75);
            ffi_closure_free(lv);
        }
        ffi_closure_free(l1);
        ffi_closure_free(l2);
        {
            /* freed and made again (often at the same address): the new data */
            void *k;
            ffi_closure *l = ffi_closure_alloc(sizeof(ffi_closure), &k);
            int other = -50;
            /* (from the pool, still bound) */
            CHECK("pooled", l == l2 || l == l1);
            CHECK("rebind", ffi_prep_closure_loc(l, &c2, cl_pt, &other, k) == FFI_OK);
            if (l)
            {
                struct pt p = { 1, 1 }, q = ((struct pt (*)(struct pt, int))k)(p, 0);
                CHECK("rebound pt", q.x == -49 && q.y == -49);
            }
            ffi_closure_free(l);
        }
        CHECK("bad codeloc", ffi_prep_closure_loc(l3, &c3, cl_big, NULL, (char *)k3 + 16) == FFI_BAD_ABI);
        ffi_closure_free(l3);
        ffi_closure_free(l4);
        ffi_closure_free(cb_closure);
    }
    printf("fficall: %s %d\n", fails ? "failed" : "ok", fails);
    return fails != 0;
}
