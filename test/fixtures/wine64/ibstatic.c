/* A function's static const holding &__ImageBase: an object whose own
 * address escapes (returned, compared across calls), so no per-use copy can
 * stand for it, and the image base is known only once the module is mapped.
 * GexIcall refuses it at compile time, naming the file (never a wrong or a
 * dead address). */
#include <windows.h>

extern IMAGE_DOS_HEADER __ImageBase;

struct held { const void *self; };

/* (kept: the optimiser can fold neither the object nor its address away) */
static const struct held *volatile keep;

static __attribute__((noinline)) const struct held *get(void)
{
    static const struct held x = { &__ImageBase };
    return &x;
}

int main(void)
{
    keep = get();
    return keep == get() && keep->self == GetModuleHandleW(NULL) ? 0 : 1;
}
