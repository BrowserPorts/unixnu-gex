/* `&__ImageBase`, the image's own base as MSVC's and MinGW's linkers define
 * it, is the program's module handle; so is it through an offset into the
 * headers (a constant expression), when chosen in a branch (a phi), and
 * inside a function's const aggregate (clang's private constant global). */
#include <windows.h>
#include <stdio.h>

extern IMAGE_DOS_HEADER __ImageBase;

static __attribute__((noinline)) const void *pick(int k)
{
    return k ? (const void *)&__ImageBase : (const void *)GetModuleHandleW(NULL);
}

struct held { int n; const void *self; const void *parts[2]; };

static __attribute__((noinline)) int held_ok(const struct held *h, HMODULE self)
{
    return h->n == 7 && h->self == self && !h->parts[0] && h->parts[1] == (const char *)self + 0x3c;
}

int main(int argc, char **argv)
{
    HMODULE self = GetModuleHandleW(NULL);
    int base = (HMODULE)&__ImageBase == self;
    int lfanew = (const char *)&__ImageBase.e_lfanew - (const char *)self == 0x3c;
    int phi = pick(argc > 0) == (const void *)self;
    int mz = __ImageBase.e_magic == IMAGE_DOS_SIGNATURE;
    const struct held h = { 7, &__ImageBase, { NULL, &__ImageBase.e_lfanew } };
    int agg = held_ok(&h, self);
    printf("imagebase: base %d lfanew %d phi %d mz %d agg %d\n", base, lfanew, phi, mz, agg);
    if (base && lfanew && phi && mz && agg) printf("imagebase ok\n");
    return 0;
}
