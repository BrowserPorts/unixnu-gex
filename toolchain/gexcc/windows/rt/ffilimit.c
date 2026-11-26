/* gexcc-win's libffi (ffi.c): this thread's ICALL bound, gex.icall_limit64,
 * as the GexIcall pass reads it. A function value below it is a function-
 * table index (native code); anything else is a guest address. Its own
 * file: this one makes no indirect call, so the pass declares no global of
 * that name here beside this one. */
__asm__(".globaltype __gexw_icall_limit_g, i64\n"
        ".import_module __gexw_icall_limit_g, gex\n"
        ".import_name __gexw_icall_limit_g, icall_limit64\n");

unsigned long long __gexw_ffi_icall_limit(void)
{
    unsigned long long v;
    __asm__ volatile("global.get __gexw_icall_limit_g\n\tlocal.set %0" : "=r"(v));
    return v;
}
