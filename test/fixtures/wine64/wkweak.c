/* wkfunc's DLLs: wkx referenced weakly here (null: nothing defines it) */
extern void wkx(void) __attribute__((weak));
__declspec(dllexport) int wkweak_has(void) { return wkx != 0; }
