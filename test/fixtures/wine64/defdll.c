/* A DLL whose .def (defdll.def) names an export twice, exports its data
 * without DATA, and has an export named `name` (an export, not the keyword);
 * and dllexports a function and an int the .def leaves out, exported too, as
 * link.exe and GNU ld export them (nss3's .def leaves NSPR's out) */
int defdll_val = 42;
int defdll_val2 = 7;
int defdll_get(void) { return defdll_val; }
__declspec(dllexport) int defdll_extra_val = 5;
__declspec(dllexport) int defdll_extra(void) { return defdll_extra_val + 1; }
