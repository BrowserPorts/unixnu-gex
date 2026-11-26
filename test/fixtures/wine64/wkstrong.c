/* and strongly here: nothing defines it, so this link must fail (or, with
 * GEXCC_WIN_UNDEFINED=stub, bind it to a stub), whatever another module's
 * weak reference says */
extern void wkx(void);
__declspec(dllexport) void wkstrong_call(void) { wkx(); }
