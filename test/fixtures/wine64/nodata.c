/* A DLL that reads data nothing defines: an undefined reference at the
   link, even with GEXCC_WIN_UNDEFINED=stub (data has no stub to bind) */
extern int nodata_missing;
__declspec(dllexport) int nodata_get(void) { return nodata_missing; }
