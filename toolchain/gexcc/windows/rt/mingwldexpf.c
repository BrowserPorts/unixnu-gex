/* ldexpf, an inline in the Windows SDK's math.h that ucrtbase does not
 * export, for a mingw-headers install (install.sh). Its own object, so a
 * program with its own ldexpf does not pull it in with __mingw_printf. */
#include <math.h>

#undef ldexpf
float __cdecl ldexpf(float x, int e) { return (float)ldexp((double)x, e); }
