/* tlsdll: a DLL with static (implicit) TLS data, as MSVC's __declspec(thread)
 * lays it out: the data in .tls, reached through gs:[0x58][_tls_index].
 * GCC's own __thread is emulated, so the access is written out here. */
#include <windows.h>

extern ULONG _tls_index;
extern char _tls_start;
__attribute__((section(".tls$WW"))) volatile LONG_PTR tls_slot = 0x5eed;

static volatile LONG_PTR *slot(void)
{
    char **vec = (char **)__readgsqword(0x58);
    return (volatile LONG_PTR *)(vec[_tls_index] + ((char *)&tls_slot - &_tls_start));
}

__declspec(dllexport) LONG_PTR tls_get(void) { return *slot(); }
__declspec(dllexport) void tls_set(LONG_PTR v) { *slot() = v; }
