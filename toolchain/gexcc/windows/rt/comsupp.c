/* The COM support library's functions comutil.h's _bstr_t and _variant_t call
 * (comsuppw.lib's part), named as C++ names them. */
#include <stdlib.h>
#include <windows.h>
#include <oleauto.h>

void WINAPI com_issue_error(HRESULT hr) __asm__("_Z16_com_issue_errorl");
BSTR WINAPI com_string_to_bstr(const char *s) __asm__("_ZN9_com_util19ConvertStringToBSTREPKc");
char *WINAPI com_bstr_to_string(BSTR s) __asm__("_ZN9_com_util19ConvertBSTRToStringEPw");

void WINAPI com_issue_error(HRESULT hr)
{
    RaiseException(hr, EXCEPTION_NONCONTINUABLE, 0, NULL);
    abort();
}

BSTR WINAPI com_string_to_bstr(const char *s)
{
    BSTR r;
    int n;
    if (!s) return NULL;
    n = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    if (n <= 0 || !(r = SysAllocStringLen(NULL, n - 1))) return NULL;
    MultiByteToWideChar(CP_ACP, 0, s, -1, r, n);
    return r;
}

/* freed with delete[], which is free() */
char *WINAPI com_bstr_to_string(BSTR s)
{
    char *r;
    int n;
    if (!s) return NULL;
    n = WideCharToMultiByte(CP_ACP, 0, s, SysStringLen(s), NULL, 0, NULL, NULL);
    if (n < 0 || !(r = malloc(n + 1))) return NULL;
    WideCharToMultiByte(CP_ACP, 0, s, SysStringLen(s), r, n, NULL, NULL);
    r[n] = 0;
    return r;
}
