/* Microsoft::WRL::Wrappers' HString and HStringReference (gexcc-win's
 * compatibility headers: Wine's include tree has no WRL) */
#pragma once
#include <windows.h>
#include <intsafe.h>
#include <winstring.h>
#include <roapi.h>
#include <cwchar>

namespace Microsoft { namespace WRL { namespace Wrappers {

class HStringReference
{
public:
    HStringReference(const wchar_t *str, unsigned int len) noexcept { Init(str, len); }
    template <unsigned int N> explicit HStringReference(const wchar_t (&str)[N]) noexcept { Init(str, N - 1); }
    HStringReference(const HStringReference &o) noexcept { unsigned int n = 0; const wchar_t *s = o.GetRawBuffer(&n); Init(s, n); }
    HStringReference &operator=(const HStringReference &o) noexcept { unsigned int n = 0; const wchar_t *s = o.GetRawBuffer(&n); Init(s, n); return *this; }
    HSTRING Get() const noexcept { return hstr; }
    const wchar_t *GetRawBuffer(unsigned int *len) const noexcept { return ::WindowsGetStringRawBuffer(hstr, len); }
    HRESULT CopyTo(HSTRING *out) const noexcept { return ::WindowsDuplicateString(hstr, out); }
private:
    void Init(const wchar_t *str, unsigned int len) noexcept
    {
        if (FAILED(::WindowsCreateStringReference(str, len, &header, &hstr))) hstr = nullptr;
    }
    HSTRING_HEADER header;
    HSTRING hstr = nullptr;
};

class HString
{
public:
    HString() noexcept : hstr(nullptr) {}
    HString(const HString &) = delete;
    HString &operator=(const HString &) = delete;
    HString(HString &&o) noexcept : hstr(o.hstr) { o.hstr = nullptr; }
    HString &operator=(HString &&o) noexcept { Release(); hstr = o.hstr; o.hstr = nullptr; return *this; }
    ~HString() { Release(); }
    HSTRING Get() const noexcept { return hstr; }
    HSTRING *GetAddressOf() noexcept { Release(); return &hstr; }
    HSTRING *ReleaseAndGetAddressOf() noexcept { Release(); return &hstr; }
    void Attach(HSTRING h) noexcept { Release(); hstr = h; }
    HSTRING Detach() noexcept { HSTRING h = hstr; hstr = nullptr; return h; }
    bool IsValid() const noexcept { return hstr != nullptr; }
    const wchar_t *GetRawBuffer(unsigned int *len) const noexcept { return ::WindowsGetStringRawBuffer(hstr, len); }
    HRESULT CopyTo(HSTRING *out) const noexcept { return ::WindowsDuplicateString(hstr, out); }
    HRESULT Set(const wchar_t *str, unsigned int len) noexcept { Release(); return ::WindowsCreateString(str, len, &hstr); }
    HRESULT Set(const wchar_t *str) noexcept { return Set(str, static_cast<unsigned int>(::wcslen(str))); }
    HRESULT Set(const HSTRING &h) noexcept { if (h == hstr) return S_OK; Release(); return ::WindowsDuplicateString(h, &hstr); }
    void Release() noexcept { if (hstr) { ::WindowsDeleteString(hstr); hstr = nullptr; } }
    static HStringReference MakeReference(const wchar_t *str, unsigned int len) noexcept { return HStringReference(str, len); }
private:
    HSTRING hstr;
};

} } } /* namespace Microsoft::WRL::Wrappers */
