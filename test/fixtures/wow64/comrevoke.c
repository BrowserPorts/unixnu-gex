/* comrevoke: in a session booted without wineboot (WINEGEX_NO_WINEBOOT=1)
 * whose services.exe never serves, a class object registered for other
 * processes (CLSCTX_LOCAL_SERVER) has no rpcss to hold it: the register
 * waits on the service manager and fails inside, though it says S_OK. Its
 * revoke then has nothing in an rpcss to change and is quick. Says
 * "comrevoke register HR" and "comrevoke revoke HR MS" (the revoke's time). */
#include <windows.h>
#include <objbase.h>
#include <stdio.h>

static HRESULT WINAPI cf_qi(IClassFactory *cf, REFIID iid, void **out)
{
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IClassFactory)) { *out = cf; return S_OK; }
    *out = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI cf_addref(IClassFactory *cf) { return 2; }
static ULONG WINAPI cf_release(IClassFactory *cf) { return 1; }
static HRESULT WINAPI cf_create(IClassFactory *cf, IUnknown *outer, REFIID iid, void **out) { *out = NULL; return E_NOTIMPL; }
static HRESULT WINAPI cf_lock(IClassFactory *cf, BOOL lock) { return S_OK; }
static IClassFactoryVtbl cf_vtbl = { cf_qi, cf_addref, cf_release, cf_create, cf_lock };
static IClassFactory cf = { &cf_vtbl };
static const CLSID clsid = { 0x6d1a4c27, 0x5b0e, 0x4f3a, { 0x9e, 0x21, 0x7c, 0x44, 0x0b, 0x8d, 0x31, 0x5f } };

int main(void)
{
    DWORD cookie = 0, t;
    HRESULT hr;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    hr = CoRegisterClassObject(&clsid, (IUnknown *)&cf, CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE, &cookie);
    printf("comrevoke register %08lx\n", hr);
    fflush(stdout);
    t = GetTickCount();
    hr = CoRevokeClassObject(cookie);
    printf("comrevoke revoke %08lx %lu\n", hr, GetTickCount() - t);
    fflush(stdout);
    CoUninitialize();
    return 0;
}
