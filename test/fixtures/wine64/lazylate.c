/* A DLL loaded once the program's threads run (lazylate_dll.c), reached from
 * threads that were running before it was loaded and never called into it:
 * on the page such a thread's Worker installs the DLL only at its first call
 * into it (gex.mjs `#lateDefer`). Each case has the thread call the DLL a
 * different way: through an object's vtable made on another thread, through
 * a start-time DLL calling a comparator of the late DLL's (qsort), through
 * a function pointer read from the DLL's data, and as a new thread's start
 * routine, in a Worker a finished thread left parked. Then a Wine DLL's
 * delay import of another, loaded after the running threads first called
 * the importer: each thread installed combase without oleaut32, which the
 * program then loads, and combase's IErrorInfo::GetDescription calls
 * oleaut32's SysAllocString through the delay import's late-bound slot
 * (gex.mjs `#lateMiss`). */
#define COBJMACROS
#include <windows.h>
#include <oaidl.h>
#include <stdio.h>
#include <stdlib.h>

static int failures;
static void check(int ok, const char *what, int got)
{
    printf("%s %s (%d)\n", ok ? "ok" : "FAIL", what, got);
    if (!ok) failures++;
}

struct obj;
struct vtbl
{
    int (*add)(struct obj *, int);
    int (*get)(struct obj *);
    void (*release)(struct obj *);
};
struct obj { const struct vtbl *v; int n; };

static HANDLE go[3], done[3], go2[3], done2[3], go3[3], done3[3];
static DWORD (WINAPI *g_curproc)(void);
static HRESULT (WINAPI *g_create_ei)(ICreateErrorInfo **);
static int r_desc[3];
/* IID_IErrorInfo, without linking uuid */
static const IID iid_errorinfo = { 0x1cf2b120, 0x547d, 0x101b, { 0x8e, 0x65, 0x08, 0x00, 0x2b, 0x2b, 0xd1, 0x19 } };
static struct obj *g_obj;
static int (*g_cmp)(const void *, const void *);
static int (**g_fnptr)(int);
static int r_vtbl, r_sort, r_data;

static DWORD WINAPI worker(void *arg)
{
    int k = (int)(INT_PTR)arg;
    WaitForSingleObject(go[k], INFINITE);
    if (k == 0)
    {
        g_obj->v->add(g_obj, 5);
        r_vtbl = g_obj->v->get(g_obj);
        g_obj->v->release(g_obj);
    }
    else if (k == 1)
    {
        int a[] = { 5, 3, 9, 1, 7 };
        qsort(a, 5, sizeof(int), g_cmp);
        r_sort = a[0] * 10000 + a[1] * 1000 + a[2] * 100 + a[3] * 10 + a[4];
    }
    else r_data = (*g_fnptr)(14);
    SetEvent(done[k]);
    /* combase installed here first, oleaut32 not yet loaded */
    WaitForSingleObject(go2[k], INFINITE);
    g_curproc();
    SetEvent(done2[k]);
    /* oleaut32 loaded since: its SysAllocString through combase's delay import */
    WaitForSingleObject(go3[k], INFINITE);
    {
        ICreateErrorInfo *cei = NULL;
        IErrorInfo *ei = NULL;
        BSTR d = NULL;
        if (SUCCEEDED(g_create_ei(&cei)) && SUCCEEDED(ICreateErrorInfo_SetDescription(cei, (LPOLESTR)L"late")) &&
            SUCCEEDED(ICreateErrorInfo_QueryInterface(cei, &iid_errorinfo, (void **)&ei)) &&
            SUCCEEDED(IErrorInfo_GetDescription(ei, &d)) && d && !lstrcmpW(d, L"late"))
            r_desc[k] = 1;
        if (ei) IErrorInfo_Release(ei);
        if (cei) ICreateErrorInfo_Release(cei);
    }
    SetEvent(done3[k]);
    return 0;
}

static DWORD WINAPI quick(void *arg) { return 7; }

int main(void)
{
    HANDLE th[3], t;
    HMODULE m;
    DWORD code = 0;
    struct obj *(*make)(int);
    LPTHREAD_START_ROUTINE proc;

    for (int k = 0; k < 3; k++)
    {
        go[k] = CreateEventA(NULL, TRUE, FALSE, NULL);
        done[k] = CreateEventA(NULL, TRUE, FALSE, NULL);
        go2[k] = CreateEventA(NULL, TRUE, FALSE, NULL);
        done2[k] = CreateEventA(NULL, TRUE, FALSE, NULL);
        go3[k] = CreateEventA(NULL, TRUE, FALSE, NULL);
        done3[k] = CreateEventA(NULL, TRUE, FALSE, NULL);
        th[k] = CreateThread(NULL, 0, worker, (void *)(INT_PTR)k, 0, NULL);
    }
    /* a thread that ends before the load: its Worker may be parked and given
     * the start routine's thread below */
    t = CreateThread(NULL, 0, quick, NULL, 0, NULL);
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
    Sleep(200);

    if (!(m = LoadLibraryA("lazylate_dll.dll")))
    {
        printf("FAIL LoadLibrary lazylate_dll.dll: %lu\n1 failures\n", GetLastError());
        return 1;
    }
    make = (void *)GetProcAddress(m, "lazy_make");
    g_cmp = (void *)GetProcAddress(m, "lazy_cmp");
    proc = (void *)GetProcAddress(m, "lazy_thread");
    g_fnptr = (void *)GetProcAddress(m, "lazy_fnptr");
    if (!make || !g_cmp || !proc || !g_fnptr)
    {
        printf("FAIL GetProcAddress\n1 failures\n");
        return 1;
    }
    g_obj = make(37);
    for (int k = 0; k < 3; k++)
    {
        SetEvent(go[k]);
        if (WaitForSingleObject(done[k], 20000)) check(0, "a running thread's first call into the late DLL returned", k);
    }
    check(r_vtbl == 42, "a vtable the late DLL made, called from a thread running before the load", r_vtbl);
    check(r_sort == 13579, "the CRT's qsort calling the late DLL's comparator on such a thread", r_sort);
    check(r_data == 42, "a pointer to the late DLL's function in its data, called on such a thread", r_data);

    t = CreateThread(NULL, 0, proc, (void *)(INT_PTR)42, 0, NULL);
    if (WaitForSingleObject(t, 20000)) check(0, "a thread starting in the late DLL ended", -1);
    else
    {
        GetExitCodeThread(t, &code);
        check(code == 1042, "a thread whose start routine is the late DLL's", (int)code);
    }

    /* a Wine DLL with a delay import (combase's of oleaut32), loaded while the
     * threads run, called by each first; then the DLL it delay-imports */
    if (GetModuleHandleA("oleaut32.dll")) check(0, "oleaut32 not loaded before the case", 0);
    if (!(m = LoadLibraryA("combase.dll")) || !(g_curproc = (void *)GetProcAddress(m, "CoGetCurrentProcess")) ||
        !(g_create_ei = (void *)GetProcAddress(m, "CreateErrorInfo")))
    {
        printf("FAIL LoadLibrary combase.dll: %lu\n1 failures\n", GetLastError());
        return 1;
    }
    for (int k = 0; k < 3; k++)
    {
        SetEvent(go2[k]);
        if (WaitForSingleObject(done2[k], 20000)) check(0, "a running thread's first call into combase returned", k);
    }
    if (!LoadLibraryA("oleaut32.dll")) check(0, "LoadLibrary oleaut32.dll", (int)GetLastError());
    for (int k = 0; k < 3; k++)
    {
        SetEvent(go3[k]);
        if (WaitForSingleObject(done3[k], 20000)) check(0, "a call through combase's delay import of oleaut32 returned", k);
    }
    for (int k = 0; k < 3; k++)
        check(r_desc[k] == 1, "combase's delay import of oleaut32, loaded after the thread installed combase, called on it", r_desc[k]);
    for (int k = 0; k < 3; k++) WaitForSingleObject(th[k], 20000);
    printf("%d failures\n", failures);
    fflush(stdout);
    return failures != 0;
}
