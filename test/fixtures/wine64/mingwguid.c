/* mingw-w64's static GUID libraries (a mingw-headers gexcc-win install):
   IID_ILatLongReport from -llocationapi, KSDATAFORMAT_SUBTYPE_PCM from
   -lksuser (also ksuser.dll's import library) */
#include <windows.h>
#include <stdio.h>
#include <locationapi.h>
#include <mmreg.h>
#include <ks.h>
#include <ksmedia.h>

int main(void)
{
    const GUID *a = &IID_ILatLongReport, *b = &KSDATAFORMAT_SUBTYPE_PCM;
    int ok = a->Data1 == 0x7fed806d && a->Data2 == 0x0ef8 && a->Data4[7] == 0x34
             && b->Data1 == 1 && b->Data2 == 0 && b->Data4[7] == 0x71;
    printf("mingwguid: %s %08lx %08lx\n", ok ? "ok" : "bad", a->Data1, b->Data1);
    return 0;
}
