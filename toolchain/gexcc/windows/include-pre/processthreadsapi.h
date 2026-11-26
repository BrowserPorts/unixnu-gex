/* processthreadsapi.h for Windows programs (gexcc-win): Wine's declares only
 * part of the process and thread API the Windows SDK's does; the rest is in
 * its winbase.h, and the mitigation policy calls here */
#include_next <processthreadsapi.h>
#include <windef.h>
#include <winbase.h>
#ifndef GEXCC_WIN_PROCESSTHREADSAPI_H
#define GEXCC_WIN_PROCESSTHREADSAPI_H
#ifdef __cplusplus
extern "C" {
#endif
WINBASEAPI BOOL WINAPI GetProcessMitigationPolicy(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
WINBASEAPI BOOL WINAPI SetProcessMitigationPolicy(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
#ifdef __cplusplus
}
#endif
#endif
