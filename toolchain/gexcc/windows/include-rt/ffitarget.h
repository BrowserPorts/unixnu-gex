/* gexcc-win's libffi (rt/ffi.c): its target, Win64 code built as native
 * wasm64 modules. The ABI names are Windows x64 libffi's; every one means
 * the one convention a gexcc-win module has. */
#ifndef GEXW_FFITARGET_H
#define GEXW_FFITARGET_H

typedef unsigned long long ffi_arg;
typedef signed long long ffi_sarg;

typedef enum ffi_abi
{
    FFI_FIRST_ABI = 0,
    FFI_WIN64,
    FFI_GNUW64,
    FFI_SYSV,
    FFI_STDCALL,
    FFI_THISCALL,
    FFI_FASTCALL,
    FFI_MS_CDECL,
    FFI_LAST_ABI,
    FFI_DEFAULT_ABI = FFI_WIN64
} ffi_abi;

/* (rt/ffi.c: each closure's address bound to one entry) */
#define FFI_CLOSURES 1
#define FFI_GO_CLOSURES 0
#define FFI_TRAMPOLINE_SIZE 32
#define FFI_NATIVE_RAW_API 0

#endif
