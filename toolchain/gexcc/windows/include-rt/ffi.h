/* gexcc-win's libffi (rt/ffi.c, lib/gexcc-win/libffi.a): libffi 3's API
 * for native wasm64 modules under gex.
 *
 * ffi_call reaches two kinds of function value. A native one (a function-
 * table index, below gex.icall_limit64) is called through a thunk gex makes
 * once per wasm signature (gex.ffi_thunk), since call_indirect needs the
 * callee's exact type. A guest one (an x86-64 address: what GetProcAddress
 * gives, a Wine export's skeleton) is called as Win64 calls it, through
 * gexrt's __gexw_guest_call64.
 *
 * A closure's function value is the closure's own address (the code
 * ffi_closure_alloc gives), a guest address gex binds to libffi's closure
 * entry; ffi_prep_closure_loc takes no other codeloc (FFI_BAD_ABI). */
#ifndef GEXW_FFI_H
#define GEXW_FFI_H

#include <stddef.h>
#include <ffitarget.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FFI_TYPE_VOID       0
#define FFI_TYPE_INT        1
#define FFI_TYPE_FLOAT      2
#define FFI_TYPE_DOUBLE     3
/* (long double is double here: -mlong-double-64) */
#define FFI_TYPE_LONGDOUBLE FFI_TYPE_DOUBLE
#define FFI_TYPE_UINT8      5
#define FFI_TYPE_SINT8      6
#define FFI_TYPE_UINT16     7
#define FFI_TYPE_SINT16     8
#define FFI_TYPE_UINT32     9
#define FFI_TYPE_SINT32     10
#define FFI_TYPE_UINT64     11
#define FFI_TYPE_SINT64     12
#define FFI_TYPE_STRUCT     13
#define FFI_TYPE_POINTER    14
#define FFI_TYPE_COMPLEX    15
#define FFI_TYPE_LAST       FFI_TYPE_COMPLEX

#define FFI_SIZEOF_ARG 8

typedef struct _ffi_type
{
    size_t size;
    unsigned short alignment;
    unsigned short type;
    struct _ffi_type **elements;
} ffi_type;

extern ffi_type ffi_type_void, ffi_type_uint8, ffi_type_sint8, ffi_type_uint16, ffi_type_sint16,
    ffi_type_uint32, ffi_type_sint32, ffi_type_uint64, ffi_type_sint64, ffi_type_float, ffi_type_double,
    ffi_type_longdouble, ffi_type_pointer;

#define ffi_type_uchar  ffi_type_uint8
#define ffi_type_schar  ffi_type_sint8
#define ffi_type_ushort ffi_type_uint16
#define ffi_type_sshort ffi_type_sint16
#define ffi_type_uint   ffi_type_uint32
#define ffi_type_sint   ffi_type_sint32
/* (long is 32-bit: LLP64) */
#define ffi_type_ulong  ffi_type_uint32
#define ffi_type_slong  ffi_type_sint32

typedef enum
{
    FFI_OK = 0,
    FFI_BAD_TYPEDEF,
    FFI_BAD_ABI,
    FFI_BAD_ARGTYPE
} ffi_status;

typedef struct
{
    ffi_abi abi;
    unsigned nargs;
    ffi_type **arg_types;
    ffi_type *rtype;
    unsigned bytes;
    unsigned flags;
    /* (gexcc-win's: the fixed arguments of a variadic call, else nargs;
     * the thunk for its wasm signature once made, gex.ffi_thunk's) */
    unsigned nfixed;
    unsigned long long thunk;
} ffi_cif;

ffi_status ffi_prep_cif(ffi_cif *cif, ffi_abi abi, unsigned int nargs, ffi_type *rtype, ffi_type **atypes);
ffi_status ffi_prep_cif_var(ffi_cif *cif, ffi_abi abi, unsigned int nfixedargs, unsigned int ntotalargs,
                            ffi_type *rtype, ffi_type **atypes);
void ffi_call(ffi_cif *cif, void (*fn)(void), void *rvalue, void **avalue);
ffi_status ffi_get_struct_offsets(ffi_abi abi, ffi_type *struct_type, size_t *offsets);

#define FFI_FN(f) ((void (*)(void))(f))

typedef struct
{
    char tramp[FFI_TRAMPOLINE_SIZE];
    ffi_cif *cif;
    void (*fun)(ffi_cif *, void *, void **, void *);
    void *user_data;
} ffi_closure;

void *ffi_closure_alloc(size_t size, void **code);
void ffi_closure_free(void *closure);
ffi_status ffi_prep_closure_loc(ffi_closure *closure, ffi_cif *cif,
                                void (*fun)(ffi_cif *, void *, void **, void *), void *user_data, void *codeloc);
ffi_status ffi_prep_closure(ffi_closure *closure, ffi_cif *cif,
                            void (*fun)(ffi_cif *, void *, void **, void *), void *user_data);

#ifdef __cplusplus
}
#endif

#endif
