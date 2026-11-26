// vtdecl: this object emits VtBase's vtable (its key function, ~VtBase, is
// defined here) while VtEvent is incomplete, so clang declares VtBase::make,
// which the vtable takes the address of, with a placeholder `void ()` type.
// The same for vt_make2, whose address main passes. No entry thunk may be
// made from either declaration: it would call the function through the
// wrong type. The addresses come from vtdecl2.cpp's definitions.
#include <stdio.h>
#include "vtdecl.h"
VtBase::~VtBase() {}
int main() {
  VtBase b;
  int r = vt_use(&b, 5), r2 = vt_call(vt_make2, 4);
  int ok = r == 5 + 6 + 7 + 3 * 7 && r2 == 4 + 5 + 6;
  printf("vtdecl: %s %d %d\n", ok ? "ok" : "FAIL", r, r2);
  return ok ? 0 : 1;
}
