// vtdecl: VtBase::make, defined where VtEvent is complete (a struct returned
// in memory), and a virtual call through the vtable vtdecl.cpp emits.
#include "vtdecl.h"
struct VtEvent { int a, b, c; };
VtEvent VtBase::make(int v) { return {v, v + 1, v + 2}; }
int vt_use(VtBase *b, int v) {
  VtEvent e = b->make(v);
  return e.a + e.b + e.c - 3 + 3 * b->seed + 3;
}
VtEvent vt_make2(int v) { return {v, v + 1, v + 2}; }
int vt_call(VtMakeFn f, int v) { VtEvent e = f(v); return e.a + e.b + e.c; }
