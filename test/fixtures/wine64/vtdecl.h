// vtdecl: a class whose vtable is emitted where a virtual's return type is
// incomplete (vtdecl.cpp), and a function of that result whose address is
// passed there; their definitions in another object (vtdecl2.cpp).
struct VtEvent;
struct VtBase {
  virtual ~VtBase();
  virtual VtEvent make(int v);
  int seed = 7;
};
int vt_use(VtBase *b, int v);
// a function returning the incomplete type, its address passed as an argument
typedef VtEvent (*VtMakeFn)(int);
VtEvent vt_make2(int v);
int vt_call(VtMakeFn f, int v);
