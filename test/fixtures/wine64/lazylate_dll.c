/* lazylate.c's DLL, loaded after the program's threads started: an object
 * with a vtable (COM's shape), a comparator a start-time DLL (the CRT's
 * qsort) calls back, a thread procedure, and data holding a pointer to one
 * of its functions (a data relocation). */
#include <windows.h>

struct obj;
struct vtbl
{
    int (*add)(struct obj *, int);
    int (*get)(struct obj *);
    void (*release)(struct obj *);
};
struct obj { const struct vtbl *v; int n; };

static int obj_add(struct obj *o, int x) { return o->n += x; }
static int obj_get(struct obj *o) { return o->n; }
static void obj_release(struct obj *o) { HeapFree(GetProcessHeap(), 0, o); }
static const struct vtbl obj_vtbl = { obj_add, obj_get, obj_release };

struct obj *lazy_make(int n)
{
    struct obj *o = HeapAlloc(GetProcessHeap(), 0, sizeof(*o));
    o->v = &obj_vtbl;
    o->n = n;
    return o;
}

int lazy_cmp(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

DWORD WINAPI lazy_thread(void *arg) { return 1000 + (int)(INT_PTR)arg; }

static int triple(int x) { return 3 * x; }
int (*lazy_fnptr)(int) = triple;
