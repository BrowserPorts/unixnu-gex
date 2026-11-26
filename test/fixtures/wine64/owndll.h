/* What owndll.c (a gexcc-win DLL with no .def: its default-visibility
 * symbols are its exports) gives ownmain.c, which links its import
 * library: functions, variadic ones, a struct by value, and data both
 * sides write. */
#define OWN_API __attribute__((visibility("default")))

struct own_pt { int x, y; };

extern OWN_API int own_count;
extern OWN_API struct own_pt own_pt;
OWN_API int own_add(int a, int b);
OWN_API int own_pt_sum(struct own_pt p);
OWN_API int *own_count_addr(void);
OWN_API struct own_pt *own_pt_addr(void);
OWN_API void own_bump(void);
OWN_API int own_vsum(int n, ...);
OWN_API int own_vfmt(char *b, unsigned n, const char *f, ...);
