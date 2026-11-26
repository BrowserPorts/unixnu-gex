/* A one-step C++ compile and link (gexcc-win++ prelude.cpp -o prelude.exe)
 * gets the program's own -include and then gexcc-win's prelude (libc++'s
 * math.h first, in both header modes), as a -c compile does. */
#ifndef PRELUDE_OWN
#  error "the program's own -include is missing"
#endif
#ifndef _LIBCPP_MATH_H
#  error "gexcc-win's C++ prelude is missing"
#endif
#include <cstdio>
int main() { std::printf("prelude: ok %d\n", PRELUDE_OWN); return 0; }
