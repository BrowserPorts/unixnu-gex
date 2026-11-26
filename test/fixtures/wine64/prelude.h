/* prelude.cpp's own -include: it comes before gexcc-win's C++ prelude */
#ifdef _LIBCPP_MATH_H
#  error "gexcc-win's prelude came before the program's own -include"
#endif
#define PRELUDE_OWN 1
