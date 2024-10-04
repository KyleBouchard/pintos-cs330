#ifndef _FLOAT_POINT_H
#define _FLOAT_POINT_H

#include <stdint.h>

typedef int floater;

#define FLOATER_P 17
#define FLOATER_Q (31 - FLOATER_P)
#define _FLOATER_F (1 << FLOATER_Q)

#define floater_from_int(n) ((n) * _FLOATER_F)
#define floater_to_int_trunc(x) ((x) / _FLOATER_F)
#define floater_to_int_round(x) ((x) > 0 ? \
                                    ((x) + _FLOATER_F / 2) / _FLOATER_F : \
                                    ((x) - _FLOATER_F / 2) / _FLOATER_F)

#define floater_add_floater(x, y) ((x) + (y))
#define floater_sub_floater(x, y) ((x) - (y))

#define floater_add_int(x, n) floater_add_floater((x), floater_from_int(n))
#define floater_sub_int(x, n) floater_sub_floater((x), floater_from_int(n))

#define floater_mul_floater(x, y) (((int64_t)(x)) * (y) / _FLOATER_F)
#define floater_mul_int(x, n) ((x) * (n))

#define floater_div_floater(x, y) (((int64_t)(x)) * _FLOATER_F / (y))
#define floater_div_int(x, n) ((x) / (n))

#endif /* _FLOAT_POINT_H */