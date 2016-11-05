#pragma once
#include "common.h"

/* Type of 128-bit SIMD instructions */
typedef Word Vec  __attribute__ ((vector_size (16)));
/* Type of 256-bit SIMD instructions */
typedef Word Vec2 __attribute__ ((vector_size (32)));
/* Type of 512-bit SIMD instructions */
typedef Word Vec4 __attribute__ ((vector_size (64)));
