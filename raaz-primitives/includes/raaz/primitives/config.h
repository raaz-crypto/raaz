#ifndef __RAAZ_PRIMITIVES_CONFIG_H__
#define __RAAZ_PRIMITIVES_CONFIG_H__

/*

Used symbols
------------

1. RAAZ_PORTABLE_C: If defined, we use only portable feature of the c
   compiler.

2. RAAZ_HAVE_GCC: If defined, we assume a gcc based system.



Generated symbols
-----------------


1. RAAZ_C_COMPILER: The string that describes the name of the infered
   C compiler. Currently it can take the following possible values

   1.1 "gcc"
   1.2 "portable"

2. RAAZ_HAVE_ENDIAN_H: Defined if the c library exports endian
   conversion functions htole32, htobe32, htole64 and htobe64.


*/


#ifndef RAAZ_PORTABLE_C

#   ifdef RAAZ_HAVE_GCC  /* GCC specific stuff */

#      define RAAZ_C_COMPILER "gcc"
#      define RAAZ_HAVE_ENDIAN_H

#   endif  /* RAAZ_HAVE_GCC */

#else /* RAAZ_PORTABLE_C */


#   define RAAZ_C_COMPILER "portable"
#   undef RAAZ_HAVE_ENDIAN_H

#endif /* RAAZ_PORTABLE_C */

#endif
