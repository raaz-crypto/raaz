# pragma once
# include <stdint.h>

/* This header file does the following

1. Declarations of raazSwap* and RaazSwap*Array functions that are the
   C functions for call from Haskell.

2. Endian conversion functions that are used by implementations of
   primitives.

Note that on the Haskell side endian conversion happens by calling the
swap if required and we do not need the endian functions
here. Therefore, they are declared as static inline whenever possible.


We first define functions for byte swapping falling back to portable C
implementation (indicated by defining __RAAZ_REQUIRE_PORTABLE_SWAP__)
available in raaz/core/endian.c. The C-ffi stub functions make use of
these functions. The endian conversions functions also use them if we
can detect the byte order. Otherwise they too have a portable c
implementation (indicated by defining
__RAAZ_REQUIRE_PORTABLE_ENDIAN__)

*/

/*
 *         Byte swapping. Use platform specific ones when we know it.
 */

#ifdef PLATFORM_OSX
#  include <libkern/OSByteOrder.h> /* For PLATFORM OSX */

   static inline uint32_t raaz_bswap32(uint32_t x){ return OSSwapInt32(x); }
   static inline uint64_t raaz_bswap64(uint64_t x){ return OSSwapInt64(x); }

#elif defined(PLATFORM_WINDOWS)
#  include<stdlib.h>
   static inline uint32_t raaz_bswap32(uint32_t x){ return _byteswap_ulong(x); }
   static inline uint64_t raaz_bswap64(uint64_t x){ return _byteswap_uint64(x); }

#elif defined(PLATFORM_OPENBSD)
#  include <sys/endian.h>
   static inline uint32_t raaz_bswap32(uint32_t x){ return bswap32(x); }
   static inline uint64_t raaz_bswap64(uint64_t x){ return bswap64(x); }

#elif defined(PLATFORM_LINUX) /* All other platforms */
#  include <byteswap.h>
   static inline uint32_t raaz_bswap32(uint32_t x){ return bswap_32(x); }
   static inline uint64_t raaz_bswap64(uint64_t x){ return bswap_64(x); }
#else
  /* We do not have platform specific byte swap */
# define __RAAZ_REQUIRE_PORTABLE_SWAP__

  extern uint32_t raaz_bswap32(uint32_t x);
  extern uint64_t raaz_bswap64(uint64_t x);

#endif


#ifdef __GNUC__

/* For GNUC compiler use byte order checks to define efficient endian
 * conversion */

#  if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

   static inline uint32_t raaz_tobe32(uint32_t x){ return raaz_bswap32(x); }
   static inline uint64_t raaz_tobe64(uint64_t x){ return raaz_bswap64(x); }

   static inline uint32_t raaz_tole32(uint32_t x){ return x; }
   static inline uint64_t raaz_tole64(uint64_t x){ return x; }

#  else
   static inline uint32_t raaz_tobe32(uint32_t x){ return x; }
   static inline uint64_t raaz_tobe64(uint64_t x){ return x; }

   static inline uint32_t raaz_tole32(uint32_t x){ return raaz_bswap32(x); }
   static inline uint64_t raaz_tole64(uint64_t x){ return raaz_bswap64(x); }

#  endif /* Byte order */

#else  /* Not __GNUC__ use portable implementations */
#  define __RAAZ_REQUIRE_PORTABLE_ENDIAN__

   extern uint32_t raaz_tobe32(uint32_t x);
   extern uint64_t raaz_tobe64(uint64_t x);
   extern uint32_t raaz_tole32(uint32_t x);
   extern uint64_t raaz_tole64(uint64_t x);

#endif

/* These are the C functions that are exported for FFI calls to
 * Haskell. Their definitions are available in endian.c
 */

extern uint32_t raazSwap32      (uint32_t a);
extern uint64_t raazSwap64      (uint64_t a);
extern void     raazSwap32Array (uint32_t *ptr, int n);
extern void     raazSwap64Array (uint64_t *ptr, int n);
