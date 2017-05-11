# pragma once
# include <stdint.h>

/* These are the C functions that are exported for FFI calls to
 * Haskell. Their definitions are available in endian.c
 */

extern uint32_t raazSwap32      (uint32_t a);
extern uint64_t raazSwap64      (uint64_t a);
extern void     raazSwap32Array (uint32_t *ptr, int n);
extern void     raazSwap64Array (uint64_t *ptr, int n);


/* This header also give interface to low level byteswap and endian
 * conversion in a platform agnostic way to both to the Haskell FFI
 * functions declared above as well as to crypto primitives defined in
 * other c sources. The should not be used directly for FFI as they
 * most likely are defined static inline and included with the source.
 */


#ifndef __GNUC__
#define __RAAZ_REQUIRE_PORTABLE_ENDIAN__

/*  We are unable to detect if the compiler is gcc or a compatible
 *  one. So we declare all the low level functions to be extern and
 *  expect their definitions to be in endian.c The above #define line
 *  is used to indicate that we are in such a situation
 */

extern uint32_t raaz_bswap32(uint32_t x);
extern uint64_t raaz_bswap64(uint64_t x);

extern uint32_t raaz_tobe32(uint32_t x);
extern uint64_t raaz_tobe64(uint64_t x);
extern uint32_t raaz_tole32(uint32_t x);
extern uint64_t raaz_tole64(uint64_t x);

#else

/* We are in GCC, so pick up the relevant platform specific functions
 * and wrap it in a static inline declaration. These
 */

#  ifdef PLATFORM_OSX
#    include <libkern/OSByteOrder.h> /* For PLATFORM OSX */

     static inline uint32_t raaz_bswap32(uint32_t x){ return OSSwapInt32(x); }
     static inline uint64_t raaz_bswap64(uint64_t x){ return OSSwapInt64(x); }

#  elif PLATFORM_LINUX
#    include <byteswap.h>
     static inline uint32_t raaz_bswap32(uint32_t x){ return bswap_32(x); }
     static inline uint64_t raaz_bswap64(uint64_t x){ return bswap_64(x); }

#  else  /* All platforms */
#    include <endian.h>
     static inline uint32_t raaz_bswap32(uint32_t x){ return swap32(x); }
     static inline uint64_t raaz_bswap64(uint64_t x){ return swap64(x); }
#  endif

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

#endif
