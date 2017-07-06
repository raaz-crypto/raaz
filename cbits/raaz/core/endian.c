#include <raaz/core/endian.h>
#ifdef __RAAZ_REQUIRE_PORTABLE_ENDIAN__

/* We were not able to detect the optimised platform specific versions
 * of the low level endian functions. We now proceed to define a
 * portable variant so that the extern declarations is satisfied.
 */



/*
 *  These are declared as macros because they will work for both
 *  32-bit as well as 64-bit cases.
 */

# define MASK(i)       (0xFFULL << (8*(i))) /* mask to select the ith byte              */
# define SEL(a,i)      ((a) & MASK(i))      /* select the ith byte                      */
# define MOVL(a,i)      ((a) << (8*(i)))    /* shift the bytes i positions to the left  */
# define MOVR(a,i)      ((a) >> (8*(i)))    /* shift the bytes i positions to the right */
# define SWAP(a,i,j)   (MOVL(SEL(a,i),(j-i)) | MOVR(SEL(a,j), (j - i)))
                       /* This function swaps the ith and jth bytes and sets other bytes to 0 */


uint32_t raaz_bswap32(uint32_t a){ return (SWAP(a,0,3) | SWAP(a,1,2)); }
uint64_t raaz_bswap64(uint64_t a){ return (SWAP(a,0,7) | SWAP(a,1,6)  | SWAP(a,2,5) | SWAP(a,3,4)); }





# define TO32(x)     ((uint32_t)(x))
# define TO64(x)     ((uint64_t)(x))

# define B32(ptr,i) (TO32(ptr[i]))
# define B64(ptr,i) (TO64(ptr[i]))

/* Make a 32-bit quantity out of the 4 bytes given in MSB first order */
# define MK32(a,b,c,d) ( (a) << 24 | (b) << 16 | (c) << 8 | (d) )

/* Similar to MK32 but for 64-bit quantities */
# define MK64(a,b,c,d,e,f,g,h)  \
    ((a) <<  56  | (b) << 48   | (c) << 40 | (d) << 32	| (e) << 24   | (f) << 16   | (g) << 8  | (h))


uint32_t raaz_tobe32(uint32_t x)
{
    uint8_t *ptr = (uint8_t *) &x;
    return MK32(B32(ptr,0), B32(ptr,1), B32(ptr,2), B32(ptr,3));
}


uint32_t raaz_tole32(uint32_t x)
{
    uint8_t *ptr = (uint8_t *) &x;
    return MK32(B32(ptr,3), B32(ptr,2), B32(ptr,1), B32(ptr,0));

}

uint64_t raaz_tobe64(uint64_t x)
{
    uint8_t *ptr = (uint8_t *) &x;
    return MK64(B64(ptr,0), B64(ptr,1), B64(ptr,2), B64(ptr,3),
		B64(ptr,4), B64(ptr,5), B64(ptr,6), B64(ptr,7));
}


uint64_t raaz_tole64(uint64_t x)
{
    uint8_t *ptr = (uint8_t *) &x;
    return MK64(B64(ptr,7), B64(ptr,6), B64(ptr,5), B64(ptr,4),
		B64(ptr,3), B64(ptr,2), B64(ptr,1), B64(ptr,0));
}



#endif

/* Finally we define the functions that are called by Haskell as FFI
 * routines for their endian store instances. These should not be
 * declared static inline.
 */

uint32_t raazSwap32(uint32_t a){ return raaz_bswap32(a);}
uint64_t raazSwap64(uint64_t a){ return raaz_bswap64(a);}

void raazSwap32Array(uint32_t *ptr, int n)
{
    for(;n > 0; ++ptr, --n){*ptr = raaz_bswap32(*ptr);}
}

void raazSwap64Array(uint64_t *ptr, int n)
{
    for(;n > 0; ++ptr, --n){*ptr = raaz_bswap64(*ptr);}
}
