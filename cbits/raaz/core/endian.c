# include <raaz/core/endian.h>

/* Include the right header file based on the platform */

#ifdef PLATFORM_LINUX
#include <endian.h>
#elif defined(PLATFORM_BSD) || defined(PLATFORM_OPENBSD)
#include <sys/endian.h>
#endif

# define TO32(w)        ((uint32_t)(w))
# define TO64(w)        ((uint64_t)(w))
# define B32(ptr,i)     TO32(((uint8_t *)(ptr))[i])
# define B64(ptr,i)     TO64(((uint8_t *)(ptr))[i])

# define B(ptr,i) (((unsigned char)(ptr))[(i)])
# define MK32(a,b,c,d)          ( (a) << 24 | (b) << 16 | (c) << 8 | (d) )
# define MK64(a,b,c,d,e,f,g,h)  \
    ((a)   <<  56  | (b) << 48   | (c) << 40 | (d) << 32 \
     | (e) << 24   | (f) << 16   | (g) << 8  | (h))


#if defined(PLATFORM_LINUX) || defined (PLATFORM_BSD) || defined(PLATFORM_OPENBSD)

    uint32_t raazLoadLE32(uint32_t *wPtr)               { return htole32(*wPtr); }
    uint32_t raazLoadBE32(uint32_t *wPtr)               { return htobe32(*wPtr); }
    uint64_t raazLoadLE64(uint64_t *wPtr)               { return htole64(*wPtr); }
    uint64_t raazLoadBE64(uint64_t *wPtr)               { return htobe64(*wPtr); }

# else /* portable implementation */

uint32_t raazLoadBE32(uint32_t  *ptr)
{
    return MK32(B32(ptr,0), B32(ptr,1), B32(ptr,2), B32(ptr,3));
}


uint32_t raazLoadLE32(uint32_t *ptr)
{
    return MK32(B32(ptr,3), B32(ptr,2), B32(ptr,1), B32(ptr,0));

}

uint64_t raazLoadBE64(uint64_t *ptr)
{
    return MK64(B64(ptr,0), B64(ptr,1), B64(ptr,2), B64(ptr,3),
		B64(ptr,4), B64(ptr,5), B64(ptr,6), B64(ptr,7));
}


uint64_t raazLoadLE64(uint64_t *ptr)
{
    return MK64(B64(ptr,7), B64(ptr,6), B64(ptr,5), B64(ptr,4),
		B64(ptr,3), B64(ptr,2), B64(ptr,1), B64(ptr,0));
}

#endif


# define MASK(i)       (0xFFULL << (8*(i)))
# define SEL(a,i)      ((a) & MASK(i))
# define MOVL(a,i)      ((a) << (8*(i)))
# define MOVR(a,i)      ((a) >> (8*(i)))

/* Assuming i < j */
# define SWAP(a,i,j)   (MOVL(SEL(a,i),(j-i)) | MOVR(SEL(a,j), (j - i)))

/*
# define SEL(a,i)      ((a) >> (8 * (i)) &  0xFF)
# define MOV(a,i)      ((a) << ((i)*8))
# define SWAP(a,i,j)   (MOV(SEL(a,i),j) | MOV(SEL(a,j),i)) */

#ifdef __GNUC__

#include <byteswap.h>

uint32_t raazSwap32(uint32_t a)
{
    return  bswap_32(a);
}

uint32_t raazSwap64(uint32_t a)
{
    return bswap_64(a);
}


void raazSwap32Array(uint32_t *ptr, int n)
{
    while(n > 0)
    {
	*ptr = bswap_32(*ptr);
	++ptr; --n;
    }
}

void raazSwap64Array(uint64_t *ptr, int n)
{
    while( n > 0)
    {

	*ptr = bswap_64(*ptr);
	++ptr; --n;
    }
}

#else


uint32_t raazSwap32(uint32_t a)
{

    return (SWAP(a,0,3) | SWAP(a,1,2));
}

uint64_t raazSwap64(uint64_t a)
{
    return (SWAP(a,0,7) | SWAP(a,1,6)  | SWAP(a,2,5) | SWAP(a,3,4));
}

void raazSwap32Array(uint32_t *ptr, int n)
{
    while(n > 0)
    {
	*ptr = raazSwap32(*ptr);
	++ptr; --n;
    }
}

void raazSwap64Array(uint64_t *ptr, int n)
{
    while( n > 0)
    {
	*ptr = raazSwap64(*ptr);
	++ptr; --n;
    }
}


#endif
