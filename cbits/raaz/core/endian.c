# include <raaz/core/endian.h>

/*
 * 32-bit Little endian  load and store
 */

# define TOW32(a)               ((uint32_t) a)
# define TOW64(a)               ((uint64_t) a)
# define MKW32(a,b,c,d)         (TOW32(a) << 24 | TOW32(b) << 16 | TOW32(c) << 8 | TOW32(d))
# define MK64(a,b,c,d,e,f,g,h) (                                      \
   TOW64(a) << 56 | TOW64(b) << 48 | TOW64(c) << 40 | TOW64(d) << 32  \
   TOW64(e) << 24 | TOW64(f) << 16 | TOW64(g) << 8 | TOW64(h)         )

# define LoadB(ptr,i)           (((unsigned char *)ptr)[i])
/* Load from a memory location with proper endian conversion */
#if defined(PLATFORM_LINUX) || defined (PLATFORM_BSD) || defined(PLATFORM_OPENBSD)

    uint32_t raazLoadLE32(uint32_t *wPtr)               { return htole32(*wPtr); }
    uint32_t raazLoadBE32(uint32_t *wPtr)               { return htobe32(*wPtr); }
    uint64_t raazLoadLE64(uint64_t *wPtr)               { return htole64(*wPtr); }
    uint64_t raazLoadBE64(uint64_t *wPtr)               { return htobe64(*wPtr); }

#else   /* portable defineition */

    uint32_t raazLoadLE32(uint32_t *ptr)
    {
	return MKW32( LoadB(ptr,3), LoadB(ptr,2), LoadB(ptr,1), LoadB(ptr, 0) );
    }

    uint32_t raazLoadBE32(uint32_t *ptr)
    {
	return MKW32( LoadB(ptr,0), LoadB(ptr,1), LoadB(ptr,2), LoadB(ptr, 3) );
    }

    uint64_t raazLoadLE64(uint64_t *ptr)
    {
	return MKW64( LoadB(ptr,7), LoadB(ptr,6), LoadB(ptr,5), LoadB(ptr, 4),
		      LoadB(ptr,3), LoadB(ptr,2), LoadB(ptr,1), LoadB(ptr, 0));
    }

    uint64_t raazLoadBE64(uint64_t *ptr)
    {
	return  MKW64( LoadB(ptr,0), LoadB(ptr,1), LoadB(ptr,2), LoadB(ptr, 3),
		       LoadB(ptr,4), LoadB(ptr,5), LoadB(ptr,6), LoadB(ptr, 7));
    }

#endif

/* STORE to a memory location with proper endian conversion */
# define GetByte(w, i)          ((unsigned char) (w >> (8*(i))))
# define StoreByte(ptr,i,w,j)   {((unsigned char *)(ptr))[i] = GetByte(w,j); }

# if defined(PLATFORM_LINUX) || defined (PLATFORM_OPENBSD)
    void raazStoreLE32(uint32_t *wPtr, uint32_t w) { *wPtr = le32toh(w); }
    void raazStoreBE32(uint32_t *wPtr, uint32_t w) { *wPtr = be32toh(w); }
    void raazStoreLE64(uint64_t *wPtr, uint64_t w) { *wPtr = le64toh(w); }
    void raazStoreBE64(uint64_t *wPtr, uint64_t w) { *wPtr = be64toh(w); }

# elif defined(PLATFORM_BSD)
    void raazStoreLE32(uint32_t *wPtr, uint32_t w) { *wPtr = letoh32(w); }
    void raazStoreBE32(uint32_t *wPtr, uint32_t w) { *wPtr = betoh32(w); }
    void raazStoreLE64(uint64_t *wPtr, uint64_t w) { *wPtr = letoh64(w); }
    void raazStoreBE64(uint64_t *wPtr, uint64_t w) { *wPtr = betoh64(w); }
# else

    void raazStoreLE32(uint32_t *ptr, uint32_t w)
    {
	StoreByte(ptr,0,w,0);
	StoreByte(ptr,1,w,1);
	StoreByte(ptr,2,w,2);
	StoreByte(ptr,3,w,3);
    }

    void raazStoreBE32(uint32_t *ptr, uint32_t w)
    {
	StoreByte(ptr,3,w,0);
	StoreByte(ptr,2,w,1);
	StoreByte(ptr,1,w,2);
	StoreByte(ptr,0,w,3);
    }

    void raazStoreLE64(uint64_t *ptr, uint64_t w)
    {
	StoreByte(ptr,0,w,0);
	StoreByte(ptr,1,w,1);
	StoreByte(ptr,2,w,2);
	StoreByte(ptr,3,w,3);
	StoreByte(ptr,4,w,4);
	StoreByte(ptr,5,w,5);
	StoreByte(ptr,6,w,6);
	StoreByte(ptr,7,w,7);
    }

    void raazStoreBE64(uint64_t *ptr, uint64_t w)
    {
	StoreByte(ptr,7,w,0);
	StoreByte(ptr,6,w,1);
	StoreByte(ptr,5,w,2);
	StoreByte(ptr,4,w,3);
	StoreByte(ptr,3,w,4);
	StoreByte(ptr,3,w,5);
	StoreByte(ptr,1,w,6);
	StoreByte(ptr,0,w,7);
    }

#endif


void raazCopyFromLE32(uint32_t *dest, uint32_t *src, int n){
    while ( n > 0){
        *dest = raazLoadLE32(src);
        ++src; ++dest; --n; /* Move on to the next element. */
    }
}


void raazCopyFromBE32(uint32_t *dest, uint32_t *src, int n){
    while (n > 0){
        *dest = raazLoadBE32(src);
        ++src; ++dest; --n; /* Move on to the next element. */
    }
    return;
}


void raazCopyFromLE64(uint64_t *dest, uint64_t *src, int n){
    while (n > 0){
        *dest =  raazLoadLE64(src);
        ++src; ++dest; --n;
    }
    return;
}


void raazCopyFromBE64(uint64_t *dest, uint64_t *src, int n){
    while (n > 0){
        *dest = raazLoadBE64(src);
        ++src; ++dest; --n;
    }
    return;
}
