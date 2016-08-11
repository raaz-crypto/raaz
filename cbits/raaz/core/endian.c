# include <raaz/core/endian.h>

/*
 * 32-bit Little endian  load and store
 */

#define HTOLE32(ptr)                  \
    ((uint32_t)  (ptr[0]))            \
    |  (((uint32_t) (ptr[1])) << 8)   \
    |  (((uint32_t) (ptr[2])) << 16)  \
    |  (((uint32_t) (ptr[3])) << 24)



uint32_t raazLoadLE32(uint32_t *wPtr)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
  return htole32(*wPtr);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) wPtr;
  return HTOLE32(ptr);
#endif
}

void raazStoreLE32(uint32_t *wPtr , uint32_t w)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD)
    *wPtr = le32toh(w);
#elif defined(PLATFORM_BSD)
    *wPtr = letoh32(w);
#else
    unsigned char *ptr;
    ptr = (unsigned char *) wPtr;
    ptr[0] = (unsigned char) w;
    ptr[1] = (unsigned char) (w >> 8);
    ptr[2] = (unsigned char) (w >> 16);
    ptr[3] = (unsigned char) (w >> 24);
#endif
    return;
}


void raazCopyLE32(int n, uint32_t *dest, uint32_t *src)
{
    unsigned char *ptr;
    while ( n > 0){
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
        *dest = htole32(*src);
#else
        ptr  = (unsigned char *) src;
        dest = HTOLE32(ptr);
#endif
        ++src; ++dest; --n; /* Move on to the next element. */
    }
}



/*
 * 32-bit Big endian  load and store
 */

#define HTOBE32(ptr)                   \
    ((uint32_t)  (ptr[3]))             \
    |    (((uint32_t) (ptr[2])) << 8)  \
    |    (((uint32_t) (ptr[1])) << 16) \
    |    (((uint32_t) (ptr[0])) << 24)

uint32_t raazLoadBE32(uint32_t *wPtr)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
    return htobe32(*wPtr);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) wPtr;
  return HTOBE32(ptr)
#endif
}

void raazStoreBE32(uint32_t *wPtr , uint32_t w)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD)
    *wPtr = be32toh(w);
#elif defined(PLATFORM_BSD)
    *wPtr = betoh32(w);
#else
    unsigned char *ptr;
    ptr = (unsigned char *) wPtr;
    ptr[3] = (unsigned char) w;
    ptr[2] = (unsigned char) (w >> 8);
    ptr[1] = (unsigned char) (w >> 16);
    ptr[0] = (unsigned char) (w >> 24);
#endif
    return;
}


void raazCopyBE32(int n, uint32_t *dest, uint32_t *src)
{
    unsigned char *ptr;

    while (n > 0){
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
        *dest =  htobe32(*src);
#else
        ptr   = (unsigned char *) src;
        *dest = HTOBE32(*src);
#endif
        ++src; ++dest; --n;  /* move on to the next element */
    }
    return;
}

/*
 * 64-bit Little endian  load and store
 */

#define HTOLE64(ptr)                        \
      ((uint64_t) (ptr[0]))                 \
      |  (((uint64_t) (ptr[1])) << 8)       \
      |  (((uint64_t) (ptr[2])) << 16)      \
      |  (((uint64_t) (ptr[3])) << 24)      \
      |  (((uint64_t) (ptr[4])) << 32)      \
      |  (((uint64_t) (ptr[5])) << 40)      \
      |  (((uint64_t) (ptr[6])) << 48)      \
      |  (((uint64_t) (ptr[7])) << 56)

uint64_t raazLoadLE64(uint64_t *wPtr)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
  return htole64(*wPtr);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) wPtr;
  return HTOLE64(ptr);
#endif
}

void raazStoreLE64(uint64_t *wPtr , uint64_t w)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD)
    *wPtr = le64toh(w);
#elif defined(PLATFORM_BSD)
    *wPtr = letoh64(w);
#else
    unsigned char *ptr;
    ptr = (unsigned char *) wPtr;
    ptr[0] = (unsigned char) w;
    ptr[1] = (unsigned char) (w >> 8);
    ptr[2] = (unsigned char) (w >> 16);
    ptr[3] = (unsigned char) (w >> 24);
    ptr[4] = (unsigned char) (w >> 32);
    ptr[5] = (unsigned char) (w >> 40);
    ptr[6] = (unsigned char) (w >> 48);
    ptr[7] = (unsigned char) (w >> 56);
#endif
    return;
}


void raazCopyLE64(int n, uint32_t *dest, uint32_t *src)
{
    unsigned char *ptr;
    while (n > 0){
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
        *dest =  htole64(*src);
#else
        ptr   = (unsigned char *) src;
        *dest = HTOLE64(ptr);
#endif
        ++src; ++dest; --n;
    }
    return;
}



/*
 * 64-bit Big endian  load and store
 */

#define HTOBE64(ptr)                       \
      ((uint64_t) (ptr[7]))                \
      |  (((uint64_t) (ptr[6])) << 8)      \
      |  (((uint64_t) (ptr[5])) << 16)     \
      |  (((uint64_t) (ptr[4])) << 24)     \
      |  (((uint64_t) (ptr[3])) << 32)     \
      |  (((uint64_t) (ptr[2])) << 40)     \
      |  (((uint64_t) (ptr[1])) << 48)     \
      |  (((uint64_t) (ptr[0])) << 56)


uint64_t raazLoadBE64(uint64_t *wPtr)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
  return htobe64(*wPtr);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) wPtr;
  return HTOBE64(ptr);
#endif
}

void raazStoreBE64(uint64_t *wPtr , uint64_t w)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD)
    *wPtr = be64toh(w);
#elif defined(PLATFORM_BSD)
    *wPtr = betoh64(w);
#else
    unsigned char *ptr;
    ptr = (unsigned char *) wPtr;
    ptr[7] = (unsigned char) w;
    ptr[6] = (unsigned char) (w >> 8);
    ptr[5] = (unsigned char) (w >> 16);
    ptr[4] = (unsigned char) (w >> 24);
    ptr[3] = (unsigned char) (w >> 32);
    ptr[2] = (unsigned char) (w >> 40);
    ptr[1] = (unsigned char) (w >> 48);
    ptr[0] = (unsigned char) (w >> 56);
#endif
    return;
}

void raazCopyBE64(int n, uint32_t *dest, uint32_t *src)
{
    unsigned char *ptr;
    while (n > 0){
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
        *dest =  htobe64(*src);
#else
        ptr   = (unsigned char *) src;
        *dest = HTOBE64(ptr);
#endif
        ++src; ++dest; --n;
    }
    return;
}
