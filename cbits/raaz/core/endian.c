# include <raaz/core/endian.h>
/*
 * 32-bit Little endian  load and store
 */

uint32_t raazLoadLE32(uint32_t *wPtr)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
  return htole32(*wPtr);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) wPtr;
  return ((uint32_t)  (ptr[0]))
      |  (((uint32_t) (ptr[1])) << 8)
      |  (((uint32_t) (ptr[2])) << 16)
      |  (((uint32_t) (ptr[3])) << 24)
    ;
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

/*
 * 32-bit Big endian  load and store
 */

uint32_t raazLoadBE32(uint32_t *wPtr)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
    return htobe32(*wPtr);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) wPtr;
  return ((uint32_t)  (ptr[3]))
    |    (((uint32_t) (ptr[2])) << 8)
    |    (((uint32_t) (ptr[1])) << 16)
    |    (((uint32_t) (ptr[0])) << 24)
    ;
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

/*
 * 64-bit Little endian  load and store
 */

uint64_t raazLoadLE64(uint64_t *wPtr)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
  return htole64(*wPtr);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) wPtr;
  return ((uint64_t) (ptr[0]))
      |  (((uint64_t) (ptr[1])) << 8)
      |  (((uint64_t) (ptr[2])) << 16)
      |  (((uint64_t) (ptr[3])) << 24)
      |  (((uint64_t) (ptr[4])) << 32)
      |  (((uint64_t) (ptr[5])) << 40)
      |  (((uint64_t) (ptr[6])) << 48)
      |  (((uint64_t) (ptr[7])) << 56)
    ;
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


/*
 * 64-bit Big endian  load and store
 */

uint64_t raazLoadBE64(uint64_t *wPtr)
{
#if defined(PLATFORM_LINUX) || defined(PLATFORM_OPENBSD) || defined(PLATFORM_BSD)
  return htobe64(*wPtr);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) wPtr;
  return ((uint64_t) (ptr[7]))
      |  (((uint64_t) (ptr[6])) << 8)
      |  (((uint64_t) (ptr[5])) << 16)
      |  (((uint64_t) (ptr[4])) << 24)
      |  (((uint64_t) (ptr[3])) << 32)
      |  (((uint64_t) (ptr[2])) << 40)
      |  (((uint64_t) (ptr[1])) << 48)
      |  (((uint64_t) (ptr[0])) << 56)
    ;
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
