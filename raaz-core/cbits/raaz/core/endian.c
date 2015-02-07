#include <stdint.h>
#include <raaz/primitives/config.h>

#if defined(RAAZ_HAVE_htole32)   | defined(RAAZ_HAVE_htobe32)	\
    | defined(RAAZ_HAVE_htole64) | defined(RAAZ_HAVE_htobe64)	\
    | defined(RAAZ_HAVE_be32toh) | defined(RAAZ_HAVE_le32toh)	\
    | defined(RAAZ_HAVE_be64toh) | defined(RAAZ_HAVE_le64toh)
#include <endian.h>
#endif

/*
 * 32-bit Little endian  load and store
 */

uint32_t raazLoadLE32(uint32_t *wPtr)
{
#ifdef RAAZ_HAVE_htole32
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
#ifdef RAAZ_HAVE_le32toh
    *wPtr = le32toh(w);
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
#ifdef RAAZ_HAVE_htobe32
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
#ifdef RAAZ_HAVE_be32toh
    *wPtr = be32toh(w);
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
#ifdef RAAZ_HAVE_htole64
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
#ifdef RAAZ_HAVE_le64toh
    *wPtr = le64toh(w);
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
#ifdef RAAZ_HAVE_htobe64
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
#ifdef RAAZ_HAVE_be64toh
    *wPtr = be64toh(w);
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
