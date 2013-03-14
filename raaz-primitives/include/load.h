#ifndef __RAAZ_LOAD_H__
#define __RAAZ_LOAD_H__

#include <stdint.h>

/*

If the C enviroment provides endian.h, like for example gcc, use it to
make the endian conversion fast. Otherwise, fall back to portable C
implementation.

Potential problems: This code has *NOT* been tested on architectures
that throws exception on reading from a non-word aligned
location. Most likely it would not work on them.

*/

#ifdef __RAAZ_HAVE_ENDIAN_H__
#include <endian.h>
#endif

static inline uint32_t raazLoad32LE(uint32_t *w, int i)
{
#ifdef __RAAZ_HAVE_ENDIAN_H__
  return htole32(w[i]);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) (w + i);
  return ((uint32_t) (ptr[0]))
    | (  ((uint32_t) (ptr[1])) << 8)
    | (  ((uint32_t) (ptr[2])) << 16)
    | (  ((uint32_t) (ptr[3])) << 24)
    ;
#endif
}


static inline uint32_t raazLoad32BE(uint32_t *w, int i)
{
#ifdef __RAAZ_HAVE_ENDIAN_H__
  return htobe32(w[i]);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) (w + i);
  return ((uint32_t) (ptr[3]))
    | (  ((uint32_t) (ptr[2])) << 8)
    | (  ((uint32_t) (ptr[1])) << 16)
    | (  ((uint32_t) (ptr[0])) << 24)
    ;
#endif
}


static inline uint64_t raazLoad64LE(uint64_t *w, int i)
{
#ifdef __RAAZ_HAVE_ENDIAN_H__
  return htole64(w[i]);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) (w + i);
  return ((uint64_t)(ptr[0]))
    | (  ((uint64_t) (ptr[1])) << 8)
    | (  ((uint64_t) (ptr[2])) << 16)
    | (  ((uint64_t) (ptr[3])) << 24)
    | (  ((uint64_t) (ptr[4])) << 32)
    | (  ((uint64_t) (ptr[5])) << 40)
    | (  ((uint64_t) (ptr[6])) << 48)
    | (  ((uint64_t) (ptr[7])) << 56)
    ;
#endif
}

static inline uint64_t raazLoad64BE(uint64_t *w, int i)
{
#ifdef __RAAZ_HAVE_ENDIAN_H__
  return htobe64(w[i]);
#else
  unsigned char *ptr;
  ptr = (unsigned char *) (w + i);
  return ((uint64_t) ptr[7])
    | (  ((uint64_t) ptr[6]) << 8)
    | (  ((uint64_t) ptr[5]) << 16)
    | (  ((uint64_t) ptr[4]) << 24)
    | (  ((uint64_t) ptr[3]) << 32)
    | (  ((uint64_t) ptr[2]) << 40)
    | (  ((uint64_t) ptr[1]) << 48)
    | (  ((uint64_t) ptr[0]) << 56)
    ;
#endif
}

#endif
