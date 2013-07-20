/*

This header file provides endian explicit load instruction.

Copyright (c) 2012, Piyush P Kurur

All rights reserved.

This software is distributed under the terms and conditions of the
BSD3 license. See the accompanying file LICENSE for exact terms and
condition.

*/


#ifndef __RAAZ_PRIMITIVES_LOAD_H__
#define __RAAZ_PRIMITIVES_LOAD_H__

#include <stdint.h>
#include <raaz/primitives/config.h>

/*

If the C enviroment provides functions htolex/htobex via endian.h
(e.g. gcc/glibc), use it to make the endian conversion
fast. Otherwise, fall back to portable C implementation.

Potential problems: This code has *NOT* been tested on architectures
that throws exception on reading from a non-word aligned
location.

*/

static inline uint32_t raazLoad32LE(uint32_t *w, int i)
{
#ifdef RAAZ_HAVE_htole32
#include <endian.h>
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
#ifdef RAAZ_HAVE_htobe32
#include <endian.h>
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
#ifdef RAAZ_HAVE_htole64
#include <endian.h>
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
#ifdef RAAZ_HAVE_htobe64
#include <endian.h>
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
