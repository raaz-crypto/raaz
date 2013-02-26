# ifndef __RAAZ_GCC_ENDIAN_H__
# define __RAAZ_GCC_ENDIAN_H__

#include <stdint.h>
#include <endian.h>
static inline uint16_t raaz_toBE16(uint16_t w)
{
  return htobe16(w);
}

static inline uint16_t raaz_toLE16(uint16_t w)
{
  return htole16(w);
}


static inline uint32_t raaz_toBE32(uint32_t w)
{
  return htobe32(w);
}

static inline uint32_t raaz_toLE32(uint32_t w)
{
  return htole32(w);
}

static inline uint64_t raaz_toBE64(uint64_t w)
{
  return htobe64(w);
}

static inline uint64_t raaz_toLE64(uint64_t w)
{
  return htole64(w);
}

#endif
