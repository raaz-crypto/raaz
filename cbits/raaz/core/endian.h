#ifndef __RAAZ_ENDIAN_H_
#define __RAAZ_ENDIAN_H_

#include <stdint.h>
#include <raaz/primitives/config.h>

#if defined(RAAZ_HAVE_htole32)   | defined(RAAZ_HAVE_htobe32)	\
    | defined(RAAZ_HAVE_htole64) | defined(RAAZ_HAVE_htobe64)	\
    | defined(RAAZ_HAVE_be32toh) | defined(RAAZ_HAVE_le32toh)	\
    | defined(RAAZ_HAVE_be64toh) | defined(RAAZ_HAVE_le64toh)
#include <endian.h>
#endif

/* Loads */
extern uint32_t raazLoadLE32(uint32_t *);
extern uint32_t raazLoadBE32(uint32_t *);
extern uint64_t raazLoadLE64(uint64_t *);
extern uint64_t raazLoadBE64(uint64_t *);

/* Stores */
extern void raazStoreLE32(uint32_t *, uint32_t);
extern void raazStoreBE32(uint32_t *, uint32_t);
extern void raazStoreLE64(uint64_t *, uint64_t);
extern void raazStoreBE64(uint64_t *, uint64_t);

#endif
