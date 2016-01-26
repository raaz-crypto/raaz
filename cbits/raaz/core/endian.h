#ifndef __RAAZ_ENDIAN_H_
#define __RAAZ_ENDIAN_H_
#include <stdint.h>

/* Include the right header file based on the platform */
#ifdef PLATFORM_LINUX
#include <endian.h>
#elif defined(PLATFORM_BSD) || defined(PLATFORM_OPENBSD)
#include <sys/endian.h>
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
