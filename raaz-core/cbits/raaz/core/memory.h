#ifndef _RAAZ_CORE_MEMORY_H_
#define _RAAZ_CORE_MEMORY_H_
#include <stdio.h>
#include <string.h>
#include <raaz/primitives/config.h>

#ifdef RAAZ_HAVE_mlock
#include <sys/mman.h>
#endif

#ifdef RAAZ_HAVE_memalign
#include <stdlib.h>
#include <unistd.h>
#endif

extern char * getLine (char*, size_t);
extern void wipememory (volatile void*, size_t);
extern void * createpool(size_t);
extern void freepool(void*, size_t);
extern int memorylock(void*, size_t);
extern void memoryunlock(void*, size_t);

#endif
