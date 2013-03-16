#ifndef __RAAZ_TESTS_PORTABLE_LOAD_H__
#define __RAAZ_TESTS_PORTABLE_LOAD_H__

/*  Make sure that no system specific options are set  */

#define RAAZ_PORTABLE_C
#include <raaz/primitives/load.h>

extern uint32_t raazTestsPortableLoad32LE(uint32_t *w, int i);
extern uint32_t raazTestsPortableLoad32BE(uint32_t *w, int i);
extern uint64_t raazTestsPortableLoad64LE(uint64_t *w, int i);
extern uint64_t raazTestsPortableLoad64BE(uint64_t *w, int i);
extern char *   raazTestsPortableCCompiler(void);

#endif
