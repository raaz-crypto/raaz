#ifndef __RAAZ_TEST_LOAD_H__
#define __RAAZ_TEST_LOAD_H__
#include <raaz/primitives/load.h>

extern uint32_t raazTestsLoad32LE(uint32_t *w, int i);
extern uint32_t raazTestsLoad32BE(uint32_t *w, int i);
extern uint64_t raazTestsLoad64LE(uint64_t *w, int i);
extern uint64_t raazTestsLoad64BE(uint64_t *w, int i);
extern char *   raazTestsCCompiler(void);
#endif
