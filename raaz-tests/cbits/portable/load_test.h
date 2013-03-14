#ifdef  __RAAZ_PORTABLE_LOADSTORE_TEST_H__
#define __RAAZ_PORTABLE_LOADSTORE_TEST_H__

extern uint32_t raaz_portable_get32le(uint32_t *w, int i);
extern uint32_t raaz_portable_get32be(uint32_t *w, int i);
extern uint64_t raaz_portable_get64le(uint64_t *w, int i);
extern uint64_t raaz_portable_get64be(uint64_t *w, int i);

#endif
