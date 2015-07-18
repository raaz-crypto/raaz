#include <stdint.h>
#include <raaz/primitives/load.h>

extern uint32_t raazTestsLoad32LE(uint32_t *w, int i);
extern uint32_t raazTestsLoad32BE(uint32_t *w, int i);
extern uint64_t raazTestsLoad64LE(uint64_t *w, int i);
extern uint64_t raazTestsLoad64BE(uint64_t *w, int i);
extern char *   raazTestsCCompiler(void);


uint32_t raazTestsLoad32LE(uint32_t *w, int i)
{
  return raazLoad32LE(w,i);
}

uint32_t raazTestsLoad32BE(uint32_t *w, int i)
{
  return raazLoad32BE(w,i);
}

uint64_t raazTestsLoad64LE(uint64_t *w, int i)
{
  return raazLoad64LE(w,i);
}

uint64_t raazTestsLoad64BE(uint64_t *w, int i)
{
  return raazLoad64BE(w,i);
}
