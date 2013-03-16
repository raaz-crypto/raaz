#include <stdint.h>
#include <raaz/tests/platform/load_test.h>

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

char *raazTestsCCompiler(void)
{
  return RAAZ_C_COMPILER;
}
