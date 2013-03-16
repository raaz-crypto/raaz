#include <stdint.h>
#include <raaz/tests/portable/load_test.h>

uint32_t raazTestsPortableLoad32LE(uint32_t *w, int i)
{
  return raazLoad32LE(w,i);
}



uint32_t raazTestsPortableLoad32BE(uint32_t *w, int i)
{
  return raazLoad32BE(w,i);
}



uint64_t raazTestsPortableLoad64LE(uint64_t *w, int i)
{
  return raazLoad64LE(w,i);
}



uint64_t raazTestsPortableLoad64BE(uint64_t *w, int i)
{
  return raazLoad64BE(w,i);
}

char *raazTestsPortableCCompiler(void)
{
  return RAAZ_C_COMPILER;
}
