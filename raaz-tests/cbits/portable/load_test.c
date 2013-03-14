#undef __RAAZ_HAVE_ENDIAN_H__

#include <stdint.h>
#include <load.h>


uint32_t raaz_portable_get32le(uint32_t *w, int i)
{
  return raazLoad32LE(w,i);
}



uint32_t raaz_portable_get32be(uint32_t *w, int i)
{
  return raazLoad32BE(w,i);
}



uint64_t raaz_portable_get64le(uint64_t *w, int i)
{
  return raazLoad64LE(w,i);
}



uint64_t raaz_portable_get64be(uint64_t *w, int i)
{
  return raazLoad64BE(w,i);
}
