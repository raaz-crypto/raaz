#include <stdint.h>
#include <endian.h>

uint32_t le32(uint32_t arg)
{
    return htole32 (arg);
}
