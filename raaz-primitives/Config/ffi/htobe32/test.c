#include <stdint.h>
#include <endian.h>

uint32_t be32(uint32_t arg)
{
    return htobe32 (arg);
}
