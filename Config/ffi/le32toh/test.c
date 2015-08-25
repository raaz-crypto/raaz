#include <stdint.h>
#include <endian.h>

uint32_t le32(uint32_t arg)
{
    return le32toh (arg);
}
