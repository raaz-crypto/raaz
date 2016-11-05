#pragma once

#include <stdint.h>
#include <inttypes.h>
#include <raaz/core/endian.h>

typedef uint32_t Word;
typedef Word     State[16];
typedef Word     Block[16];

/* Implementation in accordance to RFC7539
 * https://tools.ietf.org/html/rfc7539
 *
 * Note that there is a difference in the rfc and the version
 * published by djb.  In the rfc one uses 32-bit counter and 96-bit
 * nounce, whereas the published version of djb uses 64bit counter and
 * 64bit nounce.
 *
 * As a result the maximum data that should be encrypted with this
 * cipher (for a given key, iv pair).
 *
 * 2^32 blocks = 256 GB.
 *
 */

typedef uint32_t Counter;
typedef Word     IV[3];
typedef Word     Key[8];

# define BLOCK_SIZE       (sizeof(State))

#define C0 ((Word) 0x61707865)
#define C1 ((Word) 0x3320646e)
#define C2 ((Word) 0x79622d32)
#define C3 ((Word) 0x6b206574)
