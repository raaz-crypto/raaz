#pragma once

#include <raaz/core/endian.h>
#include <stdint.h>

#define HASH_SIZE  8
#define BLOCK_SIZE 16

typedef uint64_t Word2b;  /* basic unit for blake2b */
typedef uint32_t Word2s;  /* basic unit for blake2s */


typedef Word2b Blake2b[HASH_SIZE];
typedef Word2b Block2b[BLOCK_SIZE];

typedef Word2s Blake2s[HASH_SIZE];
typedef Word2s Block2s[BLOCK_SIZE];
