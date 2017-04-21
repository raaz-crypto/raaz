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


const Word2b iv2b0 = 0x6a09e667f3bcc908ULL;
const Word2b iv2b1 = 0xbb67ae8584caa73bULL;
const Word2b iv2b2 = 0x3c6ef372fe94f82bULL;
const Word2b iv2b3 = 0xa54ff53a5f1d36f1ULL;
const Word2b iv2b4 = 0x510e527fade682d1ULL;
const Word2b iv2b5 = 0x9b05688c2b3e6c1fULL;
const Word2b iv2b6 = 0x1f83d9abfb41bd6bULL;
const Word2b iv2b7 = 0x5be0cd19137e2179ULL;

const Word2s iv2s0 = 0x6a09e667UL;
const Word2s iv2s1 = 0xbb67ae85UL;
const Word2s iv2s2 = 0x3c6ef372UL;
const Word2s iv2s3 = 0xa54ff53aUL;
const Word2s iv2s4 = 0x510e527fUL;
const Word2s iv2s5 = 0x9b05688cUL;
const Word2s iv2s6 = 0x1f83d9abUL;
const Word2s iv2s7 = 0x5be0cd19UL;
