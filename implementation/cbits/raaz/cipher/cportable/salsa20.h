/*

Portable C implementation of Salsa20 Encryption. The implementation is
part of the raaz cryptographic network library and is not meant to be
used as a standalone aes implementation.

Copyright (c) 2013, Satvik Chauhan

All rights reserved.

This software is distributed under the terms and conditions of the
BSD3 license. See the accompanying file LICENSE for exact terms and
condition.

*/

#ifndef __RAAZ_CIPHER_SALSA_H_
#define __RAAZ_CIPHER_SALSA_H_

#include <raaz/primitives/load.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

typedef uint8_t  Word8;
typedef uint32_t Word32;
typedef uint64_t Word64;

extern void salsa20_20_word(Word32 out[16],Word32 in[16]);
extern void salsa20_12_word(Word32 out[16],Word32 in[16]);
extern void salsa20_8_word(Word32 out[16],Word32 in[16]);
extern void expand128(Word32 iv[8],Word32 matrix[16]);
extern void expand256(Word32 iv[12],Word32 matrix[16]);

extern void salsa20_20(Word32 matrix[16], Word8 *input, Word32 bytes);
extern void salsa20_12(Word32 matrix[16], Word8 *input, Word32 bytes);
extern void salsa20_8(Word32 matrix[16], Word8 *input, Word32 bytes);

#endif
