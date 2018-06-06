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
#include <raaz/cipher/cportable/salsa20.h>

/* Rotate Left */
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

/* Core salsa double round */
#define SalsaRound(x)                                            \
    {                                                            \
        x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9); \
        x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18); \
        x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9); \
        x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18); \
        x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9); \
        x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18); \
        x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9); \
        x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18); \
        x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9); \
        x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18); \
        x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9); \
        x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18); \
        x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9); \
        x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18); \
        x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9); \
        x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18); \
    }                                                            \

/* to = from */
#define Copy16(to,from)    \
    {                      \
        to[0]  = from[0];  \
        to[1]  = from[1];  \
        to[2]  = from[2];  \
        to[3]  = from[3];  \
        to[4]  = from[4];  \
        to[5]  = from[5];  \
        to[6]  = from[6];  \
        to[7]  = from[7];  \
        to[8]  = from[8];  \
        to[9]  = from[9];  \
        to[10] = from[10]; \
        to[11] = from[11]; \
        to[12] = from[12]; \
        to[13] = from[13]; \
        to[14] = from[14]; \
        to[15] = from[15]; \
    }                      \

/* to += from */
#define Add16(to,from)      \
    {                       \
        to[0]  += from[0];  \
        to[1]  += from[1];  \
        to[2]  += from[2];  \
        to[3]  += from[3];  \
        to[4]  += from[4];  \
        to[5]  += from[5];  \
        to[6]  += from[6];  \
        to[7]  += from[7];  \
        to[8]  += from[8];  \
        to[9]  += from[9];  \
        to[10] += from[10]; \
        to[11] += from[11]; \
        to[12] += from[12]; \
        to[13] += from[13]; \
        to[14] += from[14]; \
        to[15] += from[15]; \
    }                       \

void salsa20_20_word(Word32 out[16],Word32 in[16])
{
    Copy16(out,in);
    // Unrolled 20 Salsa20 Rounds
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    Add16(out,in);
}

void salsa20_12_word(Word32 out[16],Word32 in[16])
{
    Copy16(out,in);
    // Unrolled 12 Salsa20 Rounds
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    Add16(out,in);
}

void salsa20_8_word(Word32 out[16],Word32 in[16])
{
    Copy16(out,in);
    // Unrolled 8 Salsa20 Rounds
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    SalsaRound(out);
    Add16(out,in);
}

void expand128(Word32 iv[8],Word32 matrix[16]){
    matrix[0]  = 0x61707865;
    matrix[1]  = raazLoad32LE(iv,0);
    matrix[2]  = raazLoad32LE(iv,1);
    matrix[3]  = raazLoad32LE(iv,2);

    matrix[4]  = raazLoad32LE(iv,3);
    matrix[5]  = 0x3120646e;
    matrix[6]  = raazLoad32LE(iv,4);
    matrix[7]  = raazLoad32LE(iv,5);

    matrix[8]  = raazLoad32LE(iv,6);
    matrix[9]  = raazLoad32LE(iv,7);
    matrix[10] = 0x79622d36;
    matrix[11] = matrix[1];

    matrix[12] = matrix[2];
    matrix[13] = matrix[3];
    matrix[14] = matrix[4];
    matrix[15] = 0x6b206574;
}

void expand256(Word32 iv[12],Word32 matrix[16]){
    matrix[0]  = 0x61707865;
    matrix[1]  = raazLoad32LE(iv,0);
    matrix[2]  = raazLoad32LE(iv,1);
    matrix[3]  = raazLoad32LE(iv,2);

    matrix[4]  = raazLoad32LE(iv,3);
    matrix[5]  = 0x3320646e;
    matrix[6]  = raazLoad32LE(iv,8);
    matrix[7]  = raazLoad32LE(iv,9);

    matrix[8]  = raazLoad32LE(iv,10);
    matrix[9]  = raazLoad32LE(iv,11);
    matrix[10] = 0x79622d32;
    matrix[11] = raazLoad32LE(iv,4);

    matrix[12] = raazLoad32LE(iv,5);
    matrix[13] = raazLoad32LE(iv,6);
    matrix[14] = raazLoad32LE(iv,7);
    matrix[15] = 0x6b206574;
}

static inline void incrCounter(Word32 matrix[16]){
    matrix[8]++;
    if (!matrix[8]) {
      matrix[9]++;
    }
}

void salsa20_20(Word32 matrix[16], Word8 *input, Word32 bytes)
{
    Word32 output[16];
    int i;
    if (!bytes) return;
    while(bytes >= 64){
        salsa20_20_word(output,matrix);
        incrCounter(matrix);
        /* Use 64bit xor operations */
        for (i = 0;i < 8;++i){
            ((Word64*)input)[i] ^= ((Word64 *)output)[i];
        }
        bytes -= 64;
        input += 64;
    }
    if (bytes > 0) {
      salsa20_20_word(output,matrix);
      incrCounter(matrix);
      for (i = 0;i < bytes;++i){
          input[i] ^= ((Word8 *)output)[i];
      }
    }
}

void salsa20_12(Word32 matrix[16], Word8 *input, Word32 bytes)
{
    Word32 output[16];
    int i;
    if (!bytes) return;
    while(bytes >= 64){
        salsa20_12_word(output,matrix);
        incrCounter(matrix);
        /* Use 64bit xor operations */
        for (i = 0;i < 8;++i){
            ((Word64*)input)[i] ^= ((Word64 *)output)[i];
        }
        bytes -= 64;
        input += 64;
    }
    if (bytes > 0) {
      salsa20_12_word(output,matrix);
      incrCounter(matrix);
      for (i = 0;i < bytes;++i){
          input[i] ^= ((Word8 *)output)[i];
      }
    }
}

void salsa20_8(Word32 matrix[16], Word8 *input, Word32 bytes)
{
    Word32 output[16];
    int i;
    if (!bytes) return;
    while(bytes >= 64){
        salsa20_8_word(output,matrix);
        incrCounter(matrix);
        /* Use 64bit xor operations */
        for (i = 0;i < 8;++i){
            ((Word64*)input)[i] ^= ((Word64 *)output)[i];
        }
        bytes -= 64;
        input += 64;
    }
    if (bytes > 0) {
      salsa20_8_word(output,matrix);
      incrCounter(matrix);
      for (i = 0;i < bytes;++i){
          input[i] ^= ((Word8 *)output)[i];
      }
    }
}
