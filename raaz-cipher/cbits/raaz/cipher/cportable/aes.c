/*

Portable C implementation of AES Block Encryption. The implementation
is part of the raaz cryptographic network library and is not meant to
be used as a standalone aes implementation.

Copyright (c) 2013, Satvik Chauhan

All rights reserved.

This software is distributed under the terms and conditions of the
BSD3 license. See the accompanying file LICENSE for exact terms and
condition.

*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

typedef uint8_t  Word8;
typedef uint32_t Word32;
typedef uint64_t Word64;

#define RotateL(x,n)  (((x) << (n))  | ((x) >> (32 - (n))))

typedef enum {KEY128=0, KEY192=1, KEY256=2} KEY;

static const Word32 rcon[] =
{
    0x8d000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000,
    0x40000000, 0x80000000, 0x1b000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000
};

static const Word8 sbox[256] =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
    0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
    0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
    0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
    0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
    0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
    0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
    0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
    0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
    0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
    0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
    0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
    0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
    0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
    0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
    0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


static const Word8 inv_sbox[256] =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81,
    0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e,
    0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23,
    0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66,
    0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72,
    0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65,
    0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46,
    0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca,
    0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91,
    0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
    0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f,
    0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
    0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
    0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93,
    0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
    0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6,
    0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

#define Substitute(with,src,dest)                       \
    {                                                   \
        (dest)  = (with)[((src) >> 24)];                \
        (dest)  = (dest) << 8;                          \
        (dest) |= (with)[(((src) >> 16) & 0x000000ff)]; \
        (dest)  = (dest) << 8;                          \
        (dest) |= (with)[(((src) >> 8) & 0x000000ff)];  \
        (dest)  = (dest) << 8;                          \
        (dest) |= (with)[((src) & 0x000000ff)];         \
    }                                                   \

#define SubByte(src,dest)    Substitute(sbox,src,dest)
#define InvSubByte(src,dest) Substitute(inv_sbox,src,dest)

#define SubBytes(state,newstate)                \
    {                                           \
        SubByte(state[0],newstate[0]);          \
        SubByte(state[1],newstate[1]);          \
        SubByte(state[2],newstate[2]);          \
        SubByte(state[3],newstate[3]);          \
    }

#define InvSubBytes(state,newstate)             \
    {                                           \
        InvSubByte(state[0],newstate[0]);       \
        InvSubByte(state[1],newstate[1]);       \
        InvSubByte(state[2],newstate[2]);       \
        InvSubByte(state[3],newstate[3]);       \
    }

#define ShiftRows(state)                        \
    {                                           \
        (state)[1] = RotateL((state)[1],8);     \
        (state)[2] = RotateL((state)[2],16);    \
        (state)[3] = RotateL((state)[3],24);    \
    }                                           \

#define InvShiftRows(state)                     \
    {                                           \
        (state)[1] = RotateL((state)[1],24);    \
        (state)[2] = RotateL((state)[2],16);    \
        (state)[3] = RotateL((state)[3],8);     \
    }                                           \

/*
  Underlying transform matrix (each entry in binary)is given below:

  00000010, 00000011, 00000001, 00000001
  00000001, 00000010, 00000011, 00000001
  00000001, 00000001, 00000010, 00000011
  00000011, 00000001, 00000001, 00000010

*/

#define MixColumns(state,newstate)                            \
    {                                                         \
        (newstate)[0] = (state)[1] ^ (state)[2] ^ (state)[3]; \
        (newstate)[1] = (state)[0] ^ (state)[2] ^ (state)[3]; \
        (newstate)[2] = (state)[0] ^ (state)[1] ^ (state)[3]; \
        (newstate)[3] = (state)[0] ^ (state)[1] ^ (state)[2]; \
        (state)[0] = Mult02((state)[0]);                      \
        (state)[1] = Mult02((state)[1]);                      \
        (state)[2] = Mult02((state)[2]);                      \
        (state)[3] = Mult02((state)[3]);                      \
        (newstate)[0] ^= (state)[0] ^ (state)[1];             \
        (newstate)[1] ^= (state)[1] ^ (state)[2];             \
        (newstate)[2] ^= (state)[2] ^ (state)[3];             \
        (newstate)[3] ^= (state)[0] ^ (state)[3];             \
    }                                                         \

/*
  Underlying transform matrix (each entry in binary) is given below

  00001110, 00001011, 00001101, 00001001
  00001001, 00001110, 00001011, 00001101
  00001101, 00001001, 00001110, 00001011
  00001011, 00001101, 00001001, 00001110
*/

#define InvMixColumns(state,newstate)                         \
    {                                                         \
        (newstate)[0] = (state)[1] ^ (state)[2] ^ (state)[3]; \
        (newstate)[1] = (state)[0] ^ (state)[2] ^ (state)[3]; \
        (newstate)[2] = (state)[0] ^ (state)[1] ^ (state)[3]; \
        (newstate)[3] = (state)[0] ^ (state)[1] ^ (state)[2]; \
        (state)[0] = Mult02((state)[0]);                      \
        (state)[1] = Mult02((state)[1]);                      \
        (state)[2] = Mult02((state)[2]);                      \
        (state)[3] = Mult02((state)[3]);                      \
        (newstate)[0] ^= (state)[0] ^ (state)[1];             \
        (newstate)[1] ^= (state)[1] ^ (state)[2];             \
        (newstate)[2] ^= (state)[2] ^ (state)[3];             \
        (newstate)[3] ^= (state)[0] ^ (state)[3];             \
        (state)[0] ^= (state)[2] ;                            \
        (state)[1] ^= (state)[3] ;                            \
        (state)[0] = Mult02((state)[0]);                      \
        (state)[1] = Mult02((state)[1]);                      \
        (newstate)[0] ^= (state)[0];                          \
        (newstate)[1] ^= (state)[1];                          \
        (newstate)[2] ^= (state)[0];                          \
        (newstate)[3] ^= (state)[1];                          \
        (state)[0] = Mult02((state)[0]);                      \
        (state)[1] = Mult02((state)[1]);                      \
        (state)[0] ^= (state)[1];                             \
        (newstate)[0] ^= (state)[0];                          \
        (newstate)[1] ^= (state)[0];                          \
        (newstate)[2] ^= (state)[0];                          \
        (newstate)[3] ^= (state)[0];                          \
    }                                                         \

#define AddRoundKey(state,roundKey)    \
    {                                  \
        (state)[0] ^= (roundKey)[0];   \
        (state)[1] ^= (roundKey)[1];   \
        (state)[2] ^= (roundKey)[2];   \
        (state)[3] ^= (roundKey)[3];   \
    }                                  \

/*
  src * x in GF_2[x]/(01{1b})
*/

#define Mult02(src) ((((src) << 1) & 0xfefefefe) ^ ((((src) >> 7) & 0x01010101) * 0x1b))


/*
  Construct a Word32 from 4*Word8
 */
static Word32 constructWord32(Word8 x3, Word8 x2, Word8 x1, Word8 x0)
{
    Word32 x = x3;
    x = x << 8; x += x2;
    x = x << 8; x += x1;
    x = x << 8; x += x0;
    return x;
}

#define copyState(src,dest)                     \
    {                                           \
        (dest)[0] = (src)[0];                   \
        (dest)[1] = (src)[1];                   \
        (dest)[2] = (src)[2];                   \
        (dest)[3] = (src)[3];                   \
    }

static int getnr(Word8 k)
{
    int nr = -1;
    switch(k)
    {
    case KEY128:
        nr = 10;
        break;
    case KEY192:
        nr = 12;
        break;
    case KEY256:
        nr = 14;
        break;
    default:
        printf("Unknown Key type\n");
        exit(1);
    }
    return nr;
}


#define expand(w,sb) ((w) ^ (((Word32)(sbox[(Word8)(sb)])) << 24))

/*
TODO: Use 4 Word32 instead of Array and use register pragma to load them into registers
*/


void raazCipherAESExpand(Word32 *expandedKey, Word8 *key, Word8 k)
{
    switch(k)
    {
    case KEY128:
    {
        const int keysize = 4; // 4 32Bit Words
        const int nrounds = 10+1; // Nr+1 wher Nr = 10
        int i,j,index;
        for(i = 0; i < keysize; i++)
        {
            expandedKey[i] = constructWord32(key[i],key[i+4],key[i+8],key[i+12]);
        }
        for(i = 1; i < nrounds; i++)
        {
            index = i*keysize;
            expandedKey[index] = expand(expandedKey[index-keysize],expandedKey[index-3]) ^ rcon[i];
            expandedKey[index+1] = expand(expandedKey[index+1-keysize],expandedKey[index-2]);
            expandedKey[index+2] = expand(expandedKey[index+2-keysize],expandedKey[index-1]);
            expandedKey[index+3] = expand(expandedKey[index+3-keysize],expandedKey[index-4]);
            for(j = 0; j < keysize; j++)
            {
                expandedKey[index+j] ^= (expandedKey[index+j] >> 8) ^ (expandedKey[index+j] >> 16) ^ (expandedKey[index+j] >> 24);
            }
        }
    }
    break;
    case KEY192: // This is much complex than 128 and 256 word sizes. Idea is to use 8 Word32 to store 24 Word8 and later shift and store.
    {
        const int blocksize = 4; // 4 32Bit Words
        Word32 temp1[8],temp2[8];
        Word32 *prev, *curr, *temp;
        prev = temp1;
        curr = temp2;
        int i,j,index;
        for(i = 0; i < blocksize; i++)
        {
            prev[i] = constructWord32(key[i],key[i+4],key[i+8],key[i+12]);
        }
        for(i = 0; i < blocksize; i++)
        {
            prev[blocksize+i] = constructWord32(0,0,key[i+16],key[i+20]);
        }
        for(i = 0; i < blocksize; i++)
        {
            expandedKey[i] = prev[i];
        }
        index = 4;
        for(i = 1; i < 8; i++)
        {
            curr[0] = expand(prev[0],prev[5]) ^ rcon[i];
            curr[1] = expand(prev[1],prev[6]);
            curr[2] = expand(prev[2],prev[7]);
            curr[3] = expand(prev[3],prev[4]);
            for(j = 0; j < blocksize; j++)
            {
                curr[j] ^= (curr[j] >> 8) ^ (curr[j] >> 16) ^ (curr[j] >> 24);
            }
            curr[4] = prev[4] ^ ((curr[0] << 8) & 0x0000ff00);
            curr[5] = prev[5] ^ ((curr[1] << 8) & 0x0000ff00);
            curr[6] = prev[6] ^ ((curr[2] << 8) & 0x0000ff00);
            curr[7] = prev[7] ^ ((curr[3] << 8) & 0x0000ff00);
            for(j = 0; j < blocksize; j++)
            {
                curr[j+4] ^= (curr[j+4] >> 8);
            }
            if (i % 2 == 1)
            {
                expandedKey[index]   = (prev[4] << 16) | (curr[0] >> 16);
                expandedKey[index+1] = (prev[5] << 16) | (curr[1] >> 16);
                expandedKey[index+2] = (prev[6] << 16) | (curr[2] >> 16);
                expandedKey[index+3] = (prev[7] << 16) | (curr[3] >> 16);
                index += 4;
                expandedKey[index]   = (curr[0] << 16) | curr[4];
                expandedKey[index+1] = (curr[1] << 16) | curr[5];
                expandedKey[index+2] = (curr[2] << 16) | curr[6];
                expandedKey[index+3] = (curr[3] << 16) | curr[7];
                index += 4;
            }
            else
            {
                expandedKey[index]   = curr[0];
                expandedKey[index+1] = curr[1];
                expandedKey[index+2] = curr[2];
                expandedKey[index+3] = curr[3];
                index += 4;
            }
            temp = prev;
            prev = curr;
            curr = temp;
        }
        expandedKey[index]     = expand(prev[0],prev[5]) ^ rcon[i];
        expandedKey[index+1] = expand(prev[1],prev[6]);
        expandedKey[index+2] = expand(prev[2],prev[7]);
        expandedKey[index+3] = expand(prev[3],prev[4]);
        for(j = index; j < blocksize + index; j++)
        {
            expandedKey[j] ^= (expandedKey[j] >> 8) ^ (expandedKey[j] >> 16) ^ (expandedKey[j] >> 24);
        }
    }
    break;
    case KEY256:
    {
        const int keysize = 8; // 8 32Bit Words
        const int blocksize = 4; // 4 32Bit Words
        const int nrounds = 14+1;
        int i,j,index;
        for(i = 0; i < blocksize; i++)
        {
            expandedKey[i] = constructWord32(key[i],key[i+4],key[i+8],key[i+12]);
        }
        for(i = 0; i < blocksize; i++)
        {
            expandedKey[blocksize+i] = constructWord32(key[i+16],key[i+20],key[i+24],key[i+28]);
        }
        for(i = 2; i < nrounds; i++)
        {
            index = i*blocksize;
            if(i % 2 == 0)
            {
                expandedKey[index] = expand(expandedKey[index-keysize],expandedKey[index-3]) ^ rcon[i/2];
                expandedKey[index+1] = expand(expandedKey[index+1-keysize],expandedKey[index-2]);
                expandedKey[index+2] = expand(expandedKey[index+2-keysize],expandedKey[index-1]);
                expandedKey[index+3] = expand(expandedKey[index+3-keysize],expandedKey[index-4]);
            }
            else
            {
                expandedKey[index] = expand(expandedKey[index-keysize],expandedKey[index-4]);
                expandedKey[index+1] = expand(expandedKey[index+1-keysize],expandedKey[index-3]);
                expandedKey[index+2] = expand(expandedKey[index+2-keysize],expandedKey[index-2]);
                expandedKey[index+3] = expand(expandedKey[index+3-keysize],expandedKey[index-1]);
            }
            for(j = 0; j < blocksize; j++)
            {
                expandedKey[index+j] ^= (expandedKey[index+j] >> 8) ^ (expandedKey[index+j] >> 16) ^ (expandedKey[index+j] >> 24);
            }
        }
    }
    break;
    default:
        printf("Unknown key type\n");
        exit(1);
    }
}

/*
TODO: Treat data as array of Word32 (with proper endianness) and shift
and load. Not sure if this will improve speed.
*/

void raazCipherAESBlockEncrypt(Word32 *eKey, Word8 *block, Word8 k)
{
    int nr = getnr(k);
    const int blocksize = 4; // Nb = 4
    int i,t;
    Word32 state[blocksize],temp[blocksize];
    // Load into state
    for(i = 0; i < blocksize; i++)
    {
        state[i] = constructWord32(block[i],block[i+4],block[i+8],block[i+12]);
    }
    AddRoundKey(state,eKey);
    for(i = 1, t = blocksize; i < nr; i++, t += blocksize)
    {
        copyState(state,temp);
        SubBytes(temp,state);
        ShiftRows(state);
        copyState(state,temp);
        MixColumns(temp,state);
        AddRoundKey(state,eKey+t);
    }
    copyState(state,temp);
    SubBytes(temp,state);
    ShiftRows(state);
    AddRoundKey(state,eKey+t);
    // Store back into Block
    for(i = 0; i < blocksize; i++)
    {
        block[i+12] = (state[i] & 0x000000ff);
        block[i+8]  = (state[i] & 0x0000ff00) >> 8;
        block[i+4]  = (state[i] & 0x00ff0000) >> 16;
        block[i]    = (state[i] & 0xff000000) >> 24;
    }
}

void raazCipherAESBlockDecrypt(Word32 *eKey, Word8 *block, Word8 k)
{
    int nr = getnr(k);
    const int blocksize = 4; // Nb = 4
    int i,t = nr * blocksize;
    Word32 state[blocksize],temp[blocksize];
    // Load into state
    for(i = 0; i < blocksize; i++)
    {
        state[i] = constructWord32(block[i],block[i+4],block[i+8],block[i+12]);
    }
    AddRoundKey(state,eKey+t);
    t -= blocksize;
    for(i = 1; i < nr; i++, t -= blocksize)
    {
        InvShiftRows(state);
        copyState(state,temp);
        InvSubBytes(temp,state);
        AddRoundKey(state,eKey+t);
        copyState(state,temp);
        InvMixColumns(temp,state);
    }
    InvShiftRows(state);
    copyState(state,temp);
    InvSubBytes(temp,state);
    AddRoundKey(state,eKey+t);
    // Store back into Block
    for(i = 0; i < blocksize; i++)
    {
        block[i+12] = (state[i] & 0x000000ff);
        block[i+8]  = (state[i] & 0x0000ff00) >> 8;
        block[i+4]  = (state[i] & 0x00ff0000) >> 16;
        block[i]    = (state[i] & 0xff000000) >> 24;
    }
}

void raazCipherAESECBEncrypt(Word32 *key, Word8 *input, Word32 nblocks, Word8 k)
{
    while(nblocks > 0)
    {
        raazCipherAESBlockEncrypt(key,input,k);
        input += 16;
        nblocks --;
    }
}

void raazCipherAESECBDecrypt(Word32 *key, Word8 *input, Word32 nblocks, Word8 k)
{
    while(nblocks > 0)
    {
        raazCipherAESBlockDecrypt(key,input,k);
        input += 16;
        nblocks --;
    }
}


#define Xor128(to,op1,op2)                                                    \
    {                                                                         \
        ((Word64 *) (to))[0] = ((Word64 *) (op1))[0] ^ ((Word64 *) (op2))[0]; \
        ((Word64 *) (to))[1] = ((Word64 *) (op1))[1] ^ ((Word64 *) (op2))[1]; \
    }

#define Copy128(to, from)                               \
    {                                                   \
        ((Word64 *) (to))[0] = ((Word64 *) (from))[0];  \
        ((Word64 *) (to))[1] = ((Word64 *) (from))[1];  \
    }

void raazCipherAESCBCEncrypt(Word32 *key, Word8 *input, Word8 *iv, Word32 nblocks, KEY k)
{
    if(nblocks > 0)
    {
        Xor128(input,input,iv);
        raazCipherAESBlockEncrypt(key,input,k);
        input += 16;
        nblocks--;
    }
    while(nblocks > 0)
    {
        Xor128(input,input,input-16);
        raazCipherAESBlockEncrypt(key,input,k);
        input += 16;
        nblocks--;
    }
    Copy128(iv, input - 16);
}

void raazCipherAESCBCDecrypt(Word32 *key, Word8 *input, Word8 *iv, Word32 nblocks, KEY k)
{
    Word8 *ptr;
    ptr = input + (nblocks - 1)*16;
    Word8 *ivCopy = (Word8 *) malloc (16 * sizeof(Word8));
    Copy128(ivCopy, ptr);
    while(nblocks > 1)
    {
        raazCipherAESBlockDecrypt(key,ptr,k);
        Xor128(ptr,ptr,ptr-16);
        ptr -= 16;
        nblocks--;
    }
    if(nblocks > 0)
    {
        raazCipherAESBlockDecrypt(key,ptr,k);
        Xor128(ptr,ptr,iv);
    }
    Copy128(iv, ivCopy);    
}

#define Incr128(ptr)               \
    {                              \
        if (++((ptr)[15]) == 0)    \
        if (++((ptr)[14]) == 0)    \
        if (++((ptr)[13]) == 0)    \
        if (++((ptr)[12]) == 0)    \
        if (++((ptr)[11]) == 0)    \
        if (++((ptr)[10]) == 0)    \
        if (++((ptr)[9]) == 0)     \
        if (++((ptr)[8]) == 0)     \
        if (++((ptr)[7]) == 0)     \
        if (++((ptr)[6]) == 0)     \
        if (++((ptr)[5]) == 0)     \
        if (++((ptr)[4]) == 0)     \
        if (++((ptr)[3]) == 0)     \
        if (++((ptr)[2]) == 0)     \
        if (++((ptr)[1]) == 0)     \
            ++((ptr)[0]);          \
    }                              \

/* Modifies iv pointer by xorring with the counter */
void raazCipherAESCTREncrypt(Word32 *key, Word8 *input, Word8 *iv, Word32 len, KEY k)
{
    Word8 temparea[16];
    Word32 nblocks = len / 16;
    Word8 extra = len % 16;
    int i = 0;
    Word8 *ptr, *block;
    block = temparea;
    ptr = input;
    while(nblocks > 0)
    {
        Copy128(block,iv);
        raazCipherAESBlockEncrypt(key,block,k);
        Xor128(ptr,ptr,block);
        Incr128(iv);
        ptr += 16;
        nblocks--;
    }
    if (extra > 0)
    {
        Copy128(block,iv);
        raazCipherAESBlockEncrypt(key,block,k);
        for(i=0;i<extra;i++)
        {
            ptr[i] = ptr[i] ^ block[i];
        }
        Incr128(iv);
    }
}
