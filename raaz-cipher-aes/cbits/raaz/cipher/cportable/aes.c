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

#define RotateL1(x,temp) \
  {                      \
    (temp) = (x)[3];     \
    (x)[3] = (x)[0];     \
    (x)[0] = (x)[1];     \
    (x)[1] = (x)[2];     \
    (x)[2] = (temp);     \
  }                      \

#define RotateL2(x,temp) \
  {                      \
    (temp) = (x)[0];     \
    (x)[0] = (x)[2];     \
    (x)[2] = (temp);     \
    (temp) = (x)[1];     \
    (x)[1] = (x)[3];     \
    (x)[3] = (temp);     \
  }                      \

#define RotateL3(x,temp) \
  {                      \
    (temp) = (x)[0];     \
    (x)[0] = (x)[3];     \
    (x)[3] = (x)[2];     \
    (x)[2] = (x)[1];     \
    (x)[1] = (temp);     \
  }                      \


/* Copies 4 Word8 between arrays of Word8's */

#define Copy32(to, from)                            \
  {                                                 \
    ((Word32 *)(to))[0] = ((Word32 *)(from))[0];    \
  }                                                 \

#define Copy64(to, from)                            \
  {                                                 \
    ((Word64 *)(to))[0] = ((Word64 *)(from))[0];    \
  }                                                 \

#define Copy128(to, from)                           \
  {                                                 \
    Copy64(to,from);                                \
    Copy64((to)+8, (from)+8);                       \
  }                                                 \


#define Xor32(to, op1, op2)                                               \
  {                                                                       \
    ((Word32 *) (to))[0] = ((Word32 *) (op1))[0] ^ ((Word32 *) (op2))[0]; \
  }                                                                       \

#define Sbox32(to, on)       \
  {                          \
    (to)[0] = sbox[(on)[0]]; \
    (to)[1] = sbox[(on)[1]]; \
    (to)[2] = sbox[(on)[2]]; \
    (to)[3] = sbox[(on)[3]]; \
  }                          \

#define InvSbox32(to, on)        \
  {                              \
    (to)[0] = inv_sbox[(on)[0]]; \
    (to)[1] = inv_sbox[(on)[1]]; \
    (to)[2] = inv_sbox[(on)[2]]; \
    (to)[3] = inv_sbox[(on)[3]]; \
  }                              \

static Word8 sbox[256] = {
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
	0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static Word8 rcon[] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };

static Word8 inv_sbox[256] = {
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
	0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

/* For fast multiplication in GF        */
/* gmult[a][i] = xtime^(i+1)(a)         */


static Word8 gmult[256][6] =
{
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e},
	{0x04, 0x06, 0x12, 0x16, 0x1a, 0x1c}, {0x06, 0x05, 0x1b, 0x1d, 0x17, 0x12},
	{0x08, 0x0c, 0x24, 0x2c, 0x34, 0x38}, {0x0a, 0x0f, 0x2d, 0x27, 0x39, 0x36},
	{0x0c, 0x0a, 0x36, 0x3a, 0x2e, 0x24}, {0x0e, 0x09, 0x3f, 0x31, 0x23, 0x2a},
	{0x10, 0x18, 0x48, 0x58, 0x68, 0x70}, {0x12, 0x1b, 0x41, 0x53, 0x65, 0x7e},
	{0x14, 0x1e, 0x5a, 0x4e, 0x72, 0x6c}, {0x16, 0x1d, 0x53, 0x45, 0x7f, 0x62},
	{0x18, 0x14, 0x6c, 0x74, 0x5c, 0x48}, {0x1a, 0x17, 0x65, 0x7f, 0x51, 0x46},
	{0x1c, 0x12, 0x7e, 0x62, 0x46, 0x54}, {0x1e, 0x11, 0x77, 0x69, 0x4b, 0x5a},
	{0x20, 0x30, 0x90, 0xb0, 0xd0, 0xe0}, {0x22, 0x33, 0x99, 0xbb, 0xdd, 0xee},
	{0x24, 0x36, 0x82, 0xa6, 0xca, 0xfc}, {0x26, 0x35, 0x8b, 0xad, 0xc7, 0xf2},
	{0x28, 0x3c, 0xb4, 0x9c, 0xe4, 0xd8}, {0x2a, 0x3f, 0xbd, 0x97, 0xe9, 0xd6},
	{0x2c, 0x3a, 0xa6, 0x8a, 0xfe, 0xc4}, {0x2e, 0x39, 0xaf, 0x81, 0xf3, 0xca},
	{0x30, 0x28, 0xd8, 0xe8, 0xb8, 0x90}, {0x32, 0x2b, 0xd1, 0xe3, 0xb5, 0x9e},
	{0x34, 0x2e, 0xca, 0xfe, 0xa2, 0x8c}, {0x36, 0x2d, 0xc3, 0xf5, 0xaf, 0x82},
	{0x38, 0x24, 0xfc, 0xc4, 0x8c, 0xa8}, {0x3a, 0x27, 0xf5, 0xcf, 0x81, 0xa6},
	{0x3c, 0x22, 0xee, 0xd2, 0x96, 0xb4}, {0x3e, 0x21, 0xe7, 0xd9, 0x9b, 0xba},
	{0x40, 0x60, 0x3b, 0x7b, 0xbb, 0xdb}, {0x42, 0x63, 0x32, 0x70, 0xb6, 0xd5},
	{0x44, 0x66, 0x29, 0x6d, 0xa1, 0xc7}, {0x46, 0x65, 0x20, 0x66, 0xac, 0xc9},
	{0x48, 0x6c, 0x1f, 0x57, 0x8f, 0xe3}, {0x4a, 0x6f, 0x16, 0x5c, 0x82, 0xed},
	{0x4c, 0x6a, 0x0d, 0x41, 0x95, 0xff}, {0x4e, 0x69, 0x04, 0x4a, 0x98, 0xf1},
	{0x50, 0x78, 0x73, 0x23, 0xd3, 0xab}, {0x52, 0x7b, 0x7a, 0x28, 0xde, 0xa5},
	{0x54, 0x7e, 0x61, 0x35, 0xc9, 0xb7}, {0x56, 0x7d, 0x68, 0x3e, 0xc4, 0xb9},
	{0x58, 0x74, 0x57, 0x0f, 0xe7, 0x93}, {0x5a, 0x77, 0x5e, 0x04, 0xea, 0x9d},
	{0x5c, 0x72, 0x45, 0x19, 0xfd, 0x8f}, {0x5e, 0x71, 0x4c, 0x12, 0xf0, 0x81},
	{0x60, 0x50, 0xab, 0xcb, 0x6b, 0x3b}, {0x62, 0x53, 0xa2, 0xc0, 0x66, 0x35},
	{0x64, 0x56, 0xb9, 0xdd, 0x71, 0x27}, {0x66, 0x55, 0xb0, 0xd6, 0x7c, 0x29},
	{0x68, 0x5c, 0x8f, 0xe7, 0x5f, 0x03}, {0x6a, 0x5f, 0x86, 0xec, 0x52, 0x0d},
	{0x6c, 0x5a, 0x9d, 0xf1, 0x45, 0x1f}, {0x6e, 0x59, 0x94, 0xfa, 0x48, 0x11},
	{0x70, 0x48, 0xe3, 0x93, 0x03, 0x4b}, {0x72, 0x4b, 0xea, 0x98, 0x0e, 0x45},
	{0x74, 0x4e, 0xf1, 0x85, 0x19, 0x57}, {0x76, 0x4d, 0xf8, 0x8e, 0x14, 0x59},
	{0x78, 0x44, 0xc7, 0xbf, 0x37, 0x73}, {0x7a, 0x47, 0xce, 0xb4, 0x3a, 0x7d},
	{0x7c, 0x42, 0xd5, 0xa9, 0x2d, 0x6f}, {0x7e, 0x41, 0xdc, 0xa2, 0x20, 0x61},
	{0x80, 0xc0, 0x76, 0xf6, 0x6d, 0xad}, {0x82, 0xc3, 0x7f, 0xfd, 0x60, 0xa3},
	{0x84, 0xc6, 0x64, 0xe0, 0x77, 0xb1}, {0x86, 0xc5, 0x6d, 0xeb, 0x7a, 0xbf},
	{0x88, 0xcc, 0x52, 0xda, 0x59, 0x95}, {0x8a, 0xcf, 0x5b, 0xd1, 0x54, 0x9b},
	{0x8c, 0xca, 0x40, 0xcc, 0x43, 0x89}, {0x8e, 0xc9, 0x49, 0xc7, 0x4e, 0x87},
	{0x90, 0xd8, 0x3e, 0xae, 0x05, 0xdd}, {0x92, 0xdb, 0x37, 0xa5, 0x08, 0xd3},
	{0x94, 0xde, 0x2c, 0xb8, 0x1f, 0xc1}, {0x96, 0xdd, 0x25, 0xb3, 0x12, 0xcf},
	{0x98, 0xd4, 0x1a, 0x82, 0x31, 0xe5}, {0x9a, 0xd7, 0x13, 0x89, 0x3c, 0xeb},
	{0x9c, 0xd2, 0x08, 0x94, 0x2b, 0xf9}, {0x9e, 0xd1, 0x01, 0x9f, 0x26, 0xf7},
	{0xa0, 0xf0, 0xe6, 0x46, 0xbd, 0x4d}, {0xa2, 0xf3, 0xef, 0x4d, 0xb0, 0x43},
	{0xa4, 0xf6, 0xf4, 0x50, 0xa7, 0x51}, {0xa6, 0xf5, 0xfd, 0x5b, 0xaa, 0x5f},
	{0xa8, 0xfc, 0xc2, 0x6a, 0x89, 0x75}, {0xaa, 0xff, 0xcb, 0x61, 0x84, 0x7b},
	{0xac, 0xfa, 0xd0, 0x7c, 0x93, 0x69}, {0xae, 0xf9, 0xd9, 0x77, 0x9e, 0x67},
	{0xb0, 0xe8, 0xae, 0x1e, 0xd5, 0x3d}, {0xb2, 0xeb, 0xa7, 0x15, 0xd8, 0x33},
	{0xb4, 0xee, 0xbc, 0x08, 0xcf, 0x21}, {0xb6, 0xed, 0xb5, 0x03, 0xc2, 0x2f},
	{0xb8, 0xe4, 0x8a, 0x32, 0xe1, 0x05}, {0xba, 0xe7, 0x83, 0x39, 0xec, 0x0b},
	{0xbc, 0xe2, 0x98, 0x24, 0xfb, 0x19}, {0xbe, 0xe1, 0x91, 0x2f, 0xf6, 0x17},
	{0xc0, 0xa0, 0x4d, 0x8d, 0xd6, 0x76}, {0xc2, 0xa3, 0x44, 0x86, 0xdb, 0x78},
	{0xc4, 0xa6, 0x5f, 0x9b, 0xcc, 0x6a}, {0xc6, 0xa5, 0x56, 0x90, 0xc1, 0x64},
	{0xc8, 0xac, 0x69, 0xa1, 0xe2, 0x4e}, {0xca, 0xaf, 0x60, 0xaa, 0xef, 0x40},
	{0xcc, 0xaa, 0x7b, 0xb7, 0xf8, 0x52}, {0xce, 0xa9, 0x72, 0xbc, 0xf5, 0x5c},
	{0xd0, 0xb8, 0x05, 0xd5, 0xbe, 0x06}, {0xd2, 0xbb, 0x0c, 0xde, 0xb3, 0x08},
	{0xd4, 0xbe, 0x17, 0xc3, 0xa4, 0x1a}, {0xd6, 0xbd, 0x1e, 0xc8, 0xa9, 0x14},
	{0xd8, 0xb4, 0x21, 0xf9, 0x8a, 0x3e}, {0xda, 0xb7, 0x28, 0xf2, 0x87, 0x30},
	{0xdc, 0xb2, 0x33, 0xef, 0x90, 0x22}, {0xde, 0xb1, 0x3a, 0xe4, 0x9d, 0x2c},
	{0xe0, 0x90, 0xdd, 0x3d, 0x06, 0x96}, {0xe2, 0x93, 0xd4, 0x36, 0x0b, 0x98},
	{0xe4, 0x96, 0xcf, 0x2b, 0x1c, 0x8a}, {0xe6, 0x95, 0xc6, 0x20, 0x11, 0x84},
	{0xe8, 0x9c, 0xf9, 0x11, 0x32, 0xae}, {0xea, 0x9f, 0xf0, 0x1a, 0x3f, 0xa0},
	{0xec, 0x9a, 0xeb, 0x07, 0x28, 0xb2}, {0xee, 0x99, 0xe2, 0x0c, 0x25, 0xbc},
	{0xf0, 0x88, 0x95, 0x65, 0x6e, 0xe6}, {0xf2, 0x8b, 0x9c, 0x6e, 0x63, 0xe8},
	{0xf4, 0x8e, 0x87, 0x73, 0x74, 0xfa}, {0xf6, 0x8d, 0x8e, 0x78, 0x79, 0xf4},
	{0xf8, 0x84, 0xb1, 0x49, 0x5a, 0xde}, {0xfa, 0x87, 0xb8, 0x42, 0x57, 0xd0},
	{0xfc, 0x82, 0xa3, 0x5f, 0x40, 0xc2}, {0xfe, 0x81, 0xaa, 0x54, 0x4d, 0xcc},
	{0x1b, 0x9b, 0xec, 0xf7, 0xda, 0x41}, {0x19, 0x98, 0xe5, 0xfc, 0xd7, 0x4f},
	{0x1f, 0x9d, 0xfe, 0xe1, 0xc0, 0x5d}, {0x1d, 0x9e, 0xf7, 0xea, 0xcd, 0x53},
	{0x13, 0x97, 0xc8, 0xdb, 0xee, 0x79}, {0x11, 0x94, 0xc1, 0xd0, 0xe3, 0x77},
	{0x17, 0x91, 0xda, 0xcd, 0xf4, 0x65}, {0x15, 0x92, 0xd3, 0xc6, 0xf9, 0x6b},
	{0x0b, 0x83, 0xa4, 0xaf, 0xb2, 0x31}, {0x09, 0x80, 0xad, 0xa4, 0xbf, 0x3f},
	{0x0f, 0x85, 0xb6, 0xb9, 0xa8, 0x2d}, {0x0d, 0x86, 0xbf, 0xb2, 0xa5, 0x23},
	{0x03, 0x8f, 0x80, 0x83, 0x86, 0x09}, {0x01, 0x8c, 0x89, 0x88, 0x8b, 0x07},
	{0x07, 0x89, 0x92, 0x95, 0x9c, 0x15}, {0x05, 0x8a, 0x9b, 0x9e, 0x91, 0x1b},
	{0x3b, 0xab, 0x7c, 0x47, 0x0a, 0xa1}, {0x39, 0xa8, 0x75, 0x4c, 0x07, 0xaf},
	{0x3f, 0xad, 0x6e, 0x51, 0x10, 0xbd}, {0x3d, 0xae, 0x67, 0x5a, 0x1d, 0xb3},
	{0x33, 0xa7, 0x58, 0x6b, 0x3e, 0x99}, {0x31, 0xa4, 0x51, 0x60, 0x33, 0x97},
	{0x37, 0xa1, 0x4a, 0x7d, 0x24, 0x85}, {0x35, 0xa2, 0x43, 0x76, 0x29, 0x8b},
	{0x2b, 0xb3, 0x34, 0x1f, 0x62, 0xd1}, {0x29, 0xb0, 0x3d, 0x14, 0x6f, 0xdf},
	{0x2f, 0xb5, 0x26, 0x09, 0x78, 0xcd}, {0x2d, 0xb6, 0x2f, 0x02, 0x75, 0xc3},
	{0x23, 0xbf, 0x10, 0x33, 0x56, 0xe9}, {0x21, 0xbc, 0x19, 0x38, 0x5b, 0xe7},
	{0x27, 0xb9, 0x02, 0x25, 0x4c, 0xf5}, {0x25, 0xba, 0x0b, 0x2e, 0x41, 0xfb},
	{0x5b, 0xfb, 0xd7, 0x8c, 0x61, 0x9a}, {0x59, 0xf8, 0xde, 0x87, 0x6c, 0x94},
	{0x5f, 0xfd, 0xc5, 0x9a, 0x7b, 0x86}, {0x5d, 0xfe, 0xcc, 0x91, 0x76, 0x88},
	{0x53, 0xf7, 0xf3, 0xa0, 0x55, 0xa2}, {0x51, 0xf4, 0xfa, 0xab, 0x58, 0xac},
	{0x57, 0xf1, 0xe1, 0xb6, 0x4f, 0xbe}, {0x55, 0xf2, 0xe8, 0xbd, 0x42, 0xb0},
	{0x4b, 0xe3, 0x9f, 0xd4, 0x09, 0xea}, {0x49, 0xe0, 0x96, 0xdf, 0x04, 0xe4},
	{0x4f, 0xe5, 0x8d, 0xc2, 0x13, 0xf6}, {0x4d, 0xe6, 0x84, 0xc9, 0x1e, 0xf8},
	{0x43, 0xef, 0xbb, 0xf8, 0x3d, 0xd2}, {0x41, 0xec, 0xb2, 0xf3, 0x30, 0xdc},
	{0x47, 0xe9, 0xa9, 0xee, 0x27, 0xce}, {0x45, 0xea, 0xa0, 0xe5, 0x2a, 0xc0},
	{0x7b, 0xcb, 0x47, 0x3c, 0xb1, 0x7a}, {0x79, 0xc8, 0x4e, 0x37, 0xbc, 0x74},
	{0x7f, 0xcd, 0x55, 0x2a, 0xab, 0x66}, {0x7d, 0xce, 0x5c, 0x21, 0xa6, 0x68},
	{0x73, 0xc7, 0x63, 0x10, 0x85, 0x42}, {0x71, 0xc4, 0x6a, 0x1b, 0x88, 0x4c},
	{0x77, 0xc1, 0x71, 0x06, 0x9f, 0x5e}, {0x75, 0xc2, 0x78, 0x0d, 0x92, 0x50},
	{0x6b, 0xd3, 0x0f, 0x64, 0xd9, 0x0a}, {0x69, 0xd0, 0x06, 0x6f, 0xd4, 0x04},
	{0x6f, 0xd5, 0x1d, 0x72, 0xc3, 0x16}, {0x6d, 0xd6, 0x14, 0x79, 0xce, 0x18},
	{0x63, 0xdf, 0x2b, 0x48, 0xed, 0x32}, {0x61, 0xdc, 0x22, 0x43, 0xe0, 0x3c},
	{0x67, 0xd9, 0x39, 0x5e, 0xf7, 0x2e}, {0x65, 0xda, 0x30, 0x55, 0xfa, 0x20},
	{0x9b, 0x5b, 0x9a, 0x01, 0xb7, 0xec}, {0x99, 0x58, 0x93, 0x0a, 0xba, 0xe2},
	{0x9f, 0x5d, 0x88, 0x17, 0xad, 0xf0}, {0x9d, 0x5e, 0x81, 0x1c, 0xa0, 0xfe},
	{0x93, 0x57, 0xbe, 0x2d, 0x83, 0xd4}, {0x91, 0x54, 0xb7, 0x26, 0x8e, 0xda},
	{0x97, 0x51, 0xac, 0x3b, 0x99, 0xc8}, {0x95, 0x52, 0xa5, 0x30, 0x94, 0xc6},
	{0x8b, 0x43, 0xd2, 0x59, 0xdf, 0x9c}, {0x89, 0x40, 0xdb, 0x52, 0xd2, 0x92},
	{0x8f, 0x45, 0xc0, 0x4f, 0xc5, 0x80}, {0x8d, 0x46, 0xc9, 0x44, 0xc8, 0x8e},
	{0x83, 0x4f, 0xf6, 0x75, 0xeb, 0xa4}, {0x81, 0x4c, 0xff, 0x7e, 0xe6, 0xaa},
	{0x87, 0x49, 0xe4, 0x63, 0xf1, 0xb8}, {0x85, 0x4a, 0xed, 0x68, 0xfc, 0xb6},
	{0xbb, 0x6b, 0x0a, 0xb1, 0x67, 0x0c}, {0xb9, 0x68, 0x03, 0xba, 0x6a, 0x02},
	{0xbf, 0x6d, 0x18, 0xa7, 0x7d, 0x10}, {0xbd, 0x6e, 0x11, 0xac, 0x70, 0x1e},
	{0xb3, 0x67, 0x2e, 0x9d, 0x53, 0x34}, {0xb1, 0x64, 0x27, 0x96, 0x5e, 0x3a},
	{0xb7, 0x61, 0x3c, 0x8b, 0x49, 0x28}, {0xb5, 0x62, 0x35, 0x80, 0x44, 0x26},
	{0xab, 0x73, 0x42, 0xe9, 0x0f, 0x7c}, {0xa9, 0x70, 0x4b, 0xe2, 0x02, 0x72},
	{0xaf, 0x75, 0x50, 0xff, 0x15, 0x60}, {0xad, 0x76, 0x59, 0xf4, 0x18, 0x6e},
	{0xa3, 0x7f, 0x66, 0xc5, 0x3b, 0x44}, {0xa1, 0x7c, 0x6f, 0xce, 0x36, 0x4a},
	{0xa7, 0x79, 0x74, 0xd3, 0x21, 0x58}, {0xa5, 0x7a, 0x7d, 0xd8, 0x2c, 0x56},
	{0xdb, 0x3b, 0xa1, 0x7a, 0x0c, 0x37}, {0xd9, 0x38, 0xa8, 0x71, 0x01, 0x39},
	{0xdf, 0x3d, 0xb3, 0x6c, 0x16, 0x2b}, {0xdd, 0x3e, 0xba, 0x67, 0x1b, 0x25},
	{0xd3, 0x37, 0x85, 0x56, 0x38, 0x0f}, {0xd1, 0x34, 0x8c, 0x5d, 0x35, 0x01},
	{0xd7, 0x31, 0x97, 0x40, 0x22, 0x13}, {0xd5, 0x32, 0x9e, 0x4b, 0x2f, 0x1d},
	{0xcb, 0x23, 0xe9, 0x22, 0x64, 0x47}, {0xc9, 0x20, 0xe0, 0x29, 0x69, 0x49},
	{0xcf, 0x25, 0xfb, 0x34, 0x7e, 0x5b}, {0xcd, 0x26, 0xf2, 0x3f, 0x73, 0x55},
	{0xc3, 0x2f, 0xcd, 0x0e, 0x50, 0x7f}, {0xc1, 0x2c, 0xc4, 0x05, 0x5d, 0x71},
	{0xc7, 0x29, 0xdf, 0x18, 0x4a, 0x63}, {0xc5, 0x2a, 0xd6, 0x13, 0x47, 0x6d},
	{0xfb, 0x0b, 0x31, 0xca, 0xdc, 0xd7}, {0xf9, 0x08, 0x38, 0xc1, 0xd1, 0xd9},
	{0xff, 0x0d, 0x23, 0xdc, 0xc6, 0xcb}, {0xfd, 0x0e, 0x2a, 0xd7, 0xcb, 0xc5},
	{0xf3, 0x07, 0x15, 0xe6, 0xe8, 0xef}, {0xf1, 0x04, 0x1c, 0xed, 0xe5, 0xe1},
	{0xf7, 0x01, 0x07, 0xf0, 0xf2, 0xf3}, {0xf5, 0x02, 0x0e, 0xfb, 0xff, 0xfd},
	{0xeb, 0x13, 0x79, 0x92, 0xb4, 0xa7}, {0xe9, 0x10, 0x70, 0x99, 0xb9, 0xa9},
	{0xef, 0x15, 0x6b, 0x84, 0xae, 0xbb}, {0xed, 0x16, 0x62, 0x8f, 0xa3, 0xb5},
	{0xe3, 0x1f, 0x5d, 0xbe, 0x80, 0x9f}, {0xe1, 0x1c, 0x54, 0xb5, 0x8d, 0x91},
	{0xe7, 0x19, 0x4f, 0xa8, 0x9a, 0x83}, {0xe5, 0x1a, 0x46, 0xa3, 0x97, 0x8d},
};

#define CopyKey128(to,from)          \
  {                                  \
    Copy128((to), (from));           \
  }                                  \

#define CopyKey192(to,from)          \
  {                                  \
    Copy128((to),(from));            \
    Copy64((to) + 16, (from) + 16);  \
  }                                  \

#define CopyKey256(to,from)             \
  {                                     \
    Copy128((to),(from));               \
    Copy128((to) + 16, (from) + 16);    \
  }                                     \

/* (Word8 state[16], Word8 temp) */

#define Transpose(state,temp)                \
  {                                          \
    (temp)      = (state)[1];                \
    (state)[1]  = (state)[4];                \
    (state)[4]  = (temp);                    \
                                             \
    (temp)      = (state)[2];                \
    (state)[2]  = (state)[8];                \
    (state)[8]  = (temp);                    \
                                             \
    (temp)      = (state)[3];                \
    (state)[3]  = (state)[12];               \
    (state)[12] = (temp);                    \
                                             \
    (temp)      = (state)[6];                \
    (state)[6]  = (state)[9];                \
    (state)[9]  = (temp);                    \
                                             \
    (temp)      = (state)[7];                \
    (state)[7]  = (state)[13];               \
    (state)[13] = (temp);                    \
                                             \
    (temp)      = (state)[11];               \
    (state)[11] = (state)[14];               \
    (state)[14] = (temp);                    \
 }                                           \


/* (Word8 word[4]) */

#define SubRot(word,i,temp)  \
  {                          \
    RotateL1(word,temp);     \
    Sbox32(word,word);       \
    (word)[0] ^= rcon[(i)];  \
	}                          \

void raazCipherAESExpand128 (Word8 *expandedKey, Word8 *key)
{
  size_t size = 16;
  size_t t = size;
  Word8 temp;

  // Round 0
  CopyKey128(expandedKey,key);

  // Round 1
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,1,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;


  // Round 2
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,2,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 3
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,3,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 4
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,4,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 5
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,5,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 6
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,6,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 7
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,7,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 8
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,8,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 9
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,9,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 10
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,10,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);

  t = 0;
  // 0
  Transpose(expandedKey + t, temp);
  t += 16;

  // 1
  Transpose(expandedKey + t, temp);
  t += 16;

  // 2
  Transpose(expandedKey + t, temp);
  t += 16;

  // 3
  Transpose(expandedKey + t, temp);
  t += 16;

  // 4
  Transpose(expandedKey + t, temp);
  t += 16;

  // 5
  Transpose(expandedKey + t, temp);
  t += 16;

  // 6
  Transpose(expandedKey + t, temp);
  t += 16;

  // 7
  Transpose(expandedKey + t, temp);
  t += 16;

  // 8
  Transpose(expandedKey + t, temp);
  t += 16;

  // 9
  Transpose(expandedKey + t, temp);
  t += 16;

  // 10
  Transpose(expandedKey + t, temp);

}

void raazCipherAESExpand192 (Word8 *expandedKey, Word8 *key)
{
  size_t size = 24;
  size_t t = size;
  Word8 temp;

  // Round 0
  CopyKey192(expandedKey,key);

  // Round 1
  Copy32(expandedKey + t, expandedKey + (t - 4));
  // t % size = 1
  SubRot(expandedKey + t,1,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 2
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  // t % size = 2
  SubRot(expandedKey + t,2,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 3
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 4
  Copy32(expandedKey + t, expandedKey + (t - 4));
  // t % size = 3
  SubRot(expandedKey + t,3,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 5
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  // t % size = 4
  SubRot(expandedKey + t,4,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 6
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 7
  Copy32(expandedKey + t, expandedKey + (t - 4));
  // t % size = 5
  SubRot(expandedKey + t,5,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 8
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  // t % size = 6
  SubRot(expandedKey + t,6,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 9
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 10
  Copy32(expandedKey + t, expandedKey + (t - 4));
  // t % size = 7
  SubRot(expandedKey + t,7,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 11
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  // t % size = 8
  SubRot(expandedKey + t,8,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 12
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);

  t = 0;
  // 0
  Transpose(expandedKey + t, temp);
  t += 16;

  // 1
  Transpose(expandedKey + t, temp);
  t += 16;

  // 2
  Transpose(expandedKey + t, temp);
  t += 16;

  // 3
  Transpose(expandedKey + t, temp);
  t += 16;

  // 4
  Transpose(expandedKey + t, temp);
  t += 16;

  // 5
  Transpose(expandedKey + t, temp);
  t += 16;

  // 6
  Transpose(expandedKey + t, temp);
  t += 16;

  // 7
  Transpose(expandedKey + t, temp);
  t += 16;

  // 8
  Transpose(expandedKey + t, temp);
  t += 16;

  // 9
  Transpose(expandedKey + t, temp);
  t += 16;

  // 10
  Transpose(expandedKey + t, temp);
  t += 16;

  // 11
  Transpose(expandedKey + t, temp);
  t += 16;

  // 12
  Transpose(expandedKey + t, temp);

}

void raazCipherAESExpand256 (Word8 *expandedKey, Word8 *key)
{
  size_t size = 32;
  size_t t = size;
  Word8 temp;

  // Round 0
  CopyKey256(expandedKey,key);

  // Round 2
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,1,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 3
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Sbox32(expandedKey + t, expandedKey + t);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 4
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,2,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 5
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Sbox32(expandedKey + t, expandedKey + t);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 6
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,3,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 7
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Sbox32(expandedKey + t, expandedKey + t);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 8
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,4,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 9
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Sbox32(expandedKey + t, expandedKey + t);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 10
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,5,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 11
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Sbox32(expandedKey + t, expandedKey + t);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 12
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,6,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 13
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Sbox32(expandedKey + t, expandedKey + t);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;

  // Round 14
  Copy32(expandedKey + t, expandedKey + (t - 4));
  SubRot(expandedKey + t,7,temp);
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);
  t += 4;
  Copy32(expandedKey + t, expandedKey + (t - 4));
  Xor32(expandedKey + t, expandedKey + (t - size), expandedKey + t);

  t = 0;
  // 0
  Transpose(expandedKey + t, temp);
  t += 16;

  // 1
  Transpose(expandedKey + t, temp);
  t += 16;

  // 2
  Transpose(expandedKey + t, temp);
  t += 16;

  // 3
  Transpose(expandedKey + t, temp);
  t += 16;

  // 4
  Transpose(expandedKey + t, temp);
  t += 16;

  // 5
  Transpose(expandedKey + t, temp);
  t += 16;

  // 6
  Transpose(expandedKey + t, temp);
  t += 16;

  // 7
  Transpose(expandedKey + t, temp);
  t += 16;

  // 8
  Transpose(expandedKey + t, temp);
  t += 16;

  // 9
  Transpose(expandedKey + t, temp);
  t += 16;

  // 10
  Transpose(expandedKey + t, temp);
  t += 16;

  // 11
  Transpose(expandedKey + t, temp);
  t += 16;

  // 12
  Transpose(expandedKey + t, temp);
  t += 16;

  // 13
  Transpose(expandedKey + t, temp);
  t += 16;

  // 14
  Transpose(expandedKey + t, temp);

}

#define gm02(a) gmult[(a)][0]
#define gm03(a) gmult[(a)][1]
#define gm09(a) gmult[(a)][2]
#define gm0b(a) gmult[(a)][3]
#define gm0d(a) gmult[(a)][4]
#define gm0e(a) gmult[(a)][5]

/* (Word8 state[16], Word8 temp[4]) */

#define MixColumn(to0,to1,to2,to3,temp)                                  \
  {                                                                      \
    (temp)[0] = gm02((to0)) ^ gm03((to1)) ^ (to2)       ^ (to3);         \
    (temp)[1] = (to0)       ^ gm02((to1)) ^ gm03((to2)) ^ (to3);         \
    (temp)[2] = (to0)       ^ (to1)       ^ gm02((to2)) ^ gm03((to3));   \
    (temp)[3] = gm03((to0)) ^ (to1)       ^ (to2)       ^ gm02((to3));   \
    (to0) = (temp)[0];                                                   \
    (to1) = (temp)[1];                                                   \
    (to2) = (temp)[2];                                                   \
    (to3) = (temp)[3];                                                   \
  }                                                                      \

/* (Word8 state[16], Word8 temp[4]) */

#define InvMixColumn(to0,to1,to2,to3,temp)                               \
  {                                                                      \
    (temp)[0] = gm0e((to0)) ^ gm0b((to1)) ^ gm0d((to2)) ^ gm09((to3));   \
    (temp)[1] = gm09((to0)) ^ gm0e((to1)) ^ gm0b((to2)) ^ gm0d((to3));   \
    (temp)[2] = gm0d((to0)) ^ gm09((to1)) ^ gm0e((to2)) ^ gm0b((to3));   \
    (temp)[3] = gm0b((to0)) ^ gm0d((to1)) ^ gm09((to2)) ^ gm0e((to3));   \
    (to0) = (temp)[0];                                                   \
    (to1) = (temp)[1];                                                   \
    (to2) = (temp)[2];                                                   \
    (to3) = (temp)[3];                                                   \
  }                                                                      \

/* (Word8 state[16]) */

#define SubBytes(state)            \
  {                                \
    Sbox32((state),(state));       \
    Sbox32((state)+4,(state)+4);   \
    Sbox32((state)+8,(state)+8);   \
    Sbox32((state)+12,(state)+12); \
  }                                \

/* (Word8 state[16]) */

#define InvSubBytes(state)            \
  {                                   \
    InvSbox32((state),(state));       \
    InvSbox32((state)+4,(state)+4);   \
    InvSbox32((state)+8,(state)+8);   \
    InvSbox32((state)+12,(state)+12); \
  }                                   \

/* (Word8 state[16]) */

#define ShiftRows(state,temp) \
{                             \
	RotateL1(state + 4, temp);  \
	RotateL2(state + 8, temp);  \
	RotateL3(state + 12, temp); \
}                             \

/* (Word8 state[16]) */

#define InvShiftRows(state,temp) \
{                                \
	RotateL3(state + 4, temp);     \
	RotateL2(state + 8, temp);     \
	RotateL1(state + 12, temp);    \
}                                \

/* (Word8 state[16], Word8 temp[4]) */

#define MixColumns(state,temp)                                       \
  {                                                                  \
    MixColumn((state)[0],(state)[4],(state)[8],(state)[12],(temp));  \
    MixColumn((state)[1],(state)[5],(state)[9],(state)[13],(temp));  \
    MixColumn((state)[2],(state)[6],(state)[10],(state)[14],(temp)); \
    MixColumn((state)[3],(state)[7],(state)[11],(state)[15],(temp)); \
  }                                                                  \

/* (Word8 state[16], Word8 temp[4]) */

#define InvMixColumns(state,temp)                                       \
  {                                                                     \
    InvMixColumn((state)[0],(state)[4],(state)[8],(state)[12],(temp));  \
    InvMixColumn((state)[1],(state)[5],(state)[9],(state)[13],(temp));  \
    InvMixColumn((state)[2],(state)[6],(state)[10],(state)[14],(temp)); \
    InvMixColumn((state)[3],(state)[7],(state)[11],(state)[15],(temp)); \
  }                                                                     \

/* (Word8 state[16], Word8 roundKey[16]) */

#define AddRoundKey(state,roundKey)               \
  {                                               \
    Xor32((state), (state), (roundKey));          \
    Xor32((state+4), (state+4), (roundKey+4));    \
    Xor32((state+8), (state+8), (roundKey+8));    \
    Xor32((state+12), (state+12), (roundKey+12)); \
  }                                               \

/* (Word8 eKey[4*4*11], Word8 state[16], Word8 temp[4]) */

#define encrypt128(eKey,state,temp)            \
{                                              \
  size_t t = 16;                               \
  /* round 0 */                                \
	AddRoundKey(state, eKey);                    \
                                               \
  /* round 1 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 2 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 3 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
                                               \
  /* round 4 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 5 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 6 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 7 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 8 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 9 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 10 */                               \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  AddRoundKey(state, eKey + t);                \
}                                              \

/* (Word8 eKey[4*4*13], Word8 state[16], Word8 temp[4]) */

#define encrypt192(eKey,state,temp)            \
{                                              \
  size_t t = 16;                               \
  /* round 0 */                                \
	AddRoundKey(state, eKey);                    \
                                               \
  /* round 1 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 2 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 3 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
                                               \
  /* round 4 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 5 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 6 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 7 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 8 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 9 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 10 */                               \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 11 */                               \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 12 */                               \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  AddRoundKey(state, eKey + t);                \
}                                              \

/* (Word8 eKey[4*4*15], Word8 state[16], Word8 temp[4]) */

#define encrypt256(eKey,state,temp)            \
{                                              \
  size_t t = 16;                               \
  /* round 0 */                                \
	AddRoundKey(state, eKey);                    \
                                               \
  /* round 1 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 2 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 3 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
                                               \
  /* round 4 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 5 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 6 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 7 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 8 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 9 */                                \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 10 */                               \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 11 */                               \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 12 */                               \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 13 */                               \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  MixColumns(state,temp);                      \
  AddRoundKey(state, eKey + t);                \
  t += 16;                                     \
                                               \
  /* round 14 */                               \
  SubBytes(state);                             \
  ShiftRows(state,temp[0]);                    \
  AddRoundKey(state, eKey + t);                \
}                                              \


/* (Word8 eKey[4*4*11], Word8 state[16], Word8 temp[4]) */

#define decrypt128(eKey,state,temp)            \
{                                              \
  size_t t = 160;                              \
  /* round 0 */                                \
	AddRoundKey(state, eKey + t);                \
  t -= 16;                                     \
                                               \
  /* round 1 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 2 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 3 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 4 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 5 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 6 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 7 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 8 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 9 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 10 */                               \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
}                                              \

/* (Word8 eKey[4*4*13], Word8 state[16], Word8 temp[4]) */

#define decrypt192(eKey,state,temp)            \
{                                              \
  size_t t = 192;                              \
  /* round 0 */                                \
	AddRoundKey(state, eKey + t);                \
  t -= 16;                                     \
                                               \
  /* round 1 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 2 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 3 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 4 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 5 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 6 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 7 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 8 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 9 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 10 */                               \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 11 */                               \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 12 */                               \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
}                                              \

/* (Word8 eKey[4*4*15], Word8 state[16], Word8 temp[4]) */

#define decrypt256(eKey,state,temp)            \
{                                              \
  size_t t = 224;                              \
  /* round 0 */                                \
	AddRoundKey(state, eKey + t);                \
  t -= 16;                                     \
                                               \
  /* round 1 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 2 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 3 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 4 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 5 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 6 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 7 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 8 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 9 */                                \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 10 */                               \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 11 */                               \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 12 */                               \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 13 */                               \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
  InvMixColumns(state,temp);                   \
  t -= 16;                                     \
                                               \
  /* round 14 */                               \
  InvShiftRows(state,temp[0]);                 \
  InvSubBytes(state);                          \
  AddRoundKey(state, eKey + t);                \
}                                              \

void raazCipherAESBlockEncrypt128(Word8 *key, Word8 *block, Word8 temp[4])
{
  Transpose(block,temp[0]);
  encrypt128(key,block,temp);
  Transpose(block,temp[0]);
}

void raazCipherAESBlockEncrypt192(Word8 *key, Word8 *block, Word8 temp[4])
{
  Transpose(block,temp[0]);
  encrypt192(key,block,temp);
  Transpose(block,temp[0]);
}

void raazCipherAESBlockEncrypt256(Word8 *key, Word8 *block, Word8 temp[4])
{
  Transpose(block,temp[0]);
  encrypt256(key,block,temp);
  Transpose(block,temp[0]);
}

void raazCipherAESBlockDecrypt128(Word8 *key, Word8 *block, Word8 temp[4])
{
  Transpose(block,temp[0]);
  decrypt128(key,block,temp);
  Transpose(block,temp[0]);
}

void raazCipherAESBlockDecrypt192(Word8 *key, Word8 *block, Word8 temp[4])
{
  Transpose(block,temp[0]);
  decrypt192(key,block,temp);
  Transpose(block,temp[0]);
}

void raazCipherAESBlockDecrypt256(Word8 *key, Word8 *block, Word8 temp[4])
{
  Transpose(block,temp[0]);
  decrypt256(key,block,temp);
  Transpose(block,temp[0]);
}

void raazCipherAESEncryptECB128(Word8 *key, Word8 *input, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input;
  while(nblocks >0){
    raazCipherAESBlockEncrypt128(key,ptr,temp);
    ptr += 16;
    nblocks --;
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESEncryptECB192(Word8 *key, Word8 *input, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input;
  while(nblocks >0){
    raazCipherAESBlockEncrypt192(key,ptr,temp);
    ptr += 16;
    nblocks --;
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESEncryptECB256(Word8 *key, Word8 *input, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input;
  while(nblocks >0){
    raazCipherAESBlockEncrypt256(key,ptr,temp);
    ptr += 16;
    nblocks --;
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESDecryptECB128(Word8 *key, Word8 *input, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input;
  while(nblocks > 0){
    raazCipherAESBlockDecrypt128(key,ptr,temp);
    ptr += 16;
    nblocks --;
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESDecryptECB192(Word8 *key, Word8 *input, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input;
  while(nblocks > 0){
    raazCipherAESBlockDecrypt192(key,ptr,temp);
    ptr += 16;
    nblocks --;
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESDecryptECB256(Word8 *key, Word8 *input, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input;
  while(nblocks > 0){
    raazCipherAESBlockDecrypt256(key,ptr,temp);
    ptr += 16;
    nblocks --;
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

#define Xor128(to,op1,op2)                                              \
  {                                                                     \
  ((Word64 *) (to))[0] = ((Word64 *) (op1))[0] ^ ((Word64 *) (op2))[0]; \
  ((Word64 *) (to))[1] = ((Word64 *) (op1))[1] ^ ((Word64 *) (op2))[1]; \
  }                                                                     \

void raazCipherAESEncryptCBC128(Word8 *key, Word8 *input, Word8 *iv, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input;
  if(nblocks > 0) {
    Xor128(ptr,ptr,iv);
    raazCipherAESBlockEncrypt128(key,ptr,temp);
    ptr += 16;
    nblocks--;
  }
  while(nblocks > 0){
    Xor128(ptr,ptr,ptr-16);
    raazCipherAESBlockEncrypt128(key,ptr,temp);
    ptr += 16;
    nblocks--;
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESEncryptCBC192(Word8 *key, Word8 *input, Word8 *iv, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input;
  if(nblocks > 0) {
    Xor128(ptr,ptr,iv);
    raazCipherAESBlockEncrypt192(key,ptr,temp);
    ptr += 16;
    nblocks--;
  }
  while(nblocks > 0){
    Xor128(ptr,ptr,ptr-16);
    raazCipherAESBlockEncrypt192(key,ptr,temp);
    ptr += 16;
    nblocks--;
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESEncryptCBC256(Word8 *key, Word8 *input, Word8 *iv, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input;
  if(nblocks > 0) {
    Xor128(ptr,ptr,iv);
    raazCipherAESBlockEncrypt256(key,ptr,temp);
    ptr += 16;
    nblocks--;
  }
  while(nblocks > 0){
    Xor128(ptr,ptr,ptr-16);
    raazCipherAESBlockEncrypt256(key,ptr,temp);
    ptr += 16;
    nblocks--;
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESDecryptCBC128(Word8 *key, Word8 *input, Word8 *iv, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input + (nblocks - 1)*16;
  while(nblocks > 1){
    raazCipherAESBlockDecrypt128(key,ptr,temp);
    Xor128(ptr,ptr,ptr-16);
    ptr -= 16;
    nblocks--;
  }
  if(nblocks > 0) {
    raazCipherAESBlockDecrypt128(key,ptr,temp);
    Xor128(ptr,ptr,iv);
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESDecryptCBC192(Word8 *key, Word8 *input, Word8 *iv, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input + (nblocks - 1)*16;
  while(nblocks > 1){
    raazCipherAESBlockDecrypt192(key,ptr,temp);
    Xor128(ptr,ptr,ptr-16);
    ptr -= 16;
    nblocks--;
  }
  if(nblocks > 0) {
    raazCipherAESBlockDecrypt192(key,ptr,temp);
    Xor128(ptr,ptr,iv);
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESDecryptCBC256(Word8 *key, Word8 *input, Word8 *iv, Word32 nblocks)
{
  Word8 temp[4];
  Word8 *ptr;
  ptr = input + (nblocks - 1)*16;
  while(nblocks > 1){
    raazCipherAESBlockDecrypt256(key,ptr,temp);
    Xor128(ptr,ptr,ptr-16);
    ptr -= 16;
    nblocks--;
  }
  if(nblocks > 0) {
    raazCipherAESBlockDecrypt256(key,ptr,temp);
    Xor128(ptr,ptr,iv);
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

#define Incr128(ptr)       \
{                          \
  if (++((ptr)[15]) == 0)  \
  if (++((ptr)[14]) == 0)  \
  if (++((ptr)[13]) == 0)  \
  if (++((ptr)[12]) == 0)  \
  if (++((ptr)[11]) == 0)  \
  if (++((ptr)[10]) == 0)  \
  if (++((ptr)[9]) == 0)   \
  if (++((ptr)[8]) == 0)   \
  if (++((ptr)[7]) == 0)   \
  if (++((ptr)[6]) == 0)   \
  if (++((ptr)[5]) == 0)   \
  if (++((ptr)[4]) == 0)   \
  if (++((ptr)[3]) == 0)   \
  if (++((ptr)[2]) == 0)   \
  if (++((ptr)[1]) == 0)   \
  ++((ptr)[0]);            \
}                          \

/* Modifies iv pointer by xorring with the counter */
void raazCipherAESEncryptCTR128(Word8 *key, Word8 *input, Word8 *iv, Word32 len)
{
  Word8 temp[4];
  Word8 temparea[16];
  Word32 nblocks = len / 16;
  Word8 extra = len % 16;
  int i=0;
  Word8 *ptr, *block;
  block = temparea;
  ptr = input;
  while(nblocks > 0){
    Copy128(block,iv);
    raazCipherAESBlockEncrypt128(key,block,temp);
    Xor128(ptr,ptr,block);
    Incr128(iv);
    ptr += 16;
    nblocks--;
  }
  if (extra > 0) {
    Copy128(block,iv);
    raazCipherAESBlockEncrypt128(key,block,temp);
    for(i=0;i<extra;i++){
      ptr[i] = ptr[i] ^ block[i];
    }
    Incr128(iv);
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}


void raazCipherAESEncryptCTR192(Word8 *key, Word8 *input, Word8 *iv, Word32 len)
{
  Word8 temp[4];
  Word8 temparea[16];
  Word32 nblocks = len / 16;
  Word8 extra = len % 16;
  int i=0;
  Word8 *ptr, *block;
  block = temparea;
  ptr = input;
  while(nblocks > 0){
    Copy128(block,iv);
    raazCipherAESBlockEncrypt192(key,block,temp);
    Xor128(ptr,ptr,block);
    Incr128(iv);
    ptr += 16;
    nblocks--;
  }
  if (extra > 0) {
    Copy128(block,iv);
    raazCipherAESBlockEncrypt192(key,block,temp);
    for(i=0;i<extra;i++){
      ptr[i] = ptr[i] ^ block[i];
    }
    Incr128(iv);
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}

void raazCipherAESEncryptCTR256(Word8 *key, Word8 *input, Word8 *iv, Word32 len)
{
  Word8 temp[4];
  Word8 temparea[16];
  Word32 nblocks = len / 16;
  Word8 extra = len % 16;
  int i=0;
  Word8 *ptr, *block;
  block = temparea;
  ptr = input;
  while(nblocks > 0){
    Copy128(block,iv);
    raazCipherAESBlockEncrypt256(key,block,temp);
    Xor128(ptr,ptr,block);
    Incr128(iv);
    ptr += 16;
    nblocks--;
  }
  if (extra > 0) {
    Copy128(block,iv);
    raazCipherAESBlockEncrypt256(key,block,temp);
    for(i=0;i<extra;i++){
      ptr[i] = ptr[i] ^ block[i];
    }
    Incr128(iv);
  }
  /* Wipe out memory */
  temp[0] = 0;
  temp[1] = 0;
  temp[2] = 0;
  temp[3] = 0;
}


/* int main(){ */
/*   Word8 expan[240]; */
/*   //Word8 key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}; */
/*   //Word8 key[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b}; */
/*   //Word8 key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}; */
/*   //Word8 inp[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}; */
/*   Word8 inp[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}; */
/*   Word8 key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}; */
/*   raazCipherAESExpand256(expan,key); */
/*   Word8 temp[4]; */
/*   int i; */
/*   for(i=0;i<16;++i) */
/*     printf ("%" PRIx8 " ",inp[i]); */
/*   printf("\n"); */
/*   printf("Encrypting\n"); */
/*   raazCipherAESEncrypt256(expan,inp,temp); */
/*   printf("Encrypted\n"); */
/*   for(i=0;i<16;++i) */
/*     printf ("%" PRIx8 " ",inp[i]); */
/*   printf("\n"); */

/*   printf("Decrypting\n"); */
/*   raazCipherAESDecrypt256(expan,inp,temp); */
/*   printf("Decrypted\n"); */

/*   for(i=0;i<16;++i) */
/*     printf ("%" PRIx8 " ",inp[i]); */
/*   printf("\n"); */

/*   return 0; */
/* } */
