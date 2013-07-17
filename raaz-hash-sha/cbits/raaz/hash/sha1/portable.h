#ifndef __RAAZ_HASH_SHA1_PORTABLE__
#define __RAAZ_HASH_SHA1_PORTABLE__
/*

Portable C implementation of SHA1 hashing. The implementation is part
of the raaz cryptographic network library and is not meant to be used
as a standalone sha1 function.

Copyright (c) 2012, Piyush P Kurur

All rights reserved.

This software is distributed under the terms and conditions of the
BSD3 license. See the accompanying file LICENSE for exact terms and
condition.

*/

#include <stdint.h>

typedef uint32_t   Word;  /* basic unit of sha1 hash    */
#define HASH_SIZE  5      /* Number of words in a Hash  */
#define BLOCK_SIZE 16     /* Number of words in a block */


typedef Word Hash [ HASH_SIZE  ];
typedef Word Block[ BLOCK_SIZE ];

void raazHashSha1PortableCompress(Hash hash, int nblocks, Block *mesg);


#endif /*  __RAAZ_HASH_SHA1_PORTABLE__  */
