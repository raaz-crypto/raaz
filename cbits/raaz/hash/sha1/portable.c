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

#include <raaz/primitives/load.h>
#include <stdint.h>

typedef uint32_t   Word;  /* basic unit of sha1 hash    */
#define HASH_SIZE  5      /* Number of words in a Hash  */
#define BLOCK_SIZE 16     /* Number of words in a block */


typedef Word Hash [ HASH_SIZE  ];
typedef Word Block[ BLOCK_SIZE ];

void raazHashSha1PortableCompress(Hash hash, int nblocks, Block *mesg);

/* WARNING: Macro variables not protected use only simple
 * expressions.
 *
 * Notes to Developers: Lot of the code is just repetative loop
 * unrollings.  The comment after these blocks contain elisp macros
 * that generate them (with some tweaks). Preserve these of ease of
 * updating the code.
 *
*/

#define RotateL(x,n)  ((x << n)  | (x >> (32 - (n))))
#define RotL30(x)    ((x << 30) | (x >> 2))
#define RotL1(x)     ((x << 1)  | (x >> 31))
#define RotL5(x)     ((x << 5)  | (x >> 27))

/* The round constants */
#define K0  0x5a827999
#define K20 0x6ed9eba1
#define K40 0x8f1bbcdc
#define K60 0xca62c1d6

/* The round functions */
#define F0(x,y,z)  CH(x,y,z)
#define F20(x,y,z) PARITY(x,y,z)
#define F40(x,y,z) MAJ(x,y,z)
#define F60(x,y,z) PARITY(x,y,z)

#define CH(x,y,z)     ((x & y) ^ (~x & z))
#define PARITY(x,y,z) (x^y^z)
#define MAJ(x,y,z)    ((x & (y | z)) | (y & z))

/* One step in the hash function

   a'  = (rotateL a 5 + (f t) b c d + e + k t + w0)
   b'  = a
   c'  = rotateL b 30
   d'  = c
   e'  = d

Notice the values of a,c,d are carried over but b and e gets updated.

*/


#define Step(a,b,c,d,e,w)                       \
    {                                           \
        e += RotL5(a) + F(b,c,d) + K + w;       \
        b =  RotL30(b);                         \
    }                                           \

/* Message scheduling is done as

   w16 = rotateL (w13 `xor` w8 `xor` w2 `xor` w0) 1

*/

/* Message scheduling */
#define SCHEDULE                                        \
    {                                                   \
        w0 ^= w13 ^ w8 ^ w2; w0  = RotL1(w0);           \
        w1 ^= w14 ^ w9 ^ w3; w1  = RotL1(w1);           \
        w2 ^= w15 ^ w10 ^ w4; w2  = RotL1(w2);          \
        w3 ^= w0 ^ w11 ^ w5; w3  = RotL1(w3);           \
        w4 ^= w1 ^ w12 ^ w6; w4  = RotL1(w4);           \
        w5 ^= w2 ^ w13 ^ w7; w5  = RotL1(w5);           \
        w6 ^= w3 ^ w14 ^ w8; w6  = RotL1(w6);           \
        w7 ^= w4 ^ w15 ^ w9; w7  = RotL1(w7);           \
        w8 ^= w5 ^ w0 ^ w10; w8  = RotL1(w8);           \
        w9 ^= w6 ^ w1 ^ w11; w9  = RotL1(w9);           \
        w10 ^= w7 ^ w2 ^ w12; w10  = RotL1(w10);        \
        w11 ^= w8 ^ w3 ^ w13; w11  = RotL1(w11);        \
        w12 ^= w9 ^ w4 ^ w14; w12  = RotL1(w12);        \
        w13 ^= w10 ^ w5 ^ w15; w13  = RotL1(w13);       \
        w14 ^= w11 ^ w6 ^ w0; w14  = RotL1(w14);        \
        w15 ^= w12 ^ w7 ^ w1; w15  = RotL1(w15);        \
    }

/*
  (dotimes (i 16)
    (setq j (% (+ i 13) 16))
    (setq k (% (+ i 8)  16))
    (setq l (% (+ i 2)  16))
    (insert (format "w%d ^= w%d ^ w%d ^ w%d; " i j k l))
    (insert (format "w%d  = RotL1(w%d);\\\n" i i)))
*/


/*

   This is the compress routine of sha1. It is safe in the sense that
   it does not overwrite the message. However, it does overwrite the
   hash array.

*/

void raazHashSha1PortableCompress(Hash hash, int nblocks, Block *mesg)
{

    register Word a,b,c,d,e; /* Stores the hash state  */

    /*
      The message variables:

      (dotimes (i 16)(insert (format "Word w%d;\n" i)))

      Why not an array? Memory wise these two will be more or less
      same as local arrays will be allocated on stack. However in
      machines with a large number of general purpose registers the
      compiler has a chance of allocating all of them to registers
      making them faster. It might also improve cache hits.

    */

    Word w0;
    Word w1;
    Word w2;
    Word w3;
    Word w4;
    Word w5;
    Word w6;
    Word w7;
    Word w8;
    Word w9;
    Word w10;
    Word w11;
    Word w12;
    Word w13;
    Word w14;
    Word w15;

    while (nblocks > 0)
    {
        /* initialisation of the hash state */
        a = hash[0]; b = hash[1]; c = hash[2]; d = hash[3]; e = hash[4];

        /* Reading in the message

           (dotimes (i 16)
             (insert (format "w%d = raazLoad32BE( (Word *) mesg, %d);\n" i i)))

        */

        w0 = raazLoad32BE( (Word *) mesg, 0);
        w1 = raazLoad32BE( (Word *) mesg, 1);
        w2 = raazLoad32BE( (Word *) mesg, 2);
        w3 = raazLoad32BE( (Word *) mesg, 3);
        w4 = raazLoad32BE( (Word *) mesg, 4);
        w5 = raazLoad32BE( (Word *) mesg, 5);
        w6 = raazLoad32BE( (Word *) mesg, 6);
        w7 = raazLoad32BE( (Word *) mesg, 7);
        w8 = raazLoad32BE( (Word *) mesg, 8);
        w9 = raazLoad32BE( (Word *) mesg, 9);
        w10 = raazLoad32BE( (Word *) mesg, 10);
        w11 = raazLoad32BE( (Word *) mesg, 11);
        w12 = raazLoad32BE( (Word *) mesg, 12);
        w13 = raazLoad32BE( (Word *) mesg, 13);
        w14 = raazLoad32BE( (Word *) mesg, 14);
        w15 = raazLoad32BE( (Word *) mesg, 15);

        /* End of reading the message */

#undef K
#undef F
#define K K0
#define F F0

        /* 0-4 */
        Step(a,b,c,d,e,w0 );
        Step(e,a,b,c,d,w1 );
        Step(d,e,a,b,c,w2 );
        Step(c,d,e,a,b,w3 );
        Step(b,c,d,e,a,w4 );

        /* 5-9 */
        Step(a,b,c,d,e,w5 );
        Step(e,a,b,c,d,w6 );
        Step(d,e,a,b,c,w7 );
        Step(c,d,e,a,b,w8 );
        Step(b,c,d,e,a,w9 );

        /* 10-14 */
        Step(a,b,c,d,e,w10);
        Step(e,a,b,c,d,w11);
        Step(d,e,a,b,c,w12);
        Step(c,d,e,a,b,w13);
        Step(b,c,d,e,a,w14);

        /* 15-19 */
        Step(a,b,c,d,e,w15); SCHEDULE;
        Step(e,a,b,c,d,w0 );
        Step(d,e,a,b,c,w1 );
        Step(c,d,e,a,b,w2 );
        Step(b,c,d,e,a,w3 );

#undef K
#undef F
#define K K20
#define F F20

        /* 20-24 */
        Step(a,b,c,d,e,w4 );
        Step(e,a,b,c,d,w5 );
        Step(d,e,a,b,c,w6 );
        Step(c,d,e,a,b,w7 );
        Step(b,c,d,e,a,w8 );

        /* 25-29 */
        Step(a,b,c,d,e,w9 );
        Step(e,a,b,c,d,w10);
        Step(d,e,a,b,c,w11);
        Step(c,d,e,a,b,w12);
        Step(b,c,d,e,a,w13);

        /* 30-34 */
        Step(a,b,c,d,e,w14);
        Step(e,a,b,c,d,w15); SCHEDULE;
        Step(d,e,a,b,c,w0 );
        Step(c,d,e,a,b,w1 );
        Step(b,c,d,e,a,w2 );

        /* 35-39 */
        Step(a,b,c,d,e,w3 );
        Step(e,a,b,c,d,w4 );
        Step(d,e,a,b,c,w5 );
        Step(c,d,e,a,b,w6 );
        Step(b,c,d,e,a,w7 );

#undef K
#undef F
#define K K40
#define F F40

        /* 40-44 */

        Step(a,b,c,d,e,w8 );
        Step(e,a,b,c,d,w9 );
        Step(d,e,a,b,c,w10);
        Step(c,d,e,a,b,w11);
        Step(b,c,d,e,a,w12);

        /* 45-49 */
        Step(a,b,c,d,e,w13);
        Step(e,a,b,c,d,w14);
        Step(d,e,a,b,c,w15); SCHEDULE;
        Step(c,d,e,a,b,w0 );
        Step(b,c,d,e,a,w1 );

        /* 50-54 */
        Step(a,b,c,d,e,w2 );
        Step(e,a,b,c,d,w3 );
        Step(d,e,a,b,c,w4 );
        Step(c,d,e,a,b,w5 );
        Step(b,c,d,e,a,w6 );

        /* 55-59 */
        Step(a,b,c,d,e,w7 );
        Step(e,a,b,c,d,w8 );
        Step(d,e,a,b,c,w9 );
        Step(c,d,e,a,b,w10);
        Step(b,c,d,e,a,w11);

#undef K
#undef F
#define K K60
#define F F60

        /* 60-64 */
        Step(a,b,c,d,e,w12);
        Step(e,a,b,c,d,w13);
        Step(d,e,a,b,c,w14);
        Step(c,d,e,a,b,w15); SCHEDULE;
        Step(b,c,d,e,a,w0 );

        /* 65-69 */
        Step(a,b,c,d,e,w1 );
        Step(e,a,b,c,d,w2 );
        Step(d,e,a,b,c,w3 );
        Step(c,d,e,a,b,w4 );
        Step(b,c,d,e,a,w5 );

        /* 70-74 */
        Step(a,b,c,d,e,w6 );
        Step(e,a,b,c,d,w7 );
        Step(d,e,a,b,c,w8 );
        Step(c,d,e,a,b,w9 );
        Step(b,c,d,e,a,w10);

        /* 75-79 */
        Step(a,b,c,d,e,w11);
        Step(e,a,b,c,d,w12);
        Step(d,e,a,b,c,w13);
        Step(c,d,e,a,b,w14);
        Step(b,c,d,e,a,w15);

        /* Update the hash */
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;

        /* Move to next block */
        --nblocks; ++mesg;
    }
    return;
}
