/*

Portable C implementation of SHA256 hashing. The implementation is
part of the raaz cryptographic network library and is not meant to be
used as a standalone sha256 function.

Copyright (c) 2012, Piyush P Kurur and Satvik Chauhan

All rights reserved.

This software is distributed under the terms and conditions of the
BSD3 license. See the accompanying file LICENSE for exact terms and
condition.

*/

#include <raaz/core/endian.h>
#include <stdint.h>

typedef uint32_t   Word;  /* basic unit of sha256 hash  */
#define HASH_SIZE  8      /* Number of words in a Hash  */
#define BLOCK_SIZE 16     /* Number of words in a block */

typedef Word Hash [ HASH_SIZE  ];
typedef Word Block[ BLOCK_SIZE ];

void raazHashSha256PortableCompress(Hash hash, int nblocks, Block *mesg);

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
#define RotateR(x,n)  ((x >> n)  | (x << (32 - (n))))
#define ShiftR(x,n)   (x >> n)

/* The round constants */

#define K0 0x428a2f98
#define K1 0x71374491
#define K2 0xb5c0fbcf
#define K3 0xe9b5dba5
#define K4 0x3956c25b
#define K5 0x59f111f1
#define K6 0x923f82a4
#define K7 0xab1c5ed5
#define K8 0xd807aa98
#define K9 0x12835b01
#define K10 0x243185be
#define K11 0x550c7dc3
#define K12 0x72be5d74
#define K13 0x80deb1fe
#define K14 0x9bdc06a7
#define K15 0xc19bf174
#define K16 0xe49b69c1
#define K17 0xefbe4786
#define K18 0x0fc19dc6
#define K19 0x240ca1cc
#define K20 0x2de92c6f
#define K21 0x4a7484aa
#define K22 0x5cb0a9dc
#define K23 0x76f988da
#define K24 0x983e5152
#define K25 0xa831c66d
#define K26 0xb00327c8
#define K27 0xbf597fc7
#define K28 0xc6e00bf3
#define K29 0xd5a79147
#define K30 0x06ca6351
#define K31 0x14292967
#define K32 0x27b70a85
#define K33 0x2e1b2138
#define K34 0x4d2c6dfc
#define K35 0x53380d13
#define K36 0x650a7354
#define K37 0x766a0abb
#define K38 0x81c2c92e
#define K39 0x92722c85
#define K40 0xa2bfe8a1
#define K41 0xa81a664b
#define K42 0xc24b8b70
#define K43 0xc76c51a3
#define K44 0xd192e819
#define K45 0xd6990624
#define K46 0xf40e3585
#define K47 0x106aa070
#define K48 0x19a4c116
#define K49 0x1e376c08
#define K50 0x2748774c
#define K51 0x34b0bcb5
#define K52 0x391c0cb3
#define K53 0x4ed8aa4a
#define K54 0x5b9cca4f
#define K55 0x682e6ff3
#define K56 0x748f82ee
#define K57 0x78a5636f
#define K58 0x84c87814
#define K59 0x8cc70208
#define K60 0x90befffa
#define K61 0xa4506ceb
#define K62 0xbef9a3f7
#define K63 0xc67178f2

/* The round functions */
#define CH(x,y,z)     ((x & y) ^ (~x & z))
#define MAJ(x,y,z)    ((x & (y | z)) | (y & z))

#define SIGB0(x)     (RotateR(x,2) ^ RotateR(x,13) ^ RotateR(x,22))
#define SIGB1(x)     (RotateR(x,6) ^ RotateR(x,11) ^ RotateR(x,25))
#define SIGS0(x)     (RotateR(x,7) ^ RotateR(x,18) ^ ShiftR(x,3))
#define SIGS1(x)     (RotateR(x,17) ^ RotateR(x,19) ^ ShiftR(x,10))

/* One step in the hash function

    t1 = h + SIGB1 e + CH e f g + k t + w t
    t2 = SIGB0 a + MAJ a b c
    a' = t1 + t2
    b' = a
    c' = b
    d' = c
    e' = d + t1
    f' = e
    g' = f
    h' = g

Notice the values of a,b,c,e,f,g are carried over but d and h gets updated.

*/

#define Step(a,b,c,d,e,f,g,h,w,k)                 \
    {                                             \
        temp = h + SIGB1(e) + CH(e,f,g) + k + w;  \
        d   += temp;                              \
        h    = temp + SIGB0(a) + MAJ(a,b,c);      \
    }

/* Message scheduling is done as

   w16 = SIGS1(w14) + w9 + SIGS0(w1) + w0

*/

/* Message scheduling

  (dotimes (i 16)
    (setq j (% (+ i 14) 16))
    (setq k (% (+ i 9)  16))
    (setq l (% (+ i 1)  16))
    (insert (format "\t\t\tw%d += SIGS1(w%d) + w%d + SIGS0(w%d); \\\n" i j k l)))

*/

#define SCHEDULE                                        \
    {                                                   \
      w0 += SIGS1(w14) + w9 + SIGS0(w1);                \
      w1 += SIGS1(w15) + w10 + SIGS0(w2);               \
      w2 += SIGS1(w0) + w11 + SIGS0(w3);                \
      w3 += SIGS1(w1) + w12 + SIGS0(w4);                \
      w4 += SIGS1(w2) + w13 + SIGS0(w5);                \
      w5 += SIGS1(w3) + w14 + SIGS0(w6);                \
      w6 += SIGS1(w4) + w15 + SIGS0(w7);                \
      w7 += SIGS1(w5) + w0 + SIGS0(w8);                 \
      w8 += SIGS1(w6) + w1 + SIGS0(w9);                 \
      w9 += SIGS1(w7) + w2 + SIGS0(w10);                \
      w10 += SIGS1(w8) + w3 + SIGS0(w11);               \
      w11 += SIGS1(w9) + w4 + SIGS0(w12);               \
      w12 += SIGS1(w10) + w5 + SIGS0(w13);              \
      w13 += SIGS1(w11) + w6 + SIGS0(w14);              \
      w14 += SIGS1(w12) + w7 + SIGS0(w15);              \
      w15 += SIGS1(w13) + w8 + SIGS0(w0);               \
    }

/*

   This is the compress routine of sha256. It is safe in the sense
   that it does not overwrite the message. However, it does overwrite
   the hash array.

*/

void raazHashSha256PortableCompress(Hash hash, int nblocks, Block *mesg)
{

    register Word a,b,c,d,e,f,g,h; /* Stores the hash state  */

    register Word temp;            /* A temproray variable   */
    /*
      The message variables:

      (dotimes (i 16)(insert (format "\t\tWord w%d;\n" i)))

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

    /* Looping over all the blocks */
    while (nblocks > 0)
    {
        /* initialisation of the hash state */
        a = hash[0]; b = hash[1]; c = hash[2]; d = hash[3]; e = hash[4];
        f = hash[5]; g = hash[6]; h = hash[7];

        /* Reading in the message

           (dotimes (i 16)
             (insert (format "\t\t\t\tw%d = raazLoad32BE( (Word *) mesg, %d);\n" i i)))

        */

        w0  = raazLoadBE32( (Word *) mesg);
        w1  = raazLoadBE32( (Word *) mesg + 1);
        w2  = raazLoadBE32( (Word *) mesg + 2);
        w3  = raazLoadBE32( (Word *) mesg + 3);
        w4  = raazLoadBE32( (Word *) mesg + 4);
        w5  = raazLoadBE32( (Word *) mesg + 5);
        w6  = raazLoadBE32( (Word *) mesg + 6);
        w7  = raazLoadBE32( (Word *) mesg + 7);
        w8  = raazLoadBE32( (Word *) mesg + 8);
        w9  = raazLoadBE32( (Word *) mesg + 9);
        w10 = raazLoadBE32( (Word *) mesg + 10);
        w11 = raazLoadBE32( (Word *) mesg + 11);
        w12 = raazLoadBE32( (Word *) mesg + 12);
        w13 = raazLoadBE32( (Word *) mesg + 13);
        w14 = raazLoadBE32( (Word *) mesg + 14);
        w15 = raazLoadBE32( (Word *) mesg + 15);

        /* End of reading the message */

        /* 0-63 */
        Step(a,b,c,d,e,f,g,h,w0,K0);
        Step(h,a,b,c,d,e,f,g,w1,K1);
        Step(g,h,a,b,c,d,e,f,w2,K2);
        Step(f,g,h,a,b,c,d,e,w3,K3);
        Step(e,f,g,h,a,b,c,d,w4,K4);
        Step(d,e,f,g,h,a,b,c,w5,K5);
        Step(c,d,e,f,g,h,a,b,w6,K6);
        Step(b,c,d,e,f,g,h,a,w7,K7);
        Step(a,b,c,d,e,f,g,h,w8,K8);
        Step(h,a,b,c,d,e,f,g,w9,K9);
        Step(g,h,a,b,c,d,e,f,w10,K10);
        Step(f,g,h,a,b,c,d,e,w11,K11);
        Step(e,f,g,h,a,b,c,d,w12,K12);
        Step(d,e,f,g,h,a,b,c,w13,K13);
        Step(c,d,e,f,g,h,a,b,w14,K14);
        Step(b,c,d,e,f,g,h,a,w15,K15); SCHEDULE;
        Step(a,b,c,d,e,f,g,h,w0,K16);
        Step(h,a,b,c,d,e,f,g,w1,K17);
        Step(g,h,a,b,c,d,e,f,w2,K18);
        Step(f,g,h,a,b,c,d,e,w3,K19);
        Step(e,f,g,h,a,b,c,d,w4,K20);
        Step(d,e,f,g,h,a,b,c,w5,K21);
        Step(c,d,e,f,g,h,a,b,w6,K22);
        Step(b,c,d,e,f,g,h,a,w7,K23);
        Step(a,b,c,d,e,f,g,h,w8,K24);
        Step(h,a,b,c,d,e,f,g,w9,K25);
        Step(g,h,a,b,c,d,e,f,w10,K26);
        Step(f,g,h,a,b,c,d,e,w11,K27);
        Step(e,f,g,h,a,b,c,d,w12,K28);
        Step(d,e,f,g,h,a,b,c,w13,K29);
        Step(c,d,e,f,g,h,a,b,w14,K30);
        Step(b,c,d,e,f,g,h,a,w15,K31); SCHEDULE;
        Step(a,b,c,d,e,f,g,h,w0,K32);
        Step(h,a,b,c,d,e,f,g,w1,K33);
        Step(g,h,a,b,c,d,e,f,w2,K34);
        Step(f,g,h,a,b,c,d,e,w3,K35);
        Step(e,f,g,h,a,b,c,d,w4,K36);
        Step(d,e,f,g,h,a,b,c,w5,K37);
        Step(c,d,e,f,g,h,a,b,w6,K38);
        Step(b,c,d,e,f,g,h,a,w7,K39);
        Step(a,b,c,d,e,f,g,h,w8,K40);
        Step(h,a,b,c,d,e,f,g,w9,K41);
        Step(g,h,a,b,c,d,e,f,w10,K42);
        Step(f,g,h,a,b,c,d,e,w11,K43);
        Step(e,f,g,h,a,b,c,d,w12,K44);
        Step(d,e,f,g,h,a,b,c,w13,K45);
        Step(c,d,e,f,g,h,a,b,w14,K46);
        Step(b,c,d,e,f,g,h,a,w15,K47); SCHEDULE;
        Step(a,b,c,d,e,f,g,h,w0,K48);
        Step(h,a,b,c,d,e,f,g,w1,K49);
        Step(g,h,a,b,c,d,e,f,w2,K50);
        Step(f,g,h,a,b,c,d,e,w3,K51);
        Step(e,f,g,h,a,b,c,d,w4,K52);
        Step(d,e,f,g,h,a,b,c,w5,K53);
        Step(c,d,e,f,g,h,a,b,w6,K54);
        Step(b,c,d,e,f,g,h,a,w7,K55);
        Step(a,b,c,d,e,f,g,h,w8,K56);
        Step(h,a,b,c,d,e,f,g,w9,K57);
        Step(g,h,a,b,c,d,e,f,w10,K58);
        Step(f,g,h,a,b,c,d,e,w11,K59);
        Step(e,f,g,h,a,b,c,d,w12,K60);
        Step(d,e,f,g,h,a,b,c,w13,K61);
        Step(c,d,e,f,g,h,a,b,w14,K62);
        Step(b,c,d,e,f,g,h,a,w15,K63);

        /* Update the hash */
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;

        /* Move to next block */
        --nblocks; ++mesg;
    }
    return;
}
