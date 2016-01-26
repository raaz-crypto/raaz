/*

Portable C implementation of SHA512 hashing. The implementation is
part of the raaz cryptographic network library and is not meant to be
used as a standalone sha512 function.

Copyright (c) 2012, Piyush P Kurur and Satvik Chauhan

All rights reserved.

This software is distributed under the terms and conditions of the
BSD3 license. See the accompanying file LICENSE for exact terms and
condition.

*/

#include <raaz/core/endian.h>
#include <stdint.h>

typedef uint64_t   Word;  /* basic unit of sha512 hash  */
#define HASH_SIZE  8      /* Number of words in a Hash  */
#define BLOCK_SIZE 16     /* Number of words in a block */

typedef Word Hash [ HASH_SIZE  ];
typedef Word Block[ BLOCK_SIZE ];

void raazHashSha512PortableCompress(Hash hash, int nblocks, Block *mesg);

/* WARNING: Macro variables not protected use only simple
 * expressions.
 *
 * Notes to Developers: Lot of the code is just repetative loop
 * unrollings.  The comment after these blocks contain elisp macros
 * that generate them (with some tweaks). Preserve these of ease of
 * updating the code.
 *
*/

#define RotateL(x,n)  ((x << n)  | (x >> (64 - (n))))
#define RotateR(x,n)  ((x >> n)  | (x << (64 - (n))))
#define ShiftR(x,n)   ( x >> n )

/* The round constants */

#define K0 0x428a2f98d728ae22
#define K1 0x7137449123ef65cd
#define K2 0xb5c0fbcfec4d3b2f
#define K3 0xe9b5dba58189dbbc
#define K4 0x3956c25bf348b538
#define K5 0x59f111f1b605d019
#define K6 0x923f82a4af194f9b
#define K7 0xab1c5ed5da6d8118
#define K8 0xd807aa98a3030242
#define K9 0x12835b0145706fbe
#define K10 0x243185be4ee4b28c
#define K11 0x550c7dc3d5ffb4e2
#define K12 0x72be5d74f27b896f
#define K13 0x80deb1fe3b1696b1
#define K14 0x9bdc06a725c71235
#define K15 0xc19bf174cf692694
#define K16 0xe49b69c19ef14ad2
#define K17 0xefbe4786384f25e3
#define K18 0x0fc19dc68b8cd5b5
#define K19 0x240ca1cc77ac9c65
#define K20 0x2de92c6f592b0275
#define K21 0x4a7484aa6ea6e483
#define K22 0x5cb0a9dcbd41fbd4
#define K23 0x76f988da831153b5
#define K24 0x983e5152ee66dfab
#define K25 0xa831c66d2db43210
#define K26 0xb00327c898fb213f
#define K27 0xbf597fc7beef0ee4
#define K28 0xc6e00bf33da88fc2
#define K29 0xd5a79147930aa725
#define K30 0x06ca6351e003826f
#define K31 0x142929670a0e6e70
#define K32 0x27b70a8546d22ffc
#define K33 0x2e1b21385c26c926
#define K34 0x4d2c6dfc5ac42aed
#define K35 0x53380d139d95b3df
#define K36 0x650a73548baf63de
#define K37 0x766a0abb3c77b2a8
#define K38 0x81c2c92e47edaee6
#define K39 0x92722c851482353b
#define K40 0xa2bfe8a14cf10364
#define K41 0xa81a664bbc423001
#define K42 0xc24b8b70d0f89791
#define K43 0xc76c51a30654be30
#define K44 0xd192e819d6ef5218
#define K45 0xd69906245565a910
#define K46 0xf40e35855771202a
#define K47 0x106aa07032bbd1b8
#define K48 0x19a4c116b8d2d0c8
#define K49 0x1e376c085141ab53
#define K50 0x2748774cdf8eeb99
#define K51 0x34b0bcb5e19b48a8
#define K52 0x391c0cb3c5c95a63
#define K53 0x4ed8aa4ae3418acb
#define K54 0x5b9cca4f7763e373
#define K55 0x682e6ff3d6b2b8a3
#define K56 0x748f82ee5defb2fc
#define K57 0x78a5636f43172f60
#define K58 0x84c87814a1f0ab72
#define K59 0x8cc702081a6439ec
#define K60 0x90befffa23631e28
#define K61 0xa4506cebde82bde9
#define K62 0xbef9a3f7b2c67915
#define K63 0xc67178f2e372532b
#define K64 0xca273eceea26619c
#define K65 0xd186b8c721c0c207
#define K66 0xeada7dd6cde0eb1e
#define K67 0xf57d4f7fee6ed178
#define K68 0x06f067aa72176fba
#define K69 0x0a637dc5a2c898a6
#define K70 0x113f9804bef90dae
#define K71 0x1b710b35131c471b
#define K72 0x28db77f523047d84
#define K73 0x32caab7b40c72493
#define K74 0x3c9ebe0a15c9bebc
#define K75 0x431d67c49c100d4c
#define K76 0x4cc5d4becb3e42b6
#define K77 0x597f299cfc657e2a
#define K78 0x5fcb6fab3ad6faec
#define K79 0x6c44198c4a475817

/* The round functions */
#define CH(x,y,z)     ((x & y) ^ (~x & z))
#define MAJ(x,y,z)    ((x & (y | z)) | (y & z))

#define SIGB0(x)     (RotateR(x,28) ^ RotateR(x,34) ^ RotateR(x,39))
#define SIGB1(x)     (RotateR(x,14) ^ RotateR(x,18) ^ RotateR(x,41))
#define SIGS0(x)     (RotateR(x,1) ^ RotateR(x,8) ^ ShiftR(x,7))
#define SIGS1(x)     (RotateR(x,19) ^ RotateR(x,61) ^ ShiftR(x,6))

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
    (insert (format "\t\t\tw%d += SIGS1(w%d) + w%d + SIGS0(w%d);\\\n" i j k l)))

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
      w15 += SIGS1(w13) + w8 + SIGS0(w0);              \
    }



/*

   This is the compress routine of sha512. It is safe in the sense
   that it does not overwrite the message. However, it does overwrite
   the hash array.

*/

void raazHashSha512PortableCompress(Hash hash, int nblocks, Block *mesg)
{

    register Word a,b,c,d,e,f,g,h; /* Stores the hash state  */

    register Word temp;

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

    /* Looping over the blocks */
    while (nblocks > 0)
    {
        /* initialisation of the hash state */
        a = hash[0]; b = hash[1]; c = hash[2]; d = hash[3]; e = hash[4];
        f = hash[5]; g = hash[6]; h = hash[7];

        /* Reading in the message

           (dotimes (i 16)
             (insert (format "\t\t\t\tw%d = raazLoad64BE( (Word *) mesg, %d);\n" i i)))

        */

	w0  = raazLoadBE64( (Word *) mesg);
	w1  = raazLoadBE64( (Word *) mesg + 1);
	w2  = raazLoadBE64( (Word *) mesg + 2);
	w3  = raazLoadBE64( (Word *) mesg + 3);
	w4  = raazLoadBE64( (Word *) mesg + 4);
	w5  = raazLoadBE64( (Word *) mesg + 5);
	w6  = raazLoadBE64( (Word *) mesg + 6);
	w7  = raazLoadBE64( (Word *) mesg + 7);
	w8  = raazLoadBE64( (Word *) mesg + 8);
	w9  = raazLoadBE64( (Word *) mesg + 9);
	w10 = raazLoadBE64( (Word *) mesg + 10);
	w11 = raazLoadBE64( (Word *) mesg + 11);
	w12 = raazLoadBE64( (Word *) mesg + 12);
	w13 = raazLoadBE64( (Word *) mesg + 13);
	w14 = raazLoadBE64( (Word *) mesg + 14);
	w15 = raazLoadBE64( (Word *) mesg + 15);


        /* End of reading the message */

        /* 0-79 */
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
        Step(b,c,d,e,f,g,h,a,w15,K63); SCHEDULE;
        Step(a,b,c,d,e,f,g,h,w0,K64);
        Step(h,a,b,c,d,e,f,g,w1,K65);
        Step(g,h,a,b,c,d,e,f,w2,K66);
        Step(f,g,h,a,b,c,d,e,w3,K67);
        Step(e,f,g,h,a,b,c,d,w4,K68);
        Step(d,e,f,g,h,a,b,c,w5,K69);
        Step(c,d,e,f,g,h,a,b,w6,K70);
        Step(b,c,d,e,f,g,h,a,w7,K71);
        Step(a,b,c,d,e,f,g,h,w8,K72);
        Step(h,a,b,c,d,e,f,g,w9,K73);
        Step(g,h,a,b,c,d,e,f,w10,K74);
        Step(f,g,h,a,b,c,d,e,w11,K75);
        Step(e,f,g,h,a,b,c,d,w12,K76);
        Step(d,e,f,g,h,a,b,c,w13,K77);
        Step(c,d,e,f,g,h,a,b,w14,K78);
        Step(b,c,d,e,f,g,h,a,w15,K79);

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
