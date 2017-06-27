#include <raaz/hash/blake2/common.h>

static inline Word2b R(Word2b x, int i)
{
    return (x << (64 - i)) | (x >> i);
}





# define G(a,b,c,d,m0,m1)		      \
    {					      \
	a += b + m0  ; d ^= a; d = R(d,32);   \
	c += d       ; b ^= c; b = R(b,24);   \
	a += b + m1  ; d ^= a; d = R(d,16);   \
	c += d       ; b ^= c; b = R(b,63);   \
    }



/* Definitions for Blake2b */

# define G0(i,j) G(x0, x4, x8,  x12, w##i, w##j);
# define G1(i,j) G(x1, x5, x9,  x13, w##i, w##j);
# define G2(i,j) G(x2, x6, x10, x14, w##i, w##j);
# define G3(i,j) G(x3, x7, x11, x15, w##i, w##j);

# define G4(i,j) G(x0, x5, x10, x15, w##i, w##j);
# define G5(i,j) G(x1, x6, x11, x12, w##i, w##j);
# define G6(i,j) G(x2, x7, x8,  x13, w##i, w##j);
# define G7(i,j) G(x3, x4, x9,  x14, w##i, w##j);

# define ROUND(i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15) \
	{							      \
	    G0( i0,i1 ); G1( i2 ,i3  ); G2( i4 ,i5  ); G3( i6 ,i7  ); \
	    G4( i8,i9 ); G5( i10,i11 ); G6( i12,i13 ); G7( i14,i15 ); \
	}


/*

This is the block compression algorithm for blake2b. Besides teh usual
suspects there are the following additional parameters.

1. upper  -- The upper 64 bits of the counter
2. lower  -- The lower 64 bits of the counter
3. f0, f1 -- the finalisation flag

*/

# ifdef __GNUC__

typedef Block2b AlignedBlock2b __attribute__ ((aligned (32)));
void raazHashBlake2bPortableBlockCompress(AlignedBlock2b *mesg, int nblocks,
					  Word2b *Upper, Word2b *Lower,
					  Blake2b h)
    __attribute__((optimize("tree-vectorize")));

#endif

#define LOAD(i) (raaz_tole64((*mesg)[(i)]))

void raazHashBlake2bPortableBlockCompress( Block2b *mesg, int nblocks,
					   Word2b *Upper, Word2b *Lower,
					   Blake2b h)
{
    register Word2b x0,  x1,  x2,  x3;  /* row 0  */
    register Word2b x4,  x5,  x6,  x7;  /* row 1  */
    register Word2b x8,  x9,  x10, x11;  /* row 2  */
    register Word2b x12, x13, x14, x15;  /* row 3  */

    /* Input block */
    register Word2b w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    /* Variable that contains the hash */
    Word2b  h0, h1, h2, h3, h4, h5, h6, h7;


    register Word2b upper, lower;
    upper = *Upper;
    lower = *Lower;

    /* Initialisation hash */
    h0 = h[0];
    h1 = h[1];
    h2 = h[2];
    h3 = h[3];
    h4 = h[4];
    h5 = h[5];
    h6 = h[6];
    h7 = h[7];

    while( nblocks > 0)
    {

	/* Initialisation hashes


	   Normally, we would like to put the length increment at the
	   end of the body; somewhere close to the place where we move
	   to the next block. However, when hashing the i-th block of
	   input, we need to set upto the initial value with the total
	   size of data including the i-th block. So we start with an
	   increment the length counter.

	*/


	if (lower > UINT64_MAX - sizeof(Block2b)) { ++upper; } /* Increment the counter */
	lower += sizeof(Block2b);


	x0 = h0;
	x1 = h1;
	x2 = h2;
	x3 = h3;
	x4 = h4;
	x5 = h5;
	x6 = h6;
	x7 = h7;

	/* Initialisation iv  */

	x8  = iv2b0;
	x9  = iv2b1;
	x10 = iv2b2;
	x11 = iv2b3;
	x12 = iv2b4 ^ lower;
	x13 = iv2b5 ^ upper;
	x14 = iv2b6;
	x15 = iv2b7;

	/* Load the block */

	w0  = LOAD(0);
	w1  = LOAD(1);
	w2  = LOAD(2);
	w3  = LOAD(3);
	w4  = LOAD(4);
	w5  = LOAD(5);
	w6  = LOAD(6);
	w7  = LOAD(7);
	w8  = LOAD(8);
	w9  = LOAD(9);
	w10 = LOAD(10);
	w11 = LOAD(11);
	w12 = LOAD(12);
	w13 = LOAD(13);
	w14 = LOAD(14);
	w15 = LOAD(15);


	ROUND(  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15); /* 0 */
	ROUND( 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3); /* 1 */
	ROUND( 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4); /* 2 */
	ROUND(  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8); /* 3 */
	ROUND(  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13); /* 4 */
	ROUND(  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9); /* 5 */
	ROUND( 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11); /* 6 */
	ROUND( 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10); /* 7 */
	ROUND(  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5); /* 8 */
	ROUND( 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0); /* 9 */


	ROUND(  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15); /* 10 */
	ROUND( 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3); /* 11 */

	/* Update the hash */

	h0 ^= x0 ^ x8;
	h1 ^= x1 ^ x9;
	h2 ^= x2 ^ x10;
	h3 ^= x3 ^ x11;
	h4 ^= x4 ^ x12;
	h5 ^= x5 ^ x13;
	h6 ^= x6 ^ x14;
	h7 ^= x7 ^ x15;

	/* Move to the next block */
	--nblocks; ++mesg;

    }

    h[0] = h0;
    h[1] = h1;
    h[2] = h2;
    h[3] = h3;
    h[4] = h4;
    h[5] = h5;
    h[6] = h6;
    h[7] = h7;
    *Upper = upper;
    *Lower = lower;
}

# ifdef __GNUC__

typedef Block2b AlignedBlock2b __attribute__ ((aligned (32)));
void raazHashBlake2bPortableLastBlock(AlignedBlock2b mesg, int nbytes,
				      Word2b upper, Word2b lower,
				      Word2b f0, Word2b f1,
				      Blake2b h)
    __attribute__((optimize("tree-vectorize")));

#endif

/* This is the function for compressing the last block. The nbytes should be <= block size */

#undef  LOAD
#define LOAD(i) (raaz_tole64(mesg[(i)]))
void raazHashBlake2bPortableLastBlock( Block2b mesg, int nbytes,
				       Word2b upper, Word2b lower,
				       Word2b f0 , Word2b f1,
				       Blake2b h)
{

    register Word2b x0,  x1,  x2,  x3;  /* row 0  */
    register Word2b x4,  x5,  x6,  x7;  /* row 1  */
    register Word2b x8,  x9,  x10, x11;  /* row 2  */
    register Word2b x12, x13, x14, x15;  /* row 3  */

    /* Input block */
    register Word2b w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    /* Variable that contains the hash */
    Word2b  h0, h1, h2, h3, h4, h5, h6, h7;

    /* Initialisation hashes

       The increment is here for the same reason as in the block
       compression function.

    */


    if (lower > UINT64_MAX - nbytes) { ++upper; } /* Increment the counter */
    lower += nbytes;


    x0 = h[0];
    x1 = h[1];
    x2 = h[2];
    x3 = h[3];
    x4 = h[4];
    x5 = h[5];
    x6 = h[6];
    x7 = h[7];

    /* Initialisation iv  */

    x8  = iv2b0;
    x9  = iv2b1;
    x10 = iv2b2;
    x11 = iv2b3;
    x12 = iv2b4 ^ lower;
    x13 = iv2b5 ^ upper;
    x14 = iv2b6 ^ f0;
    x15 = iv2b7 ^ f1;

    /* Load the block */

    w0  = LOAD(0);
    w1  = LOAD(1);
    w2  = LOAD(2);
    w3  = LOAD(3);
    w4  = LOAD(4);
    w5  = LOAD(5);
    w6  = LOAD(6);
    w7  = LOAD(7);
    w8  = LOAD(8);
    w9  = LOAD(9);
    w10 = LOAD(10);
    w11 = LOAD(11);
    w12 = LOAD(12);
    w13 = LOAD(13);
    w14 = LOAD(14);
    w15 = LOAD(15);


    ROUND(  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15); /* 0 */
    ROUND( 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3); /* 1 */
    ROUND( 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4); /* 2 */
    ROUND(  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8); /* 3 */
    ROUND(  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13); /* 4 */
    ROUND(  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9); /* 5 */
    ROUND( 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11); /* 6 */
    ROUND( 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10); /* 7 */
    ROUND(  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5); /* 8 */
    ROUND( 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0); /* 9 */


    ROUND(  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15); /* 10 */
    ROUND( 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3); /* 11 */

    /* Update the hash */

    h[0] ^= x0 ^ x8;
    h[1] ^= x1 ^ x9;
    h[2] ^= x2 ^ x10;
    h[3] ^= x3 ^ x11;
    h[4] ^= x4 ^ x12;
    h[5] ^= x5 ^ x13;
    h[6] ^= x6 ^ x14;
    h[7] ^= x7 ^ x15;

}
