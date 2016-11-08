#include "vector.h"



# define R(x,i) ((x << i) | (x >> (32 - i)))
# define QROUND(a,b,c,d)			\
    {						\
	a += b; d ^= a; d = R(d,16);		\
	c += d; b ^= c; b = R(b,12);		\
	a += b; d ^= a; d = R(d,8);		\
	c += d; b ^= c; b = R(b,7);		\
    }						\

/*

  r0 = x0 x1 x2  x3
  r1 = x4 x5 x6  x7
  r2 = x8 x9 x10 x11
  r3 = x12 x13 x14 x15

  QROUND(r0, r1, r2, r3) : Handles row o

  d0 = x0  x1    x2   x3
  d1 = x5  x6    x7   x4
  d2 = x10 x11   x8   x9
  d3 = x15 x12   x13  x14

 */


# define SIG  ((Vec){ 1 , 2 , 3 , 0 })
# define SIG2 ((Vec){ 2 , 3 , 0 , 1 })
# define SIG3 ((Vec){ 3 , 0 , 1 , 2 })


# define ISIG  ((Vec){ 3 , 0 , 1 , 2 })
# define ISIG2 ((Vec){ 2 , 3 , 0  ,1 })
# define ISIG3 ((Vec){ 1 , 2 , 3 , 0 })



#define TODIAG		               \
    {				       \
    B = __builtin_shuffle ( B, SIG  ); \
    C = __builtin_shuffle ( C, SIG2 ); \
    D = __builtin_shuffle ( D, SIG3 ); \
    }


#define TOROW			      \
    {				      \
    B = __builtin_shuffle(B, ISIG  ); \
    C = __builtin_shuffle(C, ISIG2 ); \
    D = __builtin_shuffle(D, ISIG3 ); \
    }





# define ROUND \
     { QROUND(A,B,C,D); TODIAG; QROUND(A,B,C,D); TOROW; }


# define XORA(i) (*msg)[i] ^= raaz_tole32( A[i]    )
# define XORB(i) (*msg)[i] ^= raaz_tole32( B[i-4]  )
# define XORC(i) (*msg)[i] ^= raaz_tole32( C[i-8]  )
# define XORD(i) (*msg)[i] ^= raaz_tole32( D[i-12] )


# define ChaChaConstantRow  ((Vec){ C0     , C1     , C2     ,  C3    })

# define INP(i) (((Vec *)msg)[i])
# define WRITE(i,R) { MSG  = INP(i); MSG ^= R; INP(i) = MSG; }

/* One should ensure that msg is aligned to 16 bytes. */
static inline void chacha20vec128(Block *msg, int nblocks, const Key key, const IV iv, Counter *ctr)
{

    register Vec A , B, C, D;
    register Vec M1, M2, M3;
    register Vec MSG;

    /* TODO: Optimise with vector load (take care of alignments) */

    M1 =  (Vec){ key[0] , key[1] , key[2] , key[3] };
    M2 =  (Vec){ key[4] , key[5] , key[6] , key[7] };
    M3 =  (Vec){ *(ctr) , iv[0]  ,  iv[1] , iv[2]  };

    *ctr += nblocks;

    for(; nblocks > 0; -- nblocks, ++msg)
    {
	/* Initialise the state;
	   Except for the counter everything is the same
	 */

	A = ChaChaConstantRow;
	B = M1; C = M2; D = M3;

	ROUND; /* 0,1   */
	ROUND; /* 2,3   */
	ROUND; /* 4,5   */
	ROUND; /* 6,7   */
	ROUND; /* 8,9   */
	ROUND; /* 10,11 */
	ROUND; /* 12,13 */
	ROUND; /* 14,15 */
	ROUND; /* 16,17 */
	ROUND; /* 18,19 */

	A += ChaChaConstantRow;


	B += M1;
	C += M2;
	D += M3;

	/* TODO: Optimise with vector load (take care of
	 * alignments) */

	WRITE(0,A); WRITE(1, B); WRITE(2,C); WRITE(3,D);

	++M3[0];         /* increment counter      */

    }
    return;
}

void raazChaCha20BlockVector(Block *msg, int nblocks, const Key key, const IV iv, Counter *ctr)
{
    chacha20vec128(msg, nblocks, key, iv, ctr);
}
