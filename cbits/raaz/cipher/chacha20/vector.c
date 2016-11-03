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


static int chacha20vec128(Block *msg, int nblocks, Key key, IV iv, Counter *ctr)
{

    register Vec A , B, C, D;
    register Vec M0, M1, M2, M3;

    M0 =  (Vec){ C0     , C1     , C2     ,  C3    };
    M1 =  (Vec){ key[0] , key[1] , key[2] , key[3] };
    M2 =  (Vec){ key[4] , key[5] , key[6] , key[7] };
    M3 =  (Vec){ *(ctr) , iv[0]  ,  iv[1] , iv[2]  };

    while(  nblocks > 0)
    {
	/* Initialise the state;
	   Except for the counter everything is the same
	 */
	M3[0] = *ctr;
	A     = M0; B = M1; C = M2; D = M3;




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

	A += M0; XORA(0); XORA(1); XORA(2); XORA(3);
	B += M1; XORB(0); XORB(1); XORB(2); XORB(3);
	C += M2; XORC(0); XORC(1); XORC(2); XORC(3);
	D += M3; XORD(0); XORD(1); XORD(2); XORD(3);

	++(*ctr);         /* increment counter      */
	--nblocks; ++msg; /* move to the next block */

    }
}

void raazChaCha20BlockVector(Block *msg, int nblocks, Key key, IV iv, Counter *ctr)
{
    chacha20vec128(msg, nblocks, key, iv, ctr);
}
