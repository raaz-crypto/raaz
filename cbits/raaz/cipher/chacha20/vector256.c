#include "common.h"

# define R(x,i) (							\
	(x << (Vec2){i,i,i,i,i,i,i,i}) |				\
	(x >> (Vec2){32 -i, 32 - i, 32 -i, 32 -i, 32 -i, 32 - i, 32 - i , 32 - i }) \
	)

/*
# define R(x,i) ( (x << i) | (x >> (32 - i)))
*/

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


# ifdef __clang__
#   define SIG  1 , 2 , 3 , 0 , 5 , 6 , 7 , 4
#   define SIG2 2 , 3 , 0 , 1 , 6 , 7 , 4 , 5
#   define SIG3 3 , 0 , 1 , 2 , 7 , 4 , 5 , 6
# else
#   define SIG   (Vec2){ 1 , 2 , 3 , 0 , 5 , 6 , 7 , 4 }
#   define SIG2  (Vec2){ 2 , 3 , 0 , 1 , 6 , 7 , 4 , 5 }
#   define SIG3  (Vec2){ 3 , 0 , 1 , 2 , 7 , 4 , 5 , 6 }
#endif

# define ISIG  SIG3
# define ISIG2 SIG2
# define ISIG3 SIG

#ifdef __clang__
#  define TODIAG					\
    {							\
	B = __builtin_shufflevector(B, B, SIG  );	\
	C = __builtin_shufflevector(C, C, SIG2 );	\
	D = __builtin_shufflevector(D, D, SIG3 );	\
    }

#  define TOROW						\
    {							\
	B = __builtin_shufflevector(B, B, ISIG  );	\
	C = __builtin_shufflevector(C, C, ISIG2 );	\
	D = __builtin_shufflevector(D, D, ISIG3 );	\
    }

#else

#  define TODIAG		                 \
    {						 \
	B = __builtin_shuffle ( B, SIG  );	 \
	C = __builtin_shuffle ( C, SIG2 );	 \
	D = __builtin_shuffle ( D, SIG3 );	 \
    }

#  define TOROW					\
    {						\
	B = __builtin_shuffle(B, ISIG  );	\
	C = __builtin_shuffle(C, ISIG2 );	\
	D = __builtin_shuffle(D, ISIG3 );	\
    }
#endif



# define ROUND \
    { QROUND(A,B,C,D); TODIAG; QROUND(A,B,C,D); TOROW; }


# define XORA(i) (*msg)[i] ^= raaz_tole32( A[i]    )
# define XORB(i) (*msg)[i] ^= raaz_tole32( B[i-4]  )
# define XORC(i) (*msg)[i] ^= raaz_tole32( C[i-8]  )
# define XORD(i) (*msg)[i] ^= raaz_tole32( D[i-12] )


#define ChaChaConstantRow  (Vec2){		\
	    C0     , C1     , C2     ,  C3,	\
	    C0     , C1     , C2     ,  C3	\
		}


# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#   define INP(i)            (((Vec*)msg)[i])
#   define XOR_L(i,R)   { MSG = INP(i); MSG ^= (Vec){R[0],R[1],R[2],R[3]}; INP(i) = MSG; }
#   define XOR_H(i,R)   { MSG = INP(i); MSG ^= (Vec){R[4],R[5],R[6],R[7]}; INP(i) = MSG; }

#   define WRITE_L						\
    {XOR_L(0,A); XOR_L(1,B); XOR_L(2,C); XOR_L(3,D);}

#   define WRITE_H						\
    {XOR_H(0,A); XOR_H(1,B); XOR_H(2,C); XOR_H(3,D);}
# else

#   define XORA(i,j) (*msg)[i] ^= raaz_tole32( A[j] )
#   define XORB(i,j) (*msg)[i] ^= raaz_tole32( B[j] )
#   define XORC(i,j) (*msg)[i] ^= raaz_tole32( C[j] )
#   define XORD(i,u) (*msg)[i] ^= raaz_tole32( D[j] )
#   define WRITE_L						\
    {   XORA(0,0)  ; XORA(0,1)  ; XORA(0,2)  ; XORA(0,3);	\
        XORB(4,0)  ; XORB(5,1)  ; XORB(6,2)  ; XORB(7,3);	\
        XORC(8,0)  ; XORC(9,1)  ; XORC(10,2) ; XORC(11,3);	\
        XORD(12,0) ; XORD(13,1) ; XORD(14,2) ; XORD(15,3);	\
    }
#   define WRITE_H						\
    {   XORA(0,4)  ; XORA(0,5)  ; XORA(0,6)  ; XORA(0,7);	\
        XORB(4,4)  ; XORB(5,5)  ; XORB(6,6)  ; XORB(7,7);	\
        XORC(8,4)  ; XORC(9,5)  ; XORC(10,6) ; XORC(11,7);	\
        XORD(12,4) ; XORD(13,5) ; XORD(14,6) ; XORD(15,7);	\
    }
#  endif /* Byte order */


static inline void chacha20vec256(Block *msg, int nblocks, const Key key, const IV iv, Counter *ctr)
{

    register Vec2 A , B, C, D;
    register Vec2 M1, M2, M3;
    register Vec  MSG;

    M1 =  (Vec2){
	key[0] , key[1] , key[2] , key[3],
	key[0] , key[1] , key[2] , key[3]
    };
    M2 =  (Vec2){
	key[4] , key[5] , key[6] , key[7],
	key[4] , key[5] , key[6] , key[7]
    };

    M3 =  (Vec2){
	*(ctr)   , iv[0]  ,  iv[1] , iv[2],
	*(ctr)+1 , iv[0]  ,  iv[1] , iv[2]
    };

    *ctr += nblocks;
    while(nblocks > 0)
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

	WRITE_L;
	--nblocks; ++msg; /* move to the next block */
	M3[0]++;          /* increment the counter */

	if( nblocks > 0)
	{
	    WRITE_H;
	    --nblocks; ++msg; /* move to the next block */
	    M3[0]++;          /* increment the counter */
	}
    }

   return;
}

void raazChaCha20BlockVector256(Block *msg, int nblocks, const Key key, const IV iv, Counter *ctr)
{
    chacha20vec256(msg, nblocks, key, iv, ctr);
}
