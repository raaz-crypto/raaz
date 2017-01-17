#include "common.h"

# define R(x,i) (                                                       \
        (x << (Vec2){i,i,i,i,i,i,i,i}) |                                \
        (x >> (Vec2){32 -i, 32 - i, 32 -i, 32 -i, 32 -i, 32 - i, 32 - i , 32 - i }) \
        )

/*
# define R(x,i) ( (x << i) | (x >> (32 - i)))
*/

# define QROUND(a,b,c,d)                        \
    {                                           \
        a += b; d ^= a; d = R(d,16);            \
        c += d; b ^= c; b = R(b,12);            \
        a += b; d ^= a; d = R(d,8);             \
        c += d; b ^= c; b = R(b,7);             \
    }                                           \



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



# define SIG       1 , 2 , 3 , 0 , 5  , 6  , 7  , 4
# define SIG2      2 , 3 , 0 , 1 , 6  , 7  , 4  , 5
# define SIG3      3 , 0 , 1 , 2 , 7  , 4  , 5  , 6
# define MASK_LOW  0 , 1 , 2 , 3 , 8  , 9  , 10 , 11
# define MASK_HIGH 4 , 5 , 6 , 7 , 12 , 13 , 14 , 15

# define ISIG  SIG3
# define ISIG2 SIG2
# define ISIG3 SIG

#ifdef __clang__

#     define SIGMA(X)   (__builtin_shufflevector( X, X, SIG))
#     define SIGMA2(X)  (__builtin_shufflevector( X, X, SIG2))
#     define SIGMA3(X)  (__builtin_shufflevector( X, X, SIG3))
#     define ISIGMA(X)  (__builtin_shufflevector( X, X, ISIG))
#     define ISIGMA2(X) (__builtin_shufflevector( X, X, ISIG2))
#     define ISIGMA3(X) (__builtin_shufflevector( X, X, ISIG3))

#     define MERGE_LOW(X,Y)  (__builtin_shufflevector(X,Y, MASK_LOW))
#     define MERGE_HIGH(X,Y) (__builtin_shufflevector(X,Y, MASK_HIGH))

#else


#     define SIGMA(X)   (__builtin_shuffle( X, (Vec2){SIG}))
#     define SIGMA2(X)  (__builtin_shuffle( X, (Vec2){SIG2}))
#     define SIGMA3(X)  (__builtin_shuffle( X, (Vec2){SIG3}))
#     define ISIGMA(X)  (__builtin_shuffle( X, (Vec2){ISIG}))
#     define ISIGMA2(X) (__builtin_shuffle( X, (Vec2){ISIG2}))
#     define ISIGMA3(X) (__builtin_shuffle( X, (Vec2){ISIG3}))

#     define MERGE_LOW(X,Y)  (__builtin_shuffle(X,Y, (Vec2){MASK_LOW} ))
#     define MERGE_HIGH(X,Y) (__builtin_shuffle(X,Y, (Vec2){MASK_HIGH}))

#endif

#  define TODIAG { B = SIGMA(B) ; C = SIGMA2(C) ; D = SIGMA3(D); }
#  define TOROW	 { B = ISIGMA(B); C = ISIGMA2(C); D = ISIGMA3(D); }


# define ROUND              { QROUND(A,B,C,D); TODIAG; QROUND(A,B,C,D); TOROW; }
# define ChaChaConstantRow  (Vec2){ C0 , C1 , C2 , C3, C0 , C1 , C2  , C3}

# define LOW(X)          ((Vec){X[0],X[1],X[2],X[3]})
# define HIGH(X)         ((Vec){X[4],X[5],X[6],X[7]})

# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#   define ADJUST_ENDIAN(A) {} /* do nothing */
# else
#   define SWAP(A,i) bswap_32(A[i])
#   define ADJUST_ENDIAN(A) {					   \
	A  = (Vec2){ SWAP(A,0), SWAP(A,1), SWAP(A,2), SWAP(A,3)	   \
		     SWAP(A,4), SWAP(A,5), SWAP(A,6), SWAP(A,7)};}
# endif

# define INP(i)            (((Vec*)msg)[i])
# define INP2(i)            (((Vec2*)msg)[i])

# ifdef HAVE_AVX2
#   define WRITE_LOW { 	MSG = MERGE_LOW(A,B); INP2(0) ^= MSG; MSG = MERGE_LOW(C,D); INP2(1) ^= MSG; }
#   define WRITE_HIGH { MSG = MERGE_HIGH(A,B); INP2(2) ^= MSG; MSG = MERGE_HIGH(C,D); INP2(3) ^= MSG; }
# else
#   define WRITE_LOW { INP(0) ^= LOW(A); INP(1) ^= LOW(B); INP(2) ^= LOW(C); INP(3) ^= LOW(D); }
#   define WRITE_HIGH { INP(4) ^= HIGH(A); INP(5) ^= HIGH(B); INP(6) ^= HIGH(C); INP(7) ^= HIGH(D); }
# endif


void raazChaCha20BlockVector256(Block *msg, int nblocks, const Key key, const IV iv, Counter *ctr)
{

    register Vec2 A , B, C, D;
    register Vec2 M1, M2, M3;
    register Vec2 MSG;

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

	ADJUST_ENDIAN(A); ADJUST_ENDIAN(B); ADJUST_ENDIAN(C); ADJUST_ENDIAN(D);

	WRITE_LOW;

	if( nblocks > 1) { WRITE_HIGH; nblocks -= 2 ; msg += 2; }
	else {-- nblocks ; ++ msg; }
        M3 += (Vec2){2,0,0,0,2,0,0,0};          /* increment the counter */
    }

   return;
}
