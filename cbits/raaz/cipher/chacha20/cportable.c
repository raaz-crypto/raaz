#include "common.h"

/* The main chacha20 block transform for a complete block of data.
 *
 * Maximum bytes that should be encoded is 2^32 * 64 = 256GB.  The
 * counter repeats after that.
 *
 */



/* Warnings all macros are unprotected use with care */

# define R(x,i) ((x << i) | (x >> (32 - i)))

# define QROUND(a,b,c,d)			\
    {						\
	a += b; d ^= a; d = R(d,16);		\
	c += d; b ^= c; b = R(b,12);		\
	a += b; d ^= a; d = R(d,8);		\
	c += d; b ^= c; b = R(b,7);		\
    }						\



# define ROUND			  \
    {				  \
	QROUND(x0, x4, x8,  x12); \
	QROUND(x1, x5, x9,  x13); \
	QROUND(x2, x6, x10, x14); \
	QROUND(x3, x7, x11, x15); \
	QROUND(x0, x5, x10, x15); \
	QROUND(x1, x6, x11, x12); \
	QROUND(x2, x7, x8,  x13); \
	QROUND(x3, x4, x9,  x14); \
    }


# define XOR(i,a)    (*msg)[i] ^= raaz_tole32(a)
# define EMIT(i,a)   (*msg)[i]  = a

/*

Some function for debugging.

# define PR(i)        printf("%8x  ", x##i)
# define PRM(i)       printf("%8x  ", (*msg)[i])
# define NEWLINE      printf("\n")
# define PRINTSTATE				\
    {						\
    PR(0); PR(1);   PR(2);    PR(3); NEWLINE;	\
    PR(4); PR(5);   PR(6);    PR(7); NEWLINE;	\
    PR(8); PR(9);   PR(10);   PR(11); NEWLINE;	\
    PR(12); PR(13); PR(14); PR(15); NEWLINE;	\
    }

# define PRINTMESG				\
    {						\
    PRM(0); PRM(1);   PRM(2);    PRM(3); NEWLINE;	\
    PRM(4); PRM(5);   PRM(6);    PRM(7); NEWLINE;	\
    PRM(8); PRM(9);   PRM(10);   PRM(11); NEWLINE;	\
    PRM(12); PRM(13); PRM(14); PRM(15); NEWLINE;	\
    }

*/

# ifdef __GNUC__

typedef Block MyBlock __attribute__ ((aligned (32)));

void raazChaCha20Block(MyBlock * msg, int nblocks, const Key key, const IV iv, Counter  *ctr) __attribute__((optimize("tree-vectorize")));

void raazChaCha20Block(MyBlock * msg, int nblocks, const Key key, const IV iv, Counter  *ctr)

# else

void raazChaCha20Block(Block * msg, int nblocks, const Key key, const IV iv, Counter  *ctr)

#endif

{
    register Word x0,  x1,  x2, x3;
    register Word x4,  x5,  x6, x7;
    register Word x8,  x9,  x10, x11;
    register Word x12, x13, x14, x15;
    register Word valCtr; /* value of the ctr */

    valCtr = *ctr;
    while( nblocks > 0){


	x0  = C0     ; x1  = C1     ; x2  = C2     ; x3  = C3     ;
	x4  = key[0] ; x5  = key[1] ; x6  = key[2] ; x7  = key[3] ;
	x8  = key[4] ; x9  = key[5] ; x10 = key[6] ; x11 = key[7] ;
	x12 = valCtr ; x13 = iv[0]  ; x14 = iv[1]  ; x15 = iv[2]  ;


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



	x0  += C0     ; x1  += C1     ; x2  += C2     ; x3  += C3     ;
	x4  += key[0] ; x5  += key[1] ; x6  += key[2] ; x7  += key[3] ;
	x8  += key[4] ; x9  += key[5] ; x10 += key[6] ; x11 += key[7] ;
	x12 += valCtr ; x13 += iv[0]  ; x14 += iv[1]  ; x15 += iv[2]  ;


	XOR(0,x0)   ; XOR(1, x1) ; XOR(2, x2)   ; XOR(3,  x3)  ;
	XOR(4,x4)   ; XOR(5, x5) ; XOR(6, x6)   ; XOR(7,  x7)  ;
	XOR(8,x8)   ; XOR(9, x9) ; XOR(10, x10) ; XOR(11, x11) ;
	XOR(12,x12) ; XOR(13,x13); XOR(14, x14) ; XOR(15, x15) ;


	++ valCtr;
	--nblocks; ++msg; /* move to the next block */
    }
    *ctr = valCtr;         /* increment counter      */
    return;
}
