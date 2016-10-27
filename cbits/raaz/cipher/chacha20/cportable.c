/* Warnings all macros are unprotected use with care */
#include "cportable.h"
#include <stdio.h>

/* The main chacha20 transform for a complete block of data.
 *
 * Issues
 * ------
 *
 * 1. This function does not keep track of the counter, the calling
 *    function is required to do this
 *
 * 2. Maximum bytes that should be encoded is 2^32 * 64 = 256GB.  The
 *    counter repeats after that.
 *
 * 3. It encrypts whole blocks and hence should be used with care. In
 *    particular even for partial blocks the array imp should have
 *    enough space to keep the whole input.
 *
 */




void raazChaCha20Block(Block *msg, int nblocks, Key key, IV iv, Counter *ctr)
{
    register Word x0,  x1,  x2, x3;
    register Word x4,  x5,  x6, x7;
    register Word x8,  x9,  x10, x11;
    register Word x12, x13, x14, x15;

    while( nblocks > 0){


	x0  = C0     ; x1  = C1     ; x2  = C2     ; x3  = C3     ;
	x4  = key[0] ; x5  = key[1] ; x6  = key[2] ; x7  = key[3] ;
	x8  = key[4] ; x9  = key[5] ; x10 = key[6] ; x11 = key[7] ;
	x12 = *ctr   ; x13 = iv[0]  ; x14 = iv[1]  ; x15 = iv[2]  ;


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
	x12 += *ctr   ; x13 += iv[0]  ; x14 += iv[1]  ; x15 += iv[2]  ;

	/* The output has to take care of the fact that we have permuted
	 * the columns. The ith column, i = 0,1,2,3 needs to be moved
	 * downwards by i.
	 */


	XOR(0,x0)   ; XOR(1, x1) ; XOR(2, x2)   ; XOR(3,  x3)  ;
	XOR(4,x4)   ; XOR(5, x5) ; XOR(6, x6)   ; XOR(7,  x7)  ;
	XOR(8,x8)   ; XOR(9, x9) ; XOR(10, x10) ; XOR(11, x11) ;
	XOR(12,x12) ; XOR(13,x13); XOR(14, x14) ; XOR(15, x15) ;


	++(*ctr);         /* increment counter      */
	--nblocks; ++msg; /* move to the next block */
    }
}


/* This function handles the last (partial) block of encryption. Use
 * this only when nbytes < BLOCK_SIZE
 */
