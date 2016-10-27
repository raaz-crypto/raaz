#pragma once
#include "common.h"

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
extern void raazChaCha20Block(Block *msg, int nblocks, Key key, IV iv, Counter *ctr);
