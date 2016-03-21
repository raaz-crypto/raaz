#ifndef _RAAZ_AES_COMMON_H_
#define _RAAZ_AES_COMMON_H_
#include <stdint.h>
#include <inttypes.h>

typedef uint8_t Byte;
typedef Byte    Block[16]; /* The AES block */

/*

Representing the AES block/state as 4 words.
--------------------------------------------

AES state a 4x4 matrix of bytes. This could be represented either as
4, 32-bit word each of which is a row of the matrix or 4, 32 bit words
each of which is a column. Although the C-Language will be agnostic to
our distinction and hence no type safety in this, we use such distinct
names mainly for documentation purposes

*/

typedef uint32_t Word;       /* A Word used in aes                    */
typedef Word     Row;        /* A row    of the aes state matrix      */
typedef Word     Column;     /* A column of the aes state matrix      */

typedef Word   Matrix[4];    /* AES matrix                            */
typedef Row    RMatrix[4];   /* AES matrix as an array of 4 rows      */
typedef Column CMatrix[4];   /* AES matrix as an array of 4 columns   */

extern const Byte sbox[256];     /* The AES SBOX as an array          */
extern const Byte inv_sbox[256]; /* The AES inverse sbox as an array  */


/******************** Common functions ********************************/
/*

Endian assumption: Don't ask, don't tell

All functions should not be bothered about doing endian gymnastics. It
is assumed that these gymnastics are handled at the haskell level and
these functions are merely FFI stubs. What this means is the following:


It is the callers, in this case the haskell functions duty to ensure a
function that is expecting a Matrix M in column order, i.e. expecting
an an argument of type CMatrix, should be fed 4 words such that the
ith word 0 <= i <= 3 should have M[0][i] as the most significant byte
followed by M[1][i] as the next significant byte etc.

An easy way to ensure the above is to make the type signature use BE
Word32 for the columns.

These functions, if they write data out would have this ostrich like
behaviour towards endianness and it is up to the haskell code to
compensate.

*/

extern void raazAESTranspose(int n, Matrix *state); /* Transpose all matrices */
extern void raazAESExpand128C(CMatrix *eKey);       /* AES 128 key expansion  */



/* Compute the ith  byte of a row */
#define B0(row) (Byte) (row)
#define B1(row) (Byte) ((row) >> 8 )
#define B2(row) (Byte) ((row) >> 16)
#define B3(row) (Byte) ((row) >> 24)

/* Move the byte to the appropriate offset inside a row */
#define B0ToR(b) (Row)(b)
#define B1ToR(b) (B0ToR(b)) << 8
#define B2ToR(b) (B0ToR(b)) << 16
#define B3ToR(b) (B0ToR(b)) << 24

/* Make a row out of the bytes given */
#define MkW(w3,w2,w1,w0) (B0ToR(w0))|(B1ToR(w1))|(B2ToR(w2))|(B3ToR(w3))

/* The SBOX of a word */

#define SB0(r)  sbox[B0(r)]
#define SB1(r)  sbox[B1(r)]
#define SB2(r)  sbox[B2(r)]
#define SB3(r)  sbox[B3(r)]

#define ISB0(r) inv_sbox[B0(r)]
#define ISB1(r) inv_sbox[B1(r)]
#define ISB2(r) inv_sbox[B2(r)]
#define ISB3(r) inv_sbox[B3(r)]

/* Computing the sbox of a row */

#define SBoxWord(r)  (MkW(SB3(r),  SB2(r),  SB1(r),  SB0(r)))

/* With shifts                 */
#define SBoxWordShift8(r)  (MkW(SB2(r),  SB1(r), SB0(r), SB3(r)))
#define SBoxWordShift16(r) (MkW(SB1(r),  SB0(r), SB3(r), SB2(r)))
#define SBoxWordShift24(r) (MkW(SB0(r),  SB3(r), SB2(r), SB1(r)))

#define SubBytesAndShift(r)                     \
    {                                           \
    r##0 = SBoxWord(r##0);                      \
    r##1 = SBoxWordShift8(r##1);                \
    r##2 = SBoxWordShift16(r##2);               \
    r##3 = SBoxWordShift24(r##3);               \
    }


#define ISBoxWord(r)        (MkW(ISB3(r), ISB2(r), ISB1(r), ISB0(r)))
#define ISBoxWordShift8(r)  (MkW(ISB0(r), ISB3(r), ISB2(r), ISB1(r)))
#define ISBoxWordShift16(r) (MkW(ISB1(r), ISB0(r), ISB3(r), ISB2(r)))
#define ISBoxWordShift24(r) (MkW(ISB2(r), ISB1(r), ISB0(r), ISB3(r)))


#define InvSubBytesAndShift(r)                  \
    {                                           \
    r##0 = ISBoxWord(r##0);                     \
    r##1 = ISBoxWordShift8(r##1);               \
    r##2 = ISBoxWordShift16(r##2);              \
    r##3 = ISBoxWordShift24(r##3);              \
    }



#define RotateL(r, n) ((r) << n) | ((r) >> (32 - n))
#define RotateR(r, n) ((r) >> n) | ((r) << (32 - n))

#endif
