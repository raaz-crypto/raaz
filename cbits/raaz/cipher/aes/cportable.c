#include "common.h"

#define ShiftLeftBytes(r) ((r << 1) & 0xfefefefe)
#define CycleBits(r)      ((r >> 7) & 0x01010101)
#define Mult02(r) ShiftLeftBytes(r) ^ (CycleBits(r) * 0x1b)


/* Loading a state */

#define Load(r,in)                                      \
    {                                                   \
        r##0 = MkW((in)[0],(in)[4],(in)[8] ,(in)[12]);  \
        r##1 = MkW((in)[1],(in)[5],(in)[9] ,(in)[13]);  \
        r##2 = MkW((in)[2],(in)[6],(in)[10],(in)[14]);  \
        r##3 = MkW((in)[3],(in)[7],(in)[11],(in)[15]);  \
    }

/* n = r */

#define Copy(n,r)						\
    { n##0 = r##0; n##1 = r##1; n##2 = r##2; n##3 = r##3; }

/* n ^= r */

#define XOR(n,r)						\
	{ n##0 ^= r##0; n##1 ^= r##1; n##2 ^= r##2; n##3 ^= r##3; }

#define Store(r,out)              \
    {                             \
	(out)[0]  = B3(r##0);	  \
	(out)[4]  = B2(r##0);	  \
	(out)[8]  = B1(r##0);	  \
	(out)[12] = B0(r##0);	  \
                                  \
	(out)[1]  = B3(r##1);	  \
	(out)[5]  = B2(r##1);	  \
	(out)[9]  = B1(r##1);	  \
	(out)[13] = B0(r##1);	  \
                                  \
	(out)[2]  = B3(r##2);	  \
	(out)[6]  = B2(r##2);	  \
	(out)[10] = B1(r##2);	  \
	(out)[14] = B0(r##2);	  \
                                  \
	(out)[3]  = B3(r##3);	  \
	(out)[7]  = B2(r##3);	  \
	(out)[11] = B1(r##3);	  \
	(out)[15] = B0(r##3);	  \
    }

#define AddRoundKey(r,s)        \
    {                           \
        r##0 ^= s[0];           \
        r##1 ^= s[1];           \
        r##2 ^= s[2];           \
        r##3 ^= s[3];           \
    }


#define AddRoundKeyAssign(n,r,key)      \
    {                                   \
        n##0 = r##0 ^ key[0];		\
        n##1 = r##1 ^ key[1];		\
        n##2 = r##2 ^ key[2];		\
        n##3 = r##3 ^ key[3];		\
    }

#define MixColumns(n,r)                \
    {                                  \
        n##0 = r##1 ^ r##2 ^ r##3 ;    \
        n##1 = r##2 ^ r##3 ^ r##0 ;    \
        n##2 = r##3 ^ r##0 ^ r##1 ;    \
        n##3 = r##0 ^ r##1 ^ r##2 ;    \
                                       \
        r##0 = Mult02(r##0);           \
        r##1 = Mult02(r##1);           \
        r##2 = Mult02(r##2);           \
        r##3 = Mult02(r##3);           \
				       \
        n##0 ^= r##0 ^ r##1;           \
        n##1 ^= r##1 ^ r##2;           \
        n##2 ^= r##2 ^ r##3;           \
        n##3 ^= r##3 ^ r##0;           \
    }


#define InvMixColumns(n,r)                        \
        {                                         \
        MixColumns(n,r)                           \
                                                  \
        r##0 ^= r##2 ;                            \
        r##1 ^= r##3 ;                            \
						  \
        r##0 = Mult02(r##0);                      \
        r##1 = Mult02(r##1);                      \
						  \
        n##0 ^= r##0;                             \
        n##1 ^= r##1;                             \
        n##2 ^= r##0;                             \
        n##3 ^= r##1;                             \
						  \
        r##0 = Mult02(r##0);                      \
        r##1 = Mult02(r##1);                      \
        r##0 ^= r##1;                             \
						  \
        n##0 ^= r##0;                             \
        n##1 ^= r##0;                             \
        n##2 ^= r##0;                             \
        n##3 ^= r##0;                             \
        }

#define DECL_MATRIX_REGISTER(r)  \
    register Row r##0;           \
    register Row r##1;		 \
    register Row r##2;		 \
    register Row r##3;

#define DECL_MATRIX(r) \
    Row r##0;          \
    Row r##1;          \
    Row r##2;          \
    Row r##3;


/* The encryption macro

   Uses variables state, temp, eKey, r and nRounds

   If state contained the block that needs to be encrypted then by the
   end of ENCRYPT state will contain the encrypted block.

 */

#define ENCRYPT	{				\
    AddRoundKey(state, eKey[0]);                \
    for(r = 1; r < nRounds; ++r)		\
    {						\
        SubBytesAndShift(state);		\
        MixColumns(temp,state);                 \
	AddRoundKeyAssign(state,temp, eKey[r]); \
    }                                           \
    SubBytesAndShift(state);                    \
    AddRoundKey(state,eKey[nRounds]);           \
}

/* The decryption macro

   Uses variables state, temp, eKey, r and nRounds

   If state contained the block that needs to be encrypted then by the
   end of DECRYPT the variable state will contain the decrypted block.

 */


#define DECRYPT {                               \
    AddRoundKey(state,eKey[nRounds]);           \
    for(r = nRounds - 1; r > 0; --r)		\
    {                                           \
	InvSubBytesAndShift(state);             \
	AddRoundKeyAssign(temp,state, eKey[r]); \
	InvMixColumns(state,temp);              \
    }                                           \
    InvSubBytesAndShift(state);                 \
    AddRoundKey(state,eKey[0]);			\
}

void raazAESCBCEncryptCPortable(
    Block *inp, int nBlocks,
    int nRounds, RMatrix *eKey,
    RMatrix iv)
{
    int r;
    DECL_MATRIX_REGISTER(state);
    DECL_MATRIX_REGISTER(temp);

    state0 = iv[0];
    state1 = iv[1];
    state2 = iv[2];
    state3 = iv[3];

    /* Invariant: State contains the iv for the current block */
    while( nBlocks )
    {
	/* Load the actual block into temp */
	Load(temp, *inp);

	/* XOR with the iv that is in state and store it in state */

	XOR(state, temp);

	ENCRYPT; /* now state contains the encrypted block which is
		    also the iv for the next block.
		 */

	Store(state, *inp);

	--nBlocks;
	++inp;
    }

    iv[0] = state0;
    iv[1] = state1;
    iv[2] = state2;
    iv[3] = state3;

}

void raazAESECBEncryptCPortable(
    Block *inp, int nBlocks,
    int nRounds, RMatrix *eKey)
{
    int r;
    DECL_MATRIX_REGISTER(state);
    DECL_MATRIX_REGISTER(temp);

    while(nBlocks){
	Load(state, *inp);
	ENCRYPT;
	Store(state, *inp);
	--nBlocks;
	++inp;
    }

}

void raazAESCBCDecryptCPortable(
    Block *inp, int nBlocks,
    int nRounds, RMatrix *eKey,
    RMatrix iv)
{
    int cursor, r;

    DECL_MATRIX(endIV)
    DECL_MATRIX_REGISTER(state);
    DECL_MATRIX_REGISTER(temp);


    Load(state, inp[nBlocks - 1]); /* Start from the last block */

    /* The last encrypted block is also the IV for the subsequent
       blocks. So keep track of it.
    */

    Copy(endIV, state);

    /*
      The invariant kept track of is that the variable state contains
      the current block that is to be decrypted.
    */

    for(cursor = nBlocks - 1; cursor > 0 ; --cursor)
    {

	DECRYPT;

	/* Load the IV for the current block into temp */
	Load(temp, inp[cursor - 1]);

	/* Recover the actual block */
	XOR(state,temp)

	/* Store the decrypted block */
	Store(state, inp[cursor]);

	/* Maintain the invariant by moving stuff in temp to state */
	Copy(state, temp);

    }

    /* For the first block */
    DECRYPT;

    state0 ^= iv[0];
    state1 ^= iv[1];
    state2 ^= iv[2];
    state3 ^= iv[3];

    Store(state, inp[0]);

    iv[0] = endIV0;
    iv[1] = endIV1;
    iv[2] = endIV2;
    iv[3] = endIV3;

}
