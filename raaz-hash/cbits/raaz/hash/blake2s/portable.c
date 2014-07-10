/*

Portable C implementation of BLAKE2s Hash.
This is a part of raaz cryptographic library.

*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>         
#include <raaz/primitives/load.h>

#define HASH_SIZE 8     /* Size of input hash */
#define BLOCK_SIZE 16   /* Size of a block    */
#define COUNTER_SIZE 4  /* Size of counter    */

#define ROTATER(x,n) ((x >> n) | (x << (32-n)))

typedef uint32_t Word;      /* Basic unit for Blake2s hash */
typedef Word Hash[HASH_SIZE];
typedef Word Block[BLOCK_SIZE];
//typedef Word Counter[COUNTER_SIZE];

/* Definning 8 constants for Blake2s hash */
#define IV0 0x6a09e667
#define IV1 0xbb67ae85
#define IV2 0x3c6ef372
#define IV3 0xa54ff53a
#define IV4 0x510e527f
#define IV5 0x9b05688c
#define IV6 0x1f83d9ab
#define IV7 0x5be0cd19

/* G function for Blake2s hash */
#define G(a, b, c, d, M0, M1)           \
{                                       \
  a =  a + b + M0;                      \
  d =  ROTATER((d ^ a), 16);            \
  c =  c + d;                           \
  b =  ROTATER((b ^ c), 12);            \
  a =  a + b + M1;                      \
  d =  ROTATER((d ^ a), 8);             \
  c =  c + d;                           \
  b =  ROTATER((b ^ c), 7);             \
}

void raazHashBlake2sPortableCompress(Hash hash, uint64_t *counter, int nblocks, Block *mesg)
{

    Word t0, t1, f0, f1;

    if(nblocks == 1)
        f0 = 0xffffffff;
    else f0 = 0x00000000;   

    /* Message variables */
    Word m0; 
    Word m1;
    Word m2;
    Word m3; 
    Word m4;
    Word m5;
    Word m6;
    Word m7;
    Word m8;
    Word m9;
    Word m10;
    Word m11;
    Word m12;
    Word m13;
    Word m14;
    Word m15;
  
    /* State variables - stored in registers so as to make the code faster */
    register Word v0;
    register Word v1;
    register Word v2;
    register Word v3;
    register Word v4;
    register Word v5;
    register Word v6;
    register Word v7;
    register Word v8;
    register Word v9;
    register Word v10;
    register Word v11;
    register Word v12;
    register Word v13;
    register Word v14;
    register Word v15;

    while(nblocks > 0)
    {
        /* Incrementing counter by message bits */
        //counter = counter + 512;        

        *counter = *counter + 64;
        t0 = (Word)*counter;       
        t1 = f1 = 0x00000000;

        /* Initialization of the state consisting of 16 words */                
        v0 = hash[0];
        v1 = hash[1];
        v2 = hash[2];
        v3 = hash[3];
        v4 = hash[4];
        v5 = hash[5];
        v6 = hash[6];
        v7 = hash[7];
        v8 = IV0;
        v9 = IV1;
        v10 = IV2; 
        v11 = IV3;
        v12 = t0 ^ IV4; 
        v13 = t1 ^ IV5; 
        v14 = f0 ^ IV6; 
        v15 = f1 ^ IV7;

        /* Loading the message into 16 words */
        m0 = raazLoad32LE((Word *)mesg,0);
        m1 = raazLoad32LE((Word *)mesg,1);
        m2 = raazLoad32LE((Word *)mesg,2);
        m3 = raazLoad32LE((Word *)mesg,3);
        m4 = raazLoad32LE((Word *)mesg,4);
        m5 = raazLoad32LE((Word *)mesg,5);
        m6 = raazLoad32LE((Word *)mesg,6);
        m7 = raazLoad32LE((Word *)mesg,7);
        m8 = raazLoad32LE((Word *)mesg,8);
        m9 = raazLoad32LE((Word *)mesg,9);
        m10 = raazLoad32LE((Word *)mesg,10); 
        m11 = raazLoad32LE((Word *)mesg,11); 
        m12 = raazLoad32LE((Word *)mesg,12); 
        m13 = raazLoad32LE((Word *)mesg,13); 
        m14 = raazLoad32LE((Word *)mesg,14); 
        m15 = raazLoad32LE((Word *)mesg,15);
        
        /* End of reading the message block */

        /* Round 1 */
        /* Column Steps 0-3 */
        G( v0, v4, v8 , v12, m0, m1 );
        G( v1, v5, v9 , v13, m2, m3 );
        G( v2, v6, v10, v14, m4, m5 );
        G( v3, v7, v11, v15, m6, m7 );

        /* Diagonal-Step 4-7 */  
        G( v0, v5, v10, v15, m8 , m9  );
        G( v1, v6, v11, v12, m10, m11 );
        G( v2, v7, v8 , v13, m12, m13 );
        G( v3, v4, v9 , v14, m14, m15 );

        /* Round 2 */
        /* Column Step 0-3 */
        G( v0, v4, v8 , v12, m14, m10 );
        G( v1, v5, v9 , v13, m4 , m8  );
        G( v2, v6, v10, v14, m9 , m15 );
        G( v3, v7, v11, v15, m13, m6  );

        /* Diagonal Step 4-7 */
        G( v0, v5, v10, v15, m1 , m12 );
        G( v1, v6, v11, v12, m0 , m2  );
        G( v2, v7, v8 , v13, m11, m7  );
        G( v3, v4, v9 , v14, m5 , m3  );


        /* Round 3 */
        /* Column Step 0-3 */
        G( v0, v4, v8 , v12, m11, m8  );
        G( v1, v5, v9 , v13, m12, m0  );
        G( v2, v6, v10, v14, m5 , m2  );
        G( v3, v7, v11, v15, m15, m13 );

        /* Diagonal Step 4-7 */
        G( v0, v5, v10, v15, m10, m14 );
        G( v1, v6, v11, v12, m3 , m6  );
        G( v2, v7, v8 , v13, m7 , m1  );
        G( v3, v4, v9 , v14, m9 , m4  );


        /* Round 4 */
        /* Column Step 0-3 */
        G( v0, v4, v8 , v12, m7 , m9  );
        G( v1, v5, v9 , v13, m3 , m1  );
        G( v2, v6, v10, v14, m13, m12 );
        G( v3, v7, v11, v15, m11, m14 );

        /* Diagonal Step 4-7 */
        G( v0, v5, v10, v15, m2 , m6  );
        G( v1, v6, v11, v12, m5 , m10 );
        G( v2, v7, v8 , v13, m4 , m0  );
        G( v3, v4, v9 , v14, m15, m8  );


        /* Round 5 */
        /* Column Step 0-3 */
        G( v0, v4, v8 , v12, m9 , m0  );
        G( v1, v5, v9 , v13, m5 , m7  );
        G( v2, v6, v10, v14, m2 , m4  );
        G( v3, v7, v11, v15, m10, m15 );

        /* Diagonal Step 4-7 */
        G( v0, v5, v10, v15, m14, m1  );
        G( v1, v6, v11, v12, m11, m12 );
        G( v2, v7, v8 , v13, m6 , m8  );
        G( v3, v4, v9 , v14, m3 , m13 );


        /* Round 6 */
        /* Column Step 0-3 */
        G( v0, v4, v8 , v12, m2, m12 );
        G( v1, v5, v9 , v13, m6, m10 );
        G( v2, v6, v10, v14, m0, m11 );
        G( v3, v7, v11, v15, m8, m3  );

        /* Diagonal Step 4-7 */
        G( v0, v5, v10, v15, m4 , m13 );
        G( v1, v6, v11, v12, m7 , m5  );
        G( v2, v7, v8 , v13, m15, m14 );
        G( v3, v4, v9 , v14, m1 , m9  );


        /* Round 7 */
        /* Column Step 0-3 */
        G( v0, v4, v8 , v12, m12, m5  );
        G( v1, v5, v9 , v13, m1 , m15 );
        G( v2, v6, v10, v14, m14, m13 );
        G( v3, v7, v11, v15, m4 , m10 );

        /* Diagonal Step 4-7 */
        G( v0, v5, v10, v15, m0, m7  );
        G( v1, v6, v11, v12, m6, m3  );
        G( v2, v7, v8 , v13, m9, m2  ); 
        G( v3, v4, v9 , v14, m8, m11 );


        /* Round 8 */
        /* Column Step 0-3 */
        G( v0, v4, v8 , v12, m13, m11 );
        G( v1, v5, v9 , v13, m7 , m14 );
        G( v2, v6, v10, v14, m12, m1  );
        G( v3, v7, v11, v15, m3 , m9  );

        /* Diagonal Step 4-7 */
        G( v0, v5, v10, v15, m5 , m0  );
        G( v1, v6, v11, v12, m15, m4  );
        G( v2, v7, v8 , v13, m8 , m6  );
        G( v3, v4, v9 , v14, m2 , m10 );


        /* Round 9 */
        /* Column Step 0-3 */
        G( v0, v4, v8 , v12, m6 , m15 );
        G( v1, v5, v9 , v13, m14, m9  );
        G( v2, v6, v10, v14, m11, m3  );
        G( v3, v7, v11, v15, m0 , m8  );

        /* Diagonal Step 4-7 */
        G( v0, v5, v10, v15, m12, m2  );
        G( v1, v6, v11, v12, m13, m7  );
        G( v2, v7, v8 , v13, m1 , m4  );
        G( v3, v4, v9 , v14, m10, m5  );


        /* Round 10 */
        /* Column Step 0-3 */
        G( v0, v4, v8 , v12, m10, m2 );
        G( v1, v5, v9 , v13, m8 , m4 );
        G( v2, v6, v10, v14, m7 , m6 );
        G( v3, v7, v11, v15, m1 , m5 );

        /* Diagonal Step 4-7 */
        G( v0, v5, v10, v15, m15, m11 );
        G( v1, v6, v11, v12, m9 , m14 );
        G( v2, v7, v8 , v13, m3 , m12 );
        G( v3, v4, v9 , v14, m13, m0  );


        

        /* Updation of hash variables with the new chain value */
        hash[0] = hash[0] ^ v0 ^ v8;
        hash[1] = hash[1] ^ v1 ^ v9;
        hash[2] = hash[2] ^ v2 ^ v10;
        hash[3] = hash[3] ^ v3 ^ v11;
        hash[4] = hash[4] ^ v4 ^ v12;     
        hash[5] = hash[5] ^ v5 ^ v13;     
        hash[6] = hash[6] ^ v6 ^ v14; 
        hash[7] = hash[7] ^ v7 ^ v15;     
        
        hash[0] = raazLoad32LE((Word *)hash, 0);
        hash[1] = raazLoad32LE((Word *)hash, 1);
        hash[2] = raazLoad32LE((Word *)hash, 2);
        hash[3] = raazLoad32LE((Word *)hash, 3);
        hash[4] = raazLoad32LE((Word *)hash, 4);
        hash[5] = raazLoad32LE((Word *)hash, 5);
        hash[6] = raazLoad32LE((Word *)hash, 6);
        hash[7] = raazLoad32LE((Word *)hash, 7);

        //printf("%x %x %x %x %x %x %x %x\n", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
        //t0 = t0 + 64;
        ++mesg; /* Incrementing to the next block */
        --nblocks;
        }
      

    }