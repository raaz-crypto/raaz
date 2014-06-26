/*

Portable C implementation of BLAKE256 Hash.
This is a part of raaz cryptographic library.

*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>         
#include <raaz/primitives/load.h>

#define HASH_SIZE 8     /* Size of input hash */
#define BLOCK_SIZE 16   /* Size of a block    */
#define SALT_SIZE 4     /* Size of input salt */

#define ROTATER(x,n) ((x >> n) | (x << (32-n)))

typedef uint32_t Word;      /* Basic unit for BLAKE hash */
typedef Word Hash[HASH_SIZE];
typedef Word Block[BLOCK_SIZE];
typedef Word Salt[SALT_SIZE];

/* Defining 16 Constants for Blake Hash */
#define c0 0x243F6A88
#define c1 0x85A308D3
#define c2 0x13198A2E
#define c3 0x03707344
#define c4 0xA4093822
#define c5 0x299F31D0
#define c6 0x082EFA98
#define c7 0xEC4E6C89
#define c8 0x452821E6
#define c9 0x38D01377
#define c10 0xBE5466CF
#define c11 0x34E90C6C
#define c12 0xC0AC29B7
#define c13 0xC97C50DD
#define c14 0x3F84D5B5
#define c15 0xB5470917


/*  G(a,b,c,d) function in Blake - 

    a = a + b + (m[sigma[r][2i]] 'xor' c[sigma[r][2i+1]])
    d = (d 'xor' a) >>> 16
    c = c + d
    b = (b 'xor' c) >>> 12
    a = a + b + (m[sigma[r][2i+1]] 'xor' c[sigma[r][2i]])
    d = (d 'xor' a) >>> 8
    c = c + d
    b = (b 'xor' c) >>> 7
    where (x >>> n) means rotation of n bits towards less significant bits in x


    The Gi(i = 0 to 7) function macros defined below takes four input variables - 
    (M0, M1) where M0 = m[sigma[r][2i]], M1 = m[sigma[r][2i+1]]
    (C0, C1) where C0 = c[sigma[r][2i]], C1 = c[sigma[r][2i+1]]
    
    The state variables are defined inside each macro rather than passing as arguments.

    ROTATER(x,n) is defined as a macro which will serve the function of (x >>> n).
    
    Here, we have used variables instead of an array since computing array indexes 
    and then accessing array elements will definitely consume more time and will 
    slow down the performance.

*/


/* G function for first column */
#define G0(M0, M1, C0, C1)              \
{                                       \
    v0 += v4 + ((M0) ^ (C1));           \
    v12 =  ROTATER(((v12) ^ (v0)), 16); \
    v8 += v12;                          \
    v4 = ROTATER(((v4) ^ (v8)), 12);    \
    v0 += v4 + ((M1) ^ (C0));           \
    v12 = ROTATER(((v12) ^ (v0)), 8);   \
    v8 += v12;                          \
    v4 = ROTATER(((v4) ^ (v8)),7);      \
}   

/* G function for second column */
#define G1(M0, M1, C0, C1)              \
{                                       \
    v1 += v5 + (M0 ^ C1);               \
    v13 = ROTATER((v13 ^ v1), 16);      \
    v9 += v13;                          \
    v5 = ROTATER((v5 ^ v9), 12);        \
    v1 += v5 + (M1 ^ C0);               \
    v13 = ROTATER((v13 ^ v1), 8);       \
    v9 += v13;                          \
    v5 = ROTATER((v5 ^ v9), 7);         \
}                       

/* G function for third column */
#define G2(M0, M1, C0, C1)              \
{                                       \
    v2 += v6 + (M0 ^ C1);               \
    v14 = ROTATER((v14 ^ v2), 16);      \
    v10 += v14;                         \
    v6 = ROTATER((v6 ^ v10), 12);       \
    v2 += v6 + (M1 ^ C0);               \
    v14 = ROTATER((v14 ^ v2), 8);       \
    v10 += v14;                         \
    v6 = ROTATER((v6 ^ v10), 7);        \
}                   

/* G function for fourth column */
#define G3(M0, M1, C0, C1)              \
{                                       \
    v3 += v7 + (M0 ^ C1);               \
    v15 = ROTATER((v15 ^ v3), 16);      \
    v11 += v15;                         \
    v7 = ROTATER((v7 ^ v11), 12);       \
    v3 += v7 + (M1 ^ C0);               \
    v15 = ROTATER((v15 ^ v3), 8);       \
    v11 += v15;                         \
    v7 = ROTATER((v7 ^ v11), 7);        \
}                                   

/* G function for first diagonal */
#define G4(M0, M1, C0, C1)              \
{                                       \
    v0 += v5 + (M0 ^ C1);               \
    v15 = ROTATER((v15 ^ v0), 16);      \
    v10 += v15;                         \
    v5 = ROTATER((v5 ^ v10), 12);       \
    v0 += v5 + (M1 ^ C0);               \
    v15 = ROTATER((v15 ^ v0), 8);       \
    v10 += v15;                         \
    v5 = ROTATER((v5 ^ v10), 7);        \
}                                   

/* G function for second diagonal */ 
#define G5(M0, M1, C0, C1)              \
{                                       \
    v1 += v6 + (M0 ^ C1);               \
    v12 = ROTATER((v12 ^ v1), 16);      \
    v11 += v12;                         \
    v6 = ROTATER((v6 ^ v11), 12);       \
    v1 += v6 + (M1 ^ C0);               \
    v12 = ROTATER((v12 ^ v1), 8);       \
    v11 += v12;                         \
    v6 = ROTATER((v6 ^ v11), 7);        \
}                                   

/* G function for third diagonal */
#define G6(M0, M1, C0, C1)              \
{                                       \
    v2 += v7 + (M0 ^ C1);               \
    v13 = ROTATER((v13 ^ v2), 16);      \
    v8 += v13;                          \
    v7 = ROTATER((v7 ^ v8), 12);        \
    v2 += v7 + (M1 ^ C0);               \
    v13 = ROTATER((v13 ^ v2), 8);       \
    v8 += v13;                          \
    v7 = ROTATER((v7 ^ v8), 7);         \
}


/* G function for fourth diagonal */
#define G7(M0, M1, C0, C1)              \
{                                       \
    v3 += v4 + (M0 ^ C1);               \
    v14 = ROTATER((v14 ^ v3), 16);      \
    v9 += v14;                          \
    v4 = ROTATER((v4 ^ v9), 12);        \
    v3 += v4 + (M1 ^ C0);               \
    v14 = ROTATER((v14 ^ v3), 8);       \
    v9 += v14;                          \
    v4 = ROTATER((v4 ^ v9), 7);         \
}                                   


void raazHashBlake256PortableCompress(Hash hash, Salt salt, uint64_t *counter, int nblocks, Block *mesg)
{

    Word t0,t1;  /* Counter variables */

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
        *counter = *counter + 512;  

        t0 = (Word)*counter;                    
        t1 = (Word)(*counter >> 32);
                
        /* Initialization of the state consisting of 16 words */                
        v0 = hash[0];
        v1 = hash[1];
        v2 = hash[2];
        v3 = hash[3];
        v4 = hash[4];
        v5 = hash[5];
        v6 = hash[6];
        v7 = hash[7];
        v8 = salt[0] ^ c0;
        v9 = salt[1] ^ c1;
        v10 = salt[2] ^ c2; 
        v11 = salt[3] ^ c3;
        v12 = t0 ^ c4; 
        v13 = t0 ^ c5; 
        v14 = t1 ^ c6; 
        v15 = t1 ^ c7;

        /* Loading the message into 16 words */     
        m0 = raazLoad32BE((Word *)mesg,0);
        m1 = raazLoad32BE((Word *)mesg,1);
        m2 = raazLoad32BE((Word *)mesg,2);
        m3 = raazLoad32BE((Word *)mesg,3);
        m4 = raazLoad32BE((Word *)mesg,4);
        m5 = raazLoad32BE((Word *)mesg,5);
        m6 = raazLoad32BE((Word *)mesg,6);
        m7 = raazLoad32BE((Word *)mesg,7);
        m8 = raazLoad32BE((Word *)mesg,8);
        m9 = raazLoad32BE((Word *)mesg,9);
        m10 = raazLoad32BE((Word *)mesg,10); 
        m11 = raazLoad32BE((Word *)mesg,11); 
        m12 = raazLoad32BE((Word *)mesg,12); 
        m13 = raazLoad32BE((Word *)mesg,13); 
        m14 = raazLoad32BE((Word *)mesg,14); 
        m15 = raazLoad32BE((Word *)mesg,15);
        
        /* End of reading the message block */


        /*
        Loop unrollings are being done after every round so as to improve the 
        performance. 
        */

        /* Round 1 */
        /* Column Steps 0-3 */
        G0( m0, m1, c0, c1 );
        G1( m2, m3, c2, c3 );
        G2( m4, m5, c4, c5 );
        G3( m6, m7, c6, c7 );

        /* Diagonal-Step 4-7 */  
        G4( m8 , m9 , c8 , c9  );
        G5( m10, m11, c10, c11 );
        G6( m12, m13, c12, c13 );
        G7( m14, m15, c14, c15 );


        /* Round 2 */
        /* Column Step 0-3 */
        G0( m14, m10, c14, c10 );
        G1( m4 , m8 , c4 , c8  );
        G2( m9 , m15, c9 , c15 );
        G3( m13, m6 , c13, c6  );

        /* Diagonal Step 4-7 */
        G4( m1 , m12, c1 , c12 );
        G5( m0 , m2 , c0 , c2  );
        G6( m11, m7 , c11, c7  );
        G7( m5 , m3 , c5 , c3  );


        /* Round 3 */
        /* Column Step 0-3 */
        G0( m11, m8 , c11, c8  );
        G1( m12, m0 , c12, c0  );
        G2( m5 , m2 , c5 , c2  );
        G3( m15, m13, c15, c13 );

        /* Diagonal Step 4-7 */
        G4( m10, m14, c10, c14 );
        G5( m3 , m6 , c3 , c6  );
        G6( m7 , m1 , c7 , c1  );
        G7( m9 , m4 , c9 , c4  );


        /* Round 4 */
        /* Column Step 0-3 */
        G0( m7 , m9 , c7 , c9  );
        G1( m3 , m1 , c3 , c1  );
        G2( m13, m12, c13, c12 );
        G3( m11, m14, c11, c14 );

        /* Diagonal Step 4-7 */
        G4( m2 , m6 , c2 , c6  );
        G5( m5 , m10, c5 , c10 );
        G6( m4 , m0 , c4 , c0  );
        G7( m15, m8 , c15, c8  );


        /* Round 5 */
        /* Column Step 0-3 */
        G0( m9 , m0 , c9 , c0  );
        G1( m5 , m7 , c5 , c7  );
        G2( m2 , m4 , c2 , c4  );
        G3( m10, m15, c10, c15 );

        /* Diagonal Step 4-7 */
        G4( m14, m1 , c14, c1  );
        G5( m11, m12, c11, c12 );
        G6( m6 , m8 , c6 , c8  );
        G7( m3 , m13, c3 , c13 );


        /* Round 6 */
        /* Column Step 0-3 */
        G0( m2, m12, c2, c12 );
        G1( m6, m10, c6, c10 );
        G2( m0, m11, c0, c11 );
        G3( m8, m3 , c8, c3  );

        /* Diagonal Step 4-7 */
        G4( m4 , m13, c4 , c13 );
        G5( m7 , m5 , c7 , c5  );
        G6( m15, m14, c15, c14 );
        G7( m1 , m9 , c1 , c9  );


        /* Round 7 */
        /* Column Step 0-3 */
        G0( m12, m5 , c12, c5 );
        G1( m1 , m15, c1 , c15 );
        G2( m14, m13, c14, c13 );
        G3( m4 , m10, c4 , c10 );

        /* Diagonal Step 4-7 */
        G4( m0, m7 , c0, c7  );
        G5( m6, m3 , c6, c3  );
        G6( m9, m2 , c9, c2  ); 
        G7( m8, m11, c8, c11 );


        /* Round 8 */
        /* Column Step 0-3 */
        G0( m13, m11, c13, c11 );
        G1( m7 , m14, c7 , c14 );
        G2( m12, m1 , c12, c1  );
        G3( m3 , m9 , c3 , c9  );

        /* Diagonal Step 4-7 */
        G4( m5 , m0 , c5 , c0  );
        G5( m15, m4 , c15, c4  );
        G6( m8 , m6 , c8 , c6  );
        G7( m2 , m10, c2 , c10 );


        /* Round 9 */
        /* Column Step 0-3 */
        G0( m6 , m15, c6 , c15 );
        G1( m14, m9 , c14, c9  );
        G2( m11, m3 , c11, c3  );
        G3( m0 , m8 , c0 , c8  );

        /* Diagonal Step 4-7 */
        G4( m12, m2, c12, c2 );
        G5( m13, m7, c13, c7 );
        G6( m1 , m4, c1 , c4 );
        G7( m10, m5, c10, c5 );


        /* Round 10 */
        /* Column Step 0-3 */
        G0( m10, m2, c10, c2 );
        G1( m8 , m4, c8 , c4 );
        G2( m7 , m6, c7 , c6 );
        G3( m1 , m5, c1 , c5 );

        /* Diagonal Step 4-7 */
        G4( m15, m11, c15, c11 );
        G5( m9 , m14, c9 , c14 );
        G6( m3 , m12, c3 , c12 );
        G7( m13, m0 , c13, c0  );


        /* Round 11 */
        /* Column Steps 0-3 */
        G0( m0, m1, c0, c1 );
        G1( m2, m3, c2, c3 );
        G2( m4, m5, c4, c5 );
        G3( m6, m7, c6, c7 );

        /* Diagonal-Step 4-7 */  
        G4( m8 , m9 , c8 , c9  );
        G5( m10, m11, c10, c11 );
        G6( m12, m13, c12, c13 );
        G7( m14, m15, c14, c15 );
        

        /* Round 12 */
        /* Column Step 0-3 */
        G0( m14, m10, c14, c10 );
        G1( m4 , m8 , c4 , c8  );
        G2( m9 , m15, c9 , c15 );
        G3( m13, m6 , c13, c6  );

        /* Diagonal Step 4-7 */
        G4( m1 , m12, c1 , c12 );
        G5( m0 , m2 , c0 , c2  );
        G6( m11, m7 , c11, c7  );
        G7( m5 , m3 , c5 , c3  );


        /* Round 13 */
        /* Column Step 0-3 */
        G0( m11, m8 , c11, c8  );
        G1( m12, m0 , c12, c0  );
        G2( m5 , m2 , c5 , c2  );
        G3( m15, m13, c15, c13 );
  
        /* Diagonal Step 4-7 */
        G4( m10, m14, c10, c14 );
        G5( m3 , m6 , c3 , c6  );
        G6( m7 , m1 , c7 , c1  );
        G7( m9 , m4 , c9 , c4  );


        /* Round 14 */
        /* Column Step 0-3 */
        G0( m7 , m9 , c7 , c9  );
        G1( m3 , m1 , c3 , c1  );
        G2( m13, m12, c13, c12 );
        G3( m11, m14, c11, c14 );

        /* Diagonal Step 4-7 */
        G4( m2 , m6 , c2 , c6  );
        G5( m5 , m10, c5 , c10 );
        G6( m4 , m0 , c4 , c0  );
        G7( m15, m8 , c15, c8  );



        /* Updation of hash variables with the new chain value */
        hash[0] = hash[0] ^ salt[0] ^ v0 ^ v8;
        hash[1] = hash[1] ^ salt[1] ^ v1 ^ v9;
        hash[2] = hash[2] ^ salt[2] ^ v2 ^ v10;
        hash[3] = hash[3] ^ salt[3] ^ v3 ^ v11;
        hash[4] = hash[4] ^ salt[0] ^ v4 ^ v12;     
        hash[5] = hash[5] ^ salt[1] ^ v5 ^ v13;     
        hash[6] = hash[6] ^ salt[2] ^ v6 ^ v14; 
        hash[7] = hash[7] ^ salt[3] ^ v7 ^ v15;     
        
        ++mesg; /* Incrementing to the next block */
        --nblocks;
    }   
}
