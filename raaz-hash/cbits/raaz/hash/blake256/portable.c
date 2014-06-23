/*

Portable C implementation of  BLAKE256 Hash.
This is a part of raaz cryptographic library.

*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>         
#include <raaz/primitives/load.h>

#define HASH_SIZE 8     
#define BLOCK_SIZE 16   /* Size of a block */
#define SALT_SIZE 4     /* Size of input salt */
#define ROTATEL(x,n) ((x << n) | (x >> (32-n)))
#define ROTATER(x,n) ((x >> n) | (x << (32-n)))

typedef uint32_t Word;      /* Basic unit for BLAKE hash */
typedef Word Hash[HASH_SIZE];
typedef Word Block[BLOCK_SIZE];
typedef Word Salt[SALT_SIZE];

/* Defining 16 Constants */
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


/* G function for first column */
#define G0                              \
{                                       \
    v0 += v4 + ((M00) ^ (C01));         \
    v12 =  ROTATER(((v12) ^ (v0)), 16); \
    v8 += v12;                          \
    v4 = ROTATER(((v4) ^ (v8)), 12);    \
    v0 += v4 + ((M01) ^ (C00));         \
    v12 = ROTATER(((v12) ^ (v0)), 8);   \
    v8 += v12;                          \
    v4 = ROTATER(((v4) ^ (v8)),7);      \
}   

/* G function for second column */
#define G1                              \
{                                       \
    v1 += v5 + (M10 ^ C11);             \
    v13 = ROTATER((v13 ^ v1), 16);      \
    v9 += v13;                          \
    v5 = ROTATER((v5 ^ v9), 12);        \
    v1 += v5 + (M11 ^ C10);             \
    v13 = ROTATER((v13 ^ v1), 8);       \
    v9 += v13;                          \
    v5 = ROTATER((v5 ^ v9), 7);         \
}                       

/* G function for third column */
#define G2                              \
{                                       \
    v2 += v6 + (M20 ^ C21);             \
    v14 = ROTATER((v14 ^ v2), 16);      \
    v10 += v14;                         \
    v6 = ROTATER((v6 ^ v10), 12);       \
    v2 += v6 + (M21 ^ C20);             \
    v14 = ROTATER((v14 ^ v2), 8);       \
    v10 += v14;                         \
    v6 = ROTATER((v6 ^ v10), 7);        \
}                   

/* G function for fourth column */
#define G3                              \
{                                       \
    v3 += v7 + (M30 ^ C31);             \
    v15 = ROTATER((v15 ^ v3), 16);      \
    v11 += v15;                         \
    v7 = ROTATER((v7 ^ v11), 12);       \
    v3 += v7 + (M31 ^ C30);             \
    v15 = ROTATER((v15 ^ v3), 8);       \
    v11 += v15;                         \
    v7 = ROTATER((v7 ^ v11), 7);        \
}                                   

/* G function for first diagonal */
#define G4                              \
{                                       \
    v0 += v5 + (M40 ^ C41);             \
    v15 = ROTATER((v15 ^ v0), 16);      \
    v10 += v15;                         \
    v5 = ROTATER((v5 ^ v10), 12);       \
    v0 += v5 + (M41 ^ C40);             \
    v15 = ROTATER((v15 ^ v0), 8);       \
    v10 += v15;                         \
    v5 = ROTATER((v5 ^ v10), 7);        \
}                                   

/* G function for second diagonal */ 
#define G5                              \
{                                       \
    v1 += v6 + (M50 ^ C51);             \
    v12 = ROTATER((v12 ^ v1), 16);      \
    v11 += v12;                         \
    v6 = ROTATER((v6 ^ v11), 12);       \
    v1 += v6 + (M51 ^ C50);             \
    v12 = ROTATER((v12 ^ v1), 8);       \
    v11 += v12;                         \
    v6 = ROTATER((v6 ^ v11), 7);        \
}                                   

/* G function for third diagonal */
#define G6                              \
{                                       \
    v2 += v7 + (M60 ^ C61);             \
    v13 = ROTATER((v13 ^ v2), 16);      \
    v8 += v13;                          \
    v7 = ROTATER((v7 ^ v8), 12);        \
    v2 += v7 + (M61 ^ C60);             \
    v13 = ROTATER((v13 ^ v2), 8);       \
    v8 += v13;                          \
    v7 = ROTATER((v7 ^ v8), 7);         \
}


/* G function for fourth diagonal */
#define G7                              \
{                                       \
    v3 += v4 + (M70 ^ C71);             \
    v14 = ROTATER((v14 ^ v3), 16);      \
    v9 += v14;                          \
    v4 = ROTATER((v4 ^ v9), 12);        \
    v3 += v4 + (M71 ^ C70);             \
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
    
    /* State variables */
    Word v0;    
    Word v1;
    Word v2;
    Word v3;
    Word v4;
    Word v5;
    Word v6;
    Word v7;
    Word v8;
    Word v9;
    Word v10;
    Word v11;
    Word v12;
    Word v13;
    Word v14;
    Word v15;

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


/* Defining message variables for round 1 */
#define M00 m0
#define M01 m1
#define M10 m2
#define M11 m3
#define M20 m4
#define M21 m5
#define M30 m6      
#define M31 m7
#define M40 m8      
#define M41 m9
#define M50 m10
#define M51 m11
#define M60 m12
#define M61 m13
#define M70 m14
#define M71 m15

/* Defining constant variables for round 1 */
#define C00 c0
#define C01 c1
#define C10 c2
#define C11 c3
#define C20 c4
#define C21 c5
#define C30 c6      
#define C31 c7
#define C40 c8
#define C41 c9
#define C50 c10
#define C51 c11
#define C60 c12
#define C61 c13
#define C70 c14
#define C71 c15
                    /* Round 1 */
                    /* Column Steps 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal-Step 4-7 */  
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31                  
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 2 */
#define M00 m14
#define M01 m10
#define M10 m4
#define M11 m8
#define M20 m9
#define M21 m15
#define M30 m13
#define M31 m6      
#define M40 m1
#define M41 m12
#define M50 m0
#define M51 m2
#define M60 m11
#define M61 m7
#define M70 m5
#define M71 m3


/* Defining constant variables for round 2 */
#define C00 c14
#define C01 c10
#define C10 c4
#define C11 c8
#define C20 c9
#define C21 c15
#define C30 c13
#define C31 c6      
#define C40 c1
#define C41 c12
#define C50 c0
#define C51 c2
#define C60 c11
#define C61 c7
#define C70 c5
#define C71 c3
                    /* Round 2 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 3 */
#define M00 m11
#define M01 m8
#define M10 m12
#define M11 m0
#define M20 m5
#define M21 m2
#define M30 m15
#define M31 m13
#define M40 m10         
#define M41 m14
#define M50 m3
#define M51 m6
#define M60 m7
#define M61 m1
#define M70 m9
#define M71 m4

/* Defining constant variables for round 3 */
#define C00 c11
#define C01 c8
#define C10 c12
#define C11 c0
#define C20 c5
#define C21 c2
#define C30 c15
#define C31 c13
#define C40 c10
#define C41 c14
#define C50 c3
#define C51 c6
#define C60 c7
#define C61 c1
#define C70 c9
#define C71 c4
                    /* Round 3 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 4 */
#define M00 m7
#define M01 m9
#define M10 m3
#define M11 m1
#define M20 m13
#define M21 m12
#define M30 m11
#define M31 m14
#define M40 m2      
#define M41 m6
#define M50 m5
#define M51 m10
#define M60 m4
#define M61 m0
#define M70 m15
#define M71 m8

/* Defining constant variables for round 4 */
#define C00 c7
#define C01 c9
#define C10 c3
#define C11 c1
#define C20 c13
#define C21 c12
#define C30 c11
#define C31 c14     
#define C40 c2
#define C41 c6
#define C50 c5
#define C51 c10
#define C60 c4
#define C61 c0
#define C70 c15
#define C71 c8
                    /* Round 4 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 5 */
#define M00 m9
#define M01 m0
#define M10 m5
#define M11 m7
#define M20 m2
#define M21 m4
#define M30 m10
#define M31 m15
#define M40 m14     
#define M41 m1
#define M50 m11
#define M51 m12
#define M60 m6
#define M61 m8
#define M70 m3
#define M71 m13

/* Defining constant variables for round 5 */
#define C00 c9
#define C01 c0
#define C10 c5
#define C11 c7
#define C20 c2
#define C21 c4
#define C30 c10
#define C31 c15     
#define C40 c14
#define C41 c1
#define C50 c11
#define C51 c12
#define C60 c6
#define C61 c8
#define C70 c3
#define C71 c13
                    /* Round 5 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 6 */
#define M00 m2
#define M01 m12
#define M10 m6
#define M11 m10
#define M20 m0
#define M21 m11
#define M30 m8
#define M31 m3
#define M40 m4      
#define M41 m13
#define M50 m7
#define M51 m5
#define M60 m15
#define M61 m14
#define M70 m1
#define M71 m9

/* Defining constant variables for round 6 */
#define C00 c2
#define C01 c12
#define C10 c6
#define C11 c10
#define C20 c0
#define C21 c11
#define C30 c8
#define C31 c3      
#define C40 c4
#define C41 c13
#define C50 c7
#define C51 c5
#define C60 c15
#define C61 c14
#define C70 c1
#define C71 c9
                    /* Round 6 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 7 */
#define M00 m12
#define M01 m5
#define M10 m1
#define M11 m15
#define M20 m14
#define M21 m13
#define M30 m4
#define M31 m10
#define M40 m0      
#define M41 m7
#define M50 m6
#define M51 m3
#define M60 m9
#define M61 m2
#define M70 m8
#define M71 m11

/* Defining constant variables for round 7 */
#define C00 c12
#define C01 c5
#define C10 c1
#define C11 c15
#define C20 c14
#define C21 c13
#define C30 c4
#define C31 c10     
#define C40 c0
#define C41 c7
#define C50 c6
#define C51 c3
#define C60 c9
#define C61 c2
#define C70 c8
#define C71 c11
                    /* Round 7 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6; 
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 8 */
#define M00 m13
#define M01 m11
#define M10 m7
#define M11 m14
#define M20 m12
#define M21 m1
#define M30 m3
#define M31 m9      
#define M40 m5
#define M41 m0
#define M50 m15
#define M51 m4
#define M60 m8
#define M61 m6
#define M70 m2
#define M71 m10

/* Defining constant variables for round 8 */
#define C00 c13
#define C01 c11
#define C10 c7
#define C11 c14
#define C20 c12
#define C21 c1
#define C30 c3      
#define C31 c9
#define C40 c5
#define C41 c0
#define C50 c15
#define C51 c4
#define C60 c8
#define C61 c6
#define C70 c2
#define C71 c10
                    /* Round 8 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 9 */
#define M00 m6
#define M01 m15
#define M10 m14
#define M11 m9
#define M20 m11
#define M21 m3
#define M30 m0
#define M31 m8      
#define M40 m12
#define M41 m2
#define M50 m13
#define M51 m7
#define M60 m1
#define M61 m4
#define M70 m10
#define M71 m5

/* Defining constant variables for round 9 */
#define C00 c6
#define C01 c15
#define C10 c14
#define C11 c9
#define C20 c11
#define C21 c3
#define C30 c0
#define C31 c8
#define C40 c12
#define C41 c2
#define C50 c13
#define C51 c7
#define C60 c1
#define C61 c4
#define C70 c10
#define C71 c5
                    /* Round 9 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 10 */
#define M00 m10
#define M01 m2
#define M10 m8
#define M11 m4
#define M20 m7
#define M21 m6
#define M30 m1
#define M31 m5      
#define M40 m15
#define M41 m11
#define M50 m9
#define M51 m14
#define M60 m3
#define M61 m12
#define M70 m13
#define M71 m0

/* Defining constant variables for round 10 */
#define C00 c10
#define C01 c2
#define C10 c8
#define C11 c4
#define C20 c7
#define C21 c6
#define C30 c1
#define C31 c5      
#define C40 c15
#define C41 c11
#define C50 c9
#define C51 c14
#define C60 c3
#define C61 c12
#define C70 c13
#define C71 c0
                    /* Round 10 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 11 */
#define M00 m0
#define M01 m1
#define M10 m2
#define M11 m3
#define M20 m4
#define M21 m5
#define M30 m6
#define M31 m7      
#define M40 m8
#define M41 m9
#define M50 m10
#define M51 m11
#define M60 m12
#define M61 m13
#define M70 m14
#define M71 m15

/* Defining constant variables for round 11 */
#define C00 c0
#define C01 c1
#define C10 c2
#define C11 c3
#define C20 c4
#define C21 c5
#define C30 c6
#define C31 c7
#define C40 c8      
#define C41 c9
#define C50 c10
#define C51 c11
#define C60 c12
#define C61 c13
#define C70 c14
#define C71 c15
                    /* Round 11 */
                    /* Column Steps 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal-Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71

        
/* Defining message variables for round 12 */
#define M00 m14
#define M01 m10
#define M10 m4
#define M11 m8
#define M20 m9
#define M21 m15
#define M30 m13
#define M31 m6
#define M40 m1      
#define M41 m12
#define M50 m0
#define M51 m2
#define M60 m11
#define M61 m7
#define M70 m5
#define M71 m3

/* Defining constant variables for round 12 */
#define C00 c14
#define C01 c10
#define C10 c4
#define C11 c8
#define C20 c9
#define C21 c15
#define C30 c13
#define C31 c6      
#define C40 c1
#define C41 c12
#define C50 c0
#define C51 c2
#define C60 c11
#define C61 c7
#define C70 c5
#define C71 c3
                    /* Round 12 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 13 */
#define M00 m11
#define M01 m8
#define M10 m12
#define M11 m0
#define M20 m5
#define M21 m2
#define M30 m15
#define M31 m13
#define M40 m10
#define M41 m14
#define M50 m3
#define M51 m6
#define M60 m7
#define M61 m1
#define M70 m9
#define M71 m4

/* Defining constant variables for round 13 */
#define C00 c11
#define C01 c8
#define C10 c12
#define C11 c0
#define C20 c5
#define C21 c2
#define C30 c15
#define C31 c13
#define C40 c10     
#define C41 c14
#define C50 c3
#define C51 c6
#define C60 c7
#define C61 c1
#define C70 c9
#define C71 c4
                    /* Round 13 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71


/* Defining message variables for round 14 */
#define M00 m7
#define M01 m9
#define M10 m3
#define M11 m1
#define M20 m13
#define M21 m12
#define M30 m11
#define M31 m14     
#define M40 m2
#define M41 m6
#define M50 m5
#define M51 m10
#define M60 m4
#define M61 m0
#define M70 m15
#define M71 m8

/* Defining constant variables for round 14 */
#define C00 c7
#define C01 c9
#define C10 c3
#define C11 c1
#define C20 c13
#define C21 c12
#define C30 c11     
#define C31 c14
#define C40 c2
#define C41 c6
#define C50 c5
#define C51 c10
#define C60 c4
#define C61 c0
#define C70 c15
#define C71 c8
                    /* Round 14 */
                    /* Column Step 0-3 */
                    G0;
                    G1;
                    G2;
                    G3;

                    /* Diagonal Step 4-7 */
                    G4;
                    G5;
                    G6;
                    G7;

#undef M00
#undef M01
#undef M10
#undef M11
#undef M20
#undef M21
#undef M30
#undef M31
#undef M40
#undef M41
#undef M50
#undef M51
#undef M60
#undef M61
#undef M70
#undef M71

#undef C00
#undef C01
#undef C10
#undef C11
#undef C20
#undef C21
#undef C30
#undef C31
#undef C40
#undef C41
#undef C50
#undef C51
#undef C60
#undef C61
#undef C70
#undef C71

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