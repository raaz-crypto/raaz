//RAAZ - BLAKE256 IMPLEMENTATION
#include <stdio.h>
#include <stdint.h>
#include <string.h>			
#include <raaz/primitives/load.h>

typedef uint32_t word;
#define HASH_SIZE 8
#define BLOCK_SIZE 16
#define SALT_SIZE 4
#define counte_SIZE 2
#define ROTATEL(x,n) ((x << n) | (x >> (32-n)))
#define ROTATER(x,n) ((x >> n) | (x << (32-n)))
typedef word Hash[HASH_SIZE];
typedef word Block[BLOCK_SIZE];
typedef word Salt[SALT_SIZE];

static const word permut[10][16] = {{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
									{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
									{11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
									{7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
									{9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
									{2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
									{12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
									{13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
									{6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
									{10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}};	

#define gfunc(a0,a1,b0,b1,c0,c1,d0,d1,round,i)	\
  round = round % 10;  \
  index1 = permut[round][2*i]; \
  index2 = permut[round][2*i + 1]; \
  v[a0][a1] += v[b0][b1] + (mblock[index1] ^ constant[index2]);	\
  v[d0][d1] =  ROTATER((v[d0][d1] ^ v[a0][a1]), 16);	 \
  v[c0][c1] += v[d0][d1];	\
  v[b0][b1] = ROTATER((v[b0][b1] ^ v[c0][c1]), 12);	\
 v[a0][a1] += v[b0][b1] + (mblock[index2] ^ constant[index1]);	\
 v[d0][d1] = ROTATER((v[d0][d1] ^ v[a0][a1]), 8);	\
  v[c0][c1] += v[d0][d1];		\
  v[b0][b1] = ROTATER((v[b0][b1] ^ v[c0][c1]),7); \

void raazHashBlake256PortableCompress(Hash hash, Salt salt, uint64_t *counter, int nblocks, Block *mesg){

	int rounds = 0;
	int index1, index2;
	word coun[counte_SIZE];
	word mblock[BLOCK_SIZE];
	word constant[16];
	word v[4][4];

	constant[0] = 0x243F6A88;	constant[1] = 0x85A308D3; 	constant[2] = 0x13198A2E;
	constant[3] = 0x03707344;	constant[4] = 0xA4093822;	constant[5] = 0x299F31D0;	
	constant[6] = 0x082EFA98;	constant[7] = 0xEC4E6C89;	constant[8] = 0x452821E6;
	constant[9] = 0x38D01377;	constant[10] = 0xBE5466CF;	constant[11] = 0x34E90C6C;
	constant[12] = 0xC0AC29B7;	constant[13] = 0xC97C50DD;	constant[14] = 0x3F84D5B5;
	constant[15] = 0xB5470917;	

	while(nblocks > 0){
		
		*counter = *counter + 512;
		coun[0] = (word)*counter;
		coun[1] = (word)(*counter >> 32);
				
		v[0][0] = hash[0]; v[0][1] = hash[1]; v[0][2] = hash[2]; v[0][3] = hash[3];	
		v[1][0] = hash[4]; v[1][1] = hash[5]; v[1][2] = hash[6]; v[1][3] = hash[7];
		v[2][0] = salt[0] ^ constant[0];
		v[2][1] = salt[1] ^ constant[1]; 
		v[2][2] = salt[2] ^ constant[2]; 
		v[2][3] = salt[3] ^ constant[3];
		v[3][0] = coun[0] ^ constant[4]; 
		v[3][1] = coun[0] ^ constant[5]; 
		v[3][2] = coun[1] ^ constant[6]; 
		v[3][3] = coun[1] ^ constant[7];

		mblock[0] = raazLoad32BE((word *)mesg,0);
		mblock[1] = raazLoad32BE((word *)mesg,1);
		mblock[2] = raazLoad32BE((word *)mesg,2);
		mblock[3] = raazLoad32BE((word *)mesg,3);
		mblock[4] = raazLoad32BE((word *)mesg,4);
		mblock[5] = raazLoad32BE((word *)mesg,5);
		mblock[6] = raazLoad32BE((word *)mesg,6);
		mblock[7] = raazLoad32BE((word *)mesg,7);
		mblock[8] = raazLoad32BE((word *)mesg,8);
		mblock[9] = raazLoad32BE((word *)mesg,9);
		mblock[10] = raazLoad32BE((word *)mesg,10); 
		mblock[11] = raazLoad32BE((word *)mesg,11); 
		mblock[12] = raazLoad32BE((word *)mesg,12); 
		mblock[13] = raazLoad32BE((word *)mesg,13); 
		mblock[14] = raazLoad32BE((word *)mesg,14); 
		mblock[15] = raazLoad32BE((word *)mesg,15); 
		
		
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

			rounds++;
		//Column Step
			gfunc( 0, 0, 1, 0, 2, 0, 3, 0, rounds, 0);			
			gfunc( 0, 1, 1, 1, 2, 1, 3, 1, rounds, 1);			
			gfunc( 0, 2, 1, 2, 2, 2, 3, 2, rounds, 2);
			gfunc( 0, 3, 1, 3, 2, 3, 3, 3, rounds, 3);

		//Diagonal Step
			gfunc( 0, 0, 1, 1, 2, 2, 3, 3, rounds, 4);		
			gfunc( 0, 1, 1, 2, 2, 3, 3, 0, rounds, 5);
			gfunc( 0, 2, 1, 3, 2, 0, 3, 1, rounds, 6);
			gfunc( 0, 3, 1, 0, 2, 1, 3, 2, rounds, 7);

		hash[0] = hash[0] ^ salt[0] ^ v[0][0] ^ v[2][0];
		hash[1] = hash[1] ^ salt[1] ^ v[0][1] ^ v[2][1];
		hash[2] = hash[2] ^ salt[2] ^ v[0][2] ^ v[2][2];
		hash[3] = hash[3] ^ salt[3] ^ v[0][3] ^ v[2][3];
		hash[4] = hash[4] ^ salt[0] ^ v[1][0] ^ v[3][0];
		hash[5] = hash[5] ^ salt[1] ^ v[1][1] ^ v[3][1];
		hash[6] = hash[6] ^ salt[2] ^ v[1][2] ^ v[3][2];	
		hash[7] = hash[7] ^ salt[3] ^ v[1][3] ^ v[3][3];
		
		rounds = 0;
		mesg++;
		nblocks--;
		

	}
	
}