#ifndef __RAAZ_CIPHER_AES_H_
#define __RAAZ_CIPHER_AES_H_
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

typedef uint8_t  Word8;
typedef uint32_t Word32;
typedef uint64_t Word64;

typedef enum {KEY128=0, KEY192=1, KEY256=2} KEY;

extern void raazCipherAESExpand(Word32 *expandedKey, Word8 *key, Word8 k);
extern void raazCipherAESBlockEncrypt(Word32 *eKey, Word8 *block, Word8 k);
extern void raazCipherAESBlockDecrypt(Word32 *eKey, Word8 *block, Word8 k);
extern void raazCipherAESECBEncrypt(Word32 *key, Word8 *input, Word32 nblocks, Word8 k);
extern void raazCipherAESECBDecrypt(Word32 *key, Word8 *input, Word32 nblocks, Word8 k);
extern void raazCipherAESCBCEncrypt(Word32 *key, Word8 *input, Word8 *iv, Word32 nblocks, KEY k);
extern void raazCipherAESCBCDecrypt(Word32 *key, Word8 *input, Word8 *iv, Word32 nblocks, KEY k);
extern void raazCipherAESCTREncrypt(Word32 *key, Word8 *input, Word8 *iv, Word32 len, KEY k);

#endif
