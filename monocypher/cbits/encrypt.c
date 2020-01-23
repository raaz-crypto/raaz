/* This is a small encrypt function written for testing and
 * benchmarking and is not part of the monocypher distribution. Do not
 * use this in production.
 */

#include "monocypher.h"

void chacha20(const uint8_t key[32], const uint8_t nounce[8],
	      const uint8_t *plain_text, size_t text_size,
	      uint8_t *cipher_text)
{
    crypto_chacha_ctx ctx;
    crypto_chacha20_init(&ctx, key, nounce);
    crypto_chacha20_encrypt(&ctx,cipher_text,plain_text, text_size);
}

void xchacha20(const uint8_t key[32], const uint8_t nounce[24],
	       const uint8_t *plain_text, size_t text_size,
	       uint8_t *cipher_text)
{
    crypto_chacha_ctx ctx;
    crypto_chacha20_x_init(&ctx, key, nounce);
    crypto_chacha20_encrypt(&ctx,cipher_text,plain_text, text_size);
}
