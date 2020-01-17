
#include <stdint.h>

#include "riscvcrypto/share/util.h"

#define CRYPTO_HASH_SHA512_BYTES 64
#define CRYPTO_HASH_SHA512_STATEBYTES 64
#define CRYPTO_HASH_SHA512_BLOCKBYTES 128

//! Top level hash function.
int crypto_hash_sha512(
    unsigned char *out,
    const unsigned char *in,
    unsigned long long inlen
);

//! Round function
int crypto_hashblocks_sha512(
    unsigned char *statebytes,
    const unsigned char *in,
    unsigned long long inlen
);
