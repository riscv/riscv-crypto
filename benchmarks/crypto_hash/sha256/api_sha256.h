
#include <stdint.h>

#define CRYPTO_HASH_SHA256_BYTES 32
#define CRYPTO_HASH_SHA256_STATEBYTES 32
#define CRYPTO_HASH_SHA256_BLOCKBYTES 64

//! Top level hash function.
int crypto_hash_sha256(
    unsigned char *out,
    const unsigned char *in,
    unsigned long long inlen
);

//! Round function.
int crypto_hashblocks_sha256(
    unsigned char *statebytes,
    const unsigned char *in,
    unsigned long long inlen
);
