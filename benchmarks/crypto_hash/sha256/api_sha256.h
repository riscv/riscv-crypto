
/*!
@defgroup crypto_hash_sha256 Crypto Hash SHA256
@{
*/

#include <stdint.h>

#include "riscvcrypto/share/util.h"

#ifndef __API_SHA256__
#define __API_SHA256__

//! The length of a SHA256 signature in bytes
#define CRYPTO_HASH_SHA256_BYTES 32

//! Size of the SHA256 state array in bytes.
#define CRYPTO_HASH_SHA256_STATEBYTES 32

//! Size of the SHA256 block in bytes.
#define CRYPTO_HASH_SHA256_BLOCKBYTES 64

/*!
@brief Top level function for SHA256 for hashing N bytes of data.
@param [out] out - The output signature array. CRYPTO_HASH_SHA256_BYTES long.
@param [in] in - The input data array to hash.
@param [in] inlen - The length of the input data array.
@returns 0
*/
int crypto_hash_sha256(
    unsigned char *out,
    const unsigned char *in,
    unsigned long long inlen
);

/*!
@brief The SHA256 Permutation function.
@param [in,out] statebytes - Current signature state array to add the input to.
@param [in] in - Data to add to the permutation.
@param [in] inlen - Length of the input data.
@returns The remainder of inlen after digesting `in` 64 bytes at a time.
*/
int crypto_hashblocks_sha256(
    unsigned char *statebytes,
    const unsigned char *in,
    unsigned long long inlen
);

/*! @} */

#endif // __API_SHA256__
