
/*!
@defgroup crypto_hash_sha512 Crypto Hash SHA512
@{
*/

#include <stdint.h>

#include "riscvcrypto/share/util.h"

//! Length of the SHA512 signature array in bytes.
#define CRYPTO_HASH_SHA512_BYTES 64

//! Size of the SHA512 state array in bytes.
#define CRYPTO_HASH_SHA512_STATEBYTES 64

//! Size of the SHA512 block in bytes.
#define CRYPTO_HASH_SHA512_BLOCKBYTES 128

/*!
@brief Top level function for SHA512 for hashing N bytes of data.
@param [out] out - The output signature array. CRYPTO_HASH_SHA512_BYTES long.
@param [in] in - The input data array to hash.
@param [in] inlen - The length of the input data array.
@returns 0
*/
int crypto_hash_sha512(
    unsigned char *out,
    const unsigned char *in,
    unsigned long long inlen
);

/*!
@brief The SHA512 Permutation function.
@param [in,out] statebytes - Current signature state array to add the input to.
@param [in] in - Data to add to the permutation.
@param [in] inlen - Length of the input data.
@returns The remainder of inlen after digesting `in` 128 bytes at a time.
*/
int crypto_hashblocks_sha512(
    unsigned char *statebytes,
    const unsigned char *in,
    unsigned long long inlen
);

//! @}

