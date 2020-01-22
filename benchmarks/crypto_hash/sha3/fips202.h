
#include <stdint.h>
#include <string.h>

#include "riscvcrypto/crypto_hash/sha3/Keccak.h"

#ifndef __FIPS202_H__

/*!
@defgroup crypto_hash_sha3 Crypto Hash SHA3
@{
*/

#define CRYPTO_HASH_SHA3_224_OUTPUT_LENGTH 28
#define CRYPTO_HASH_SHA3_256_OUTPUT_LENGTH 32
#define CRYPTO_HASH_SHA3_384_OUTPUT_LENGTH 48
#define CRYPTO_HASH_SHA3_512_OUTPUT_LENGTH 64

/*!
@brief Function to compute SHAKE128 on the input message with any output length.
*/
void FIPS202_SHAKE128(
    const unsigned char *input,
    unsigned int inputByteLen,
    unsigned char *output,
    int outputByteLen
);

/*!
@brief Function to compute SHAKE256 on the input message with any output length.
*/
void FIPS202_SHAKE256(
    const unsigned char *input,
    unsigned int inputByteLen,
    unsigned char *output,
    int outputByteLen
);


/*!
@brief Function to compute SHA3-224 on the input message. The output length is fixed to 28 bytes.
*/
void FIPS202_SHA3_224(
    const unsigned char *input,
    unsigned int inputByteLen,
    unsigned char *output
);


/*!
@brief Function to compute SHA3-256 on the input message. The output length is fixed to 32 bytes.
*/
void FIPS202_SHA3_256(
    const unsigned char *input,
    unsigned int inputByteLen,
    unsigned char *output
);


/*!
@brief Function to compute SHA3-384 on the input message. The output length is fixed
to 48 bytes.
*/
void FIPS202_SHA3_384(
    const unsigned char *input,
    unsigned int inputByteLen,
    unsigned char *output
);

/*!
@brief Function to compute SHA3-512 on the input message. The output length is
fixed to 64 bytes.
*/
void FIPS202_SHA3_512(
    const unsigned char *input,
    unsigned int inputByteLen,
    unsigned char *output
);

#endif

/*! @} */
