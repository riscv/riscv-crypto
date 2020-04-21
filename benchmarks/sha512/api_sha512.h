
/*!
@defgroup crypto_hash_sha512 Crypto Hash SHA512
@{
*/

#include <stdint.h>

#include "riscvcrypto/share/util.h"

#ifndef __API_SHA512__
#define __API_SHA512__

//! Hash a message using SHA512
void sha512_hash (
    uint64_t    H[ 8], //!< in,out - message block hash
    uint8_t   * M    , //!< in - The message to be hashed
    size_t      len    //!< Length of the message in *bytes*.
);

//! @}

#endif // __API_SHA512__
