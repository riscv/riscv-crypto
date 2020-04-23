
/*!
@defgroup crypto_hash_sha256 Crypto Hash SHA256
@{
*/

#include <stdint.h>
#include <stddef.h>

#include "riscvcrypto/share/util.h"

#ifndef __API_SHA256__
#define __API_SHA256__

//! Add a single message block to the current hash digest.
void sha256_hash (
    uint32_t    H[ 8], //!< in,out - message block hash
    uint8_t   * M    , //!< in - The message to be hashed
    size_t      len    //!< Length of the message in *bytes*.
);

/*! @} */

#endif // __API_SHA256__
