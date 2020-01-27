
/*!
@addtogroup crypto_block_aes_reference AES Reference
@brief Reference implementation of AES.
@ingroup crypto_block_aes
@{
*/

#include "riscvcrypto/crypto_block/aes/api_aes.h"


/*!
@brief Key expansion function for the AES 128 parameterisation
@param [out] rk - The expanded key schedule
@param [in]  ck - The cipher key to expand
*/
void    aes_128_key_schedule (
    uint8_t     rk [AES_128_RK_BYTES ],
    uint8_t     ck [AES_128_KEY_BYTES]
){

}


/*!
@brief Generic single-block AES encrypt function
@param [out] ct - Output cipher text
@param [in]  pt - Input plaintext
@param [in]  rk - The expanded key schedule
@param [in]  nr - Number of encryption rounds to perform.
*/
void    aes_ecb_encrypt (
    uint8_t     ct [AES_BLOCK_BYTES],
    uint8_t     pt [AES_BLOCK_BYTES],
    uint8_t   * rk,
    int         nr
){

}

//!@}
