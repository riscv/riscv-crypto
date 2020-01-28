
#include <stdint.h>

/*!
@defgroup crypto_block_aes Crypto Block AES
@{

AES  |   Nk  | Nb   | Nr
-----|-------|------|---------------
128  |  4    | 4    | 10
192  |  6    | 4    | 12
256  |  8    | 4    | 14

*/

#ifndef __API_AES_H__
#define __API_AES_H__

//! Number of bytes in a single AES block
#define AES_BLOCK_BYTES     16

//! Bytes in an AES 128 Cipher key
#define AES_128_KEY_BYTES   16

//! Number of bytes in the expanded AES 128 key
#define AES_128_RK_BYTES    176

//! Number of rounds for AES 128
#define AES_128_NR          10

/*!
@brief Key expansion function for the AES 128 parameterisation
@param [out] rk - The expanded key schedule
@param [in]  ck - The cipher key to expand
*/
void    aes_128_key_schedule (
    uint8_t     rk [AES_128_RK_BYTES ],
    uint8_t     ck [AES_128_KEY_BYTES]
);


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
);

/*!
@brief Generic single-block AES encrypt function
@param [out] pt - Output plaintext
@param [in]  ct - Input cipher text
@param [in]  rk - The expanded key schedule
@param [in]  nr - Number of decryption rounds to perform.
*/
void    aes_ecb_decrypt (
    uint8_t     pt [AES_BLOCK_BYTES],
    uint8_t     ct [AES_BLOCK_BYTES],
    uint8_t   * rk,
    int         nr
);


//! Macro for AES 128 encrypt
#define aes_128_ecb_encrypt(ct,pt,rk) aes_ecb_encrypt(ct,pt,rk,AES_128_NR)

//! Macro for AES 128 decrypt
#define aes_128_ecb_decrypt(ct,pt,rk) aes_ecb_decrypt(ct,pt,rk,AES_128_NR)

#endif

//! @}
