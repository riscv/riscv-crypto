
/*!
@addtogroup crypto_block_aes_zscrypto_v2 AES ZSCrypto C2
@ingroup crypto_block_aes
@{
*/

#include "riscvcrypto/crypto_block/aes/api_aes.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

/*!
*/
void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS ],
    uint8_t     ck [AES_128_KEY_BYTES]
){
    aes_128_enc_key_schedule(rk, ck);

    for(int i = 1; i < AES_128_NR; i ++) {
        
        uint32_t* t = rk  +  (4*i);

        t[0] = _saes_v2_mix_dec(t[0],t[0]);
        t[1] = _saes_v2_mix_dec(t[1],t[1]);
        t[2] = _saes_v2_mix_dec(t[2],t[2]);
        t[3] = _saes_v2_mix_dec(t[3],t[3]);

    }
}


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
    uint32_t  * rk,
    int         nr
){
    int round = 0;

    uint32_t *kp = &rk[4*nr];

    uint32_t t4, t5, t6, t7;

    uint32_t t0 = U8_TO_U32LE(ct     ) ^ kp[0]; // First AddRoundKey
    uint32_t t1 = U8_TO_U32LE(ct +  4) ^ kp[1];
    uint32_t t2 = U8_TO_U32LE(ct +  8) ^ kp[2];
    uint32_t t3 = U8_TO_U32LE(ct + 12) ^ kp[3];

    kp -= 4;
    
    for(round = nr - 1; round >= 1; round --) {
        
        t4 = _saes_v2_sub_dec(t0, t3);      // SubBytes & Partial ShiftRows
        t5 = _saes_v2_sub_dec(t1, t0);
        t6 = _saes_v2_sub_dec(t2, t1);
        t7 = _saes_v2_sub_dec(t3, t2);

        t0 = _saes_v2_mix_dec(t4, t6);      // Partial ShiftRows & MixColumns
        t1 = _saes_v2_mix_dec(t5, t7);
        t2 = _saes_v2_mix_dec(t6, t4);
        t3 = _saes_v2_mix_dec(t7, t5);
    
        t0 ^= kp[0];                        // AddRoundKey
        t1 ^= kp[1];
        t2 ^= kp[2];
        t3 ^= kp[3];
    
        kp -= 4;

    }
    

    t4 = _saes_v2_sub_dec(t2, t1);          // SubBytes & Partial ShiftRows
    t5 = _saes_v2_sub_dec(t3, t2);
    t6 = _saes_v2_sub_dec(t0, t3);
    t7 = _saes_v2_sub_dec(t1, t0);
    
    uint32_t t4h = t4 >> 16;
    uint32_t t5h = t5 >> 16;
    uint32_t t6h = t6 >> 16;
    uint32_t t7h = t7 >> 16;

    t0 = _pack(t6, t4h);                    // Finish shift rows
    t1 = _pack(t7, t5h);
    t2 = _pack(t4, t6h);
    t3 = _pack(t5, t7h);

    t0 ^= kp[0];                            // AddRoundKey
    t1 ^= kp[1];
    t2 ^= kp[2];
    t3 ^= kp[3];

    
    U32_TO_U8LE(pt , t0,  0);               // Write ciphertext block
    U32_TO_U8LE(pt , t1,  4);
    U32_TO_U8LE(pt , t2,  8);
    U32_TO_U8LE(pt , t3, 12);
}

//!@}
