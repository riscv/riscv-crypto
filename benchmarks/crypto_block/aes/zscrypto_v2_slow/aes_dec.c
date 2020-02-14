
/*!
@addtogroup crypto_block_aes_zscrypto_v2 AES ZSCrypto C2
@ingroup crypto_block_aes
@{
*/

#include "riscvcrypto/crypto_block/aes/api_aes.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

#define NOP_CYCLE_PAD {__asm__("nop;nop;nop;");}

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
        NOP_CYCLE_PAD
        t[1] = _saes_v2_mix_dec(t[1],t[1]);
        NOP_CYCLE_PAD
        t[2] = _saes_v2_mix_dec(t[2],t[2]);
        NOP_CYCLE_PAD
        t[3] = _saes_v2_mix_dec(t[3],t[3]);
        NOP_CYCLE_PAD

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
        NOP_CYCLE_PAD
        t5 = _saes_v2_sub_dec(t1, t0);
        NOP_CYCLE_PAD
        t6 = _saes_v2_sub_dec(t2, t1);
        NOP_CYCLE_PAD
        t7 = _saes_v2_sub_dec(t3, t2);
        NOP_CYCLE_PAD

        t0 = _saes_v2_mix_dec(t4, t6);      // Partial ShiftRows & MixColumns
        NOP_CYCLE_PAD
        t1 = _saes_v2_mix_dec(t5, t7);
        NOP_CYCLE_PAD
        t2 = _saes_v2_mix_dec(t6, t4);
        NOP_CYCLE_PAD
        t3 = _saes_v2_mix_dec(t7, t5);
        NOP_CYCLE_PAD
    
        t0 ^= kp[0];                        // AddRoundKey
        t1 ^= kp[1];
        t2 ^= kp[2];
        t3 ^= kp[3];
    
        kp -= 4;

    }
    

    t4 = _saes_v2_sub_dec(t2, t1);          // SubBytes & Partial ShiftRows
    NOP_CYCLE_PAD
    t5 = _saes_v2_sub_dec(t3, t2);
    NOP_CYCLE_PAD
    t6 = _saes_v2_sub_dec(t0, t3);
    NOP_CYCLE_PAD
    t7 = _saes_v2_sub_dec(t1, t0);
    NOP_CYCLE_PAD

    t0 = (t6 & 0x0000FFFF) | (t4 & 0xFFFF0000); // Finish shift rows
    t1 = (t7 & 0x0000FFFF) | (t5 & 0xFFFF0000);
    t2 = (t4 & 0x0000FFFF) | (t6 & 0xFFFF0000);
    t3 = (t5 & 0x0000FFFF) | (t7 & 0xFFFF0000);

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
