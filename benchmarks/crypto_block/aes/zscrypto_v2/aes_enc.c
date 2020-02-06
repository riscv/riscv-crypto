
/*!
@addtogroup crypto_block_aes_zscrypto_v2 AES ZSCrypto C2
@ingroup crypto_block_aes
@{
*/

#include "riscvcrypto/share/util.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

#include "riscvcrypto/crypto_block/aes/api_aes.h"

//! AES Round constants
static const uint8_t round_const[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

/*!
*/
void    aes_128_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS ],
    uint8_t     ck [AES_128_KEY_BYTES]
){
    const int        Nb =  4;
    const int        Nk =  4;
    const int        Nr = 10;

    for(int i = 0; i < Nb; i ++) {
        
        rk[i] = U8_TO_U32LE((ck +  4*i));

    }
    
    for(int i = 4; i < Nk*(Nr+1); i += 1) {

        uint32_t temp = rk[i-1];

        if( i % Nk == 0 ) {

            temp  = ROTR32(temp, 8);
            temp  = _saes_v2_sub_enc(temp,temp);
            temp ^= round_const[i/Nk];

        }

        rk[i] = rk[i-Nk] ^ temp;
    }
}


/*!
*/
void    aes_ecb_encrypt (
    uint8_t     ct [AES_BLOCK_BYTES],
    uint8_t     pt [AES_BLOCK_BYTES],
    uint32_t  * rk,
    int         nr
){
    int round = 0;

    uint32_t *kp = rk;

    uint32_t u0, u1, u2, u3;

    uint32_t t0 = U8_TO_U32LE(pt     ) ^ kp[0]; // First AddRoundKey
    uint32_t t1 = U8_TO_U32LE(pt +  4) ^ kp[1];
    uint32_t t2 = U8_TO_U32LE(pt +  8) ^ kp[2];
    uint32_t t3 = U8_TO_U32LE(pt + 12) ^ kp[3];

    kp += 4;

    for(round = 1; round < nr; round ++) {
        
        u0 = _saes_v2_sub_enc(t0, t1);      // SubBytes & Partial ShiftRows
        u1 = _saes_v2_sub_enc(t2, t3);
        u2 = _saes_v2_sub_enc(t1, t2);
        u3 = _saes_v2_sub_enc(t3, t0);

        t0 = _saes_v2_mix_enc(u0, u1);      // Partial ShiftRows & MixColumns
        t1 = _saes_v2_mix_enc(u2, u3);
        t2 = _saes_v2_mix_enc(u1, u0);
        t3 = _saes_v2_mix_enc(u3, u2);
    
        t0 ^= kp[0];                        // AddRoundKey
        t1 ^= kp[1];
        t2 ^= kp[2];
        t3 ^= kp[3];
    
        kp += 4;

    }

    u0 = _saes_v2_sub_enc(t0, t1);          // SubBytes & Partial ShiftRows
    u1 = _saes_v2_sub_enc(t2, t3);
    u2 = _saes_v2_sub_enc(t1, t2);
    u3 = _saes_v2_sub_enc(t3, t0);


    t0 = (u0 & 0x0000FFFF) | (u1 & 0xFFFF0000); // Finish shift rows
    t1 = (u2 & 0x0000FFFF) | (u3 & 0xFFFF0000);
    t2 = (u1 & 0x0000FFFF) | (u0 & 0xFFFF0000);
    t3 = (u3 & 0x0000FFFF) | (u2 & 0xFFFF0000);

    t0 ^= kp[0];                            // AddRoundKey
    t1 ^= kp[1];
    t2 ^= kp[2];
    t3 ^= kp[3];
    
    U32_TO_U8LE(ct , t0,  0);               // Write ciphertext block
    U32_TO_U8LE(ct , t1,  4);
    U32_TO_U8LE(ct , t2,  8);
    U32_TO_U8LE(ct , t3, 12);
}

//!@}
