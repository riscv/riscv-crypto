
/*
Code adapted from:
- https://github.com/mjosaarinen/lwaes_isa/blob/master/aes_enc.c
*/

/*!
@addtogroup crypto_block_aes_zscrypto_v3 AES Proposal 3
@brief implementation of AES using the V3 proposals.
@details 
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

    for(int i = 0; i < AES_128_NB; i ++) {
        
        rk[i] = U8_TO_U32LE((ck +  4*i));

    }
    
    for(int i = 4; i < AES_128_NK*(AES_128_NR+1); i += 1) {

        uint32_t temp = rk[i-1];
        uint32_t acc  = 0;

        if( i % AES_128_NK == 0 ) {

            acc   = _saes_v3_ks(temp, acc,1,0);
            acc   = _saes_v3_ks(temp, acc,2,1);
            acc   = _saes_v3_ks(temp, acc,3,2);
            acc   = _saes_v3_ks(temp, acc,0,3);
            temp  = acc ^ round_const[i/AES_128_NK];

        }

        rk[i] = rk[i-AES_128_NK] ^ temp;
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
    uint32_t t0, t1, t2, t3;                //  even round state registers
    uint32_t u0, u1, u2, u3;                //  odd round state registers
    const uint32_t *kp = &rk[4 * nr];       //  key pointer as loop condition

    t0 = rk[0];                             //  fetch even subkey
    t1 = rk[1];
    t2 = rk[2];
    t3 = rk[3];

    t0 ^= U8_TO_U32LE((pt     ));             //  xor with plaintext block
    t1 ^= U8_TO_U32LE((pt + 4 ));
    t2 ^= U8_TO_U32LE((pt + 8 ));
    t3 ^= U8_TO_U32LE((pt + 12));

    while (1) {                             //  double round

        u0 = rk[4];                         //  fetch odd subkey
        u1 = rk[5];
        u2 = rk[6];
        u3 = rk[7];

        u0 = _saes_v3_enc(t0, u0, 0, 1); //  AES round, 16 instructions
        u0 = _saes_v3_enc(t1, u0, 1, 1);
        u0 = _saes_v3_enc(t2, u0, 2, 1);
        u0 = _saes_v3_enc(t3, u0, 3, 1);

        u1 = _saes_v3_enc(t1, u1, 0, 1);
        u1 = _saes_v3_enc(t2, u1, 1, 1);
        u1 = _saes_v3_enc(t3, u1, 2, 1);
        u1 = _saes_v3_enc(t0, u1, 3, 1);

        u2 = _saes_v3_enc(t2, u2, 0, 1);
        u2 = _saes_v3_enc(t3, u2, 1, 1);
        u2 = _saes_v3_enc(t0, u2, 2, 1);
        u2 = _saes_v3_enc(t1, u2, 3, 1);

        u3 = _saes_v3_enc(t3, u3, 0, 1);
        u3 = _saes_v3_enc(t0, u3, 1, 1);
        u3 = _saes_v3_enc(t1, u3, 2, 1);
        u3 = _saes_v3_enc(t2, u3, 3, 1);

        t0 = rk[8];                         //  fetch even subkey
        t1 = rk[9];
        t2 = rk[10];
        t3 = rk[11];

        rk += 8;                            //  step key pointer
        if (rk == kp)                       //  final round ?
            break;

        t0 = _saes_v3_enc(u0, t0, 0, 1); //  final encrypt round, 16 ins.
        t0 = _saes_v3_enc(u1, t0, 1, 1);
        t0 = _saes_v3_enc(u2, t0, 2, 1);
        t0 = _saes_v3_enc(u3, t0, 3, 1);

        t1 = _saes_v3_enc(u1, t1, 0, 1);
        t1 = _saes_v3_enc(u2, t1, 1, 1);
        t1 = _saes_v3_enc(u3, t1, 2, 1);
        t1 = _saes_v3_enc(u0, t1, 3, 1);

        t2 = _saes_v3_enc(u2, t2, 0, 1);
        t2 = _saes_v3_enc(u3, t2, 1, 1);
        t2 = _saes_v3_enc(u0, t2, 2, 1);
        t2 = _saes_v3_enc(u1, t2, 3, 1);

        t3 = _saes_v3_enc(u3, t3, 0, 1);
        t3 = _saes_v3_enc(u0, t3, 1, 1);
        t3 = _saes_v3_enc(u1, t3, 2, 1);
        t3 = _saes_v3_enc(u2, t3, 3, 1);
    }

    t0 = _saes_v3_enc(u0, t0, 0, 0);         //  final round is different
    t0 = _saes_v3_enc(u1, t0, 1, 0);
    t0 = _saes_v3_enc(u2, t0, 2, 0);
    t0 = _saes_v3_enc(u3, t0, 3, 0);

    t1 = _saes_v3_enc(u1, t1, 0, 0);
    t1 = _saes_v3_enc(u2, t1, 1, 0);
    t1 = _saes_v3_enc(u3, t1, 2, 0);
    t1 = _saes_v3_enc(u0, t1, 3, 0);

    t2 = _saes_v3_enc(u2, t2, 0, 0);
    t2 = _saes_v3_enc(u3, t2, 1, 0);
    t2 = _saes_v3_enc(u0, t2, 2, 0);
    t2 = _saes_v3_enc(u1, t2, 3, 0);

    t3 = _saes_v3_enc(u3, t3, 0, 0);
    t3 = _saes_v3_enc(u0, t3, 1, 0);
    t3 = _saes_v3_enc(u1, t3, 2, 0);
    t3 = _saes_v3_enc(u2, t3, 3, 0);

    U32_TO_U8LE(ct, t0,  0 );
    U32_TO_U8LE(ct, t1,  4 );
    U32_TO_U8LE(ct, t2,  8 );
    U32_TO_U8LE(ct, t3, 12 );
}

//!@}
