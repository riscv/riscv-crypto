//  aes_dec.c
//  2020-01-22  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.


/*!
@addtogroup crypto_block_aes_reference AES Reference
@brief Reference implementation of AES.
@ingroup crypto_block_aes
@{
*/

#include "riscvcrypto/share/util.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

#include "riscvcrypto/crypto_block/aes/api_aes.h"

//  Decrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}

void aes_ecb_decrypt (
    uint8_t    pt[AES_BLOCK_BYTES],
    uint8_t    ct[AES_BLOCK_BYTES],
    uint32_t * rk,
    int nr
) {
    uint32_t t0, t1, t2, t3;                //  even round state registers
    uint32_t u0, u1, u2, u3;                //  odd round state registers
    const uint32_t *kp = &rk[4 * nr];       //  key pointer

    t0 = kp[0];                             //  fetch last subkey
    t1 = kp[1];
    t2 = kp[2];
    t3 = kp[3];
    kp -= 8;

    t0 ^= U8_TO_U32LE(ct     );               //  xor with ciphertext block
    t1 ^= U8_TO_U32LE(ct +  4);
    t2 ^= U8_TO_U32LE(ct +  8);
    t3 ^= U8_TO_U32LE(ct + 12);

    while (1) {
        u0 = kp[4];                         //  fetch odd subkey
        u1 = kp[5];
        u2 = kp[6];
        u3 = kp[7];

        u0 = _saes_v3_decsm(t0, u0, 0); //  AES decryption round, 16 instr
        u0 = _saes_v3_decsm(t3, u0, 1);
        u0 = _saes_v3_decsm(t2, u0, 2);
        u0 = _saes_v3_decsm(t1, u0, 3);

        u1 = _saes_v3_decsm(t1, u1, 0);
        u1 = _saes_v3_decsm(t0, u1, 1);
        u1 = _saes_v3_decsm(t3, u1, 2);
        u1 = _saes_v3_decsm(t2, u1, 3);

        u2 = _saes_v3_decsm(t2, u2, 0);
        u2 = _saes_v3_decsm(t1, u2, 1);
        u2 = _saes_v3_decsm(t0, u2, 2);
        u2 = _saes_v3_decsm(t3, u2, 3);

        u3 = _saes_v3_decsm(t3, u3, 0);
        u3 = _saes_v3_decsm(t2, u3, 1);
        u3 = _saes_v3_decsm(t1, u3, 2);
        u3 = _saes_v3_decsm(t0, u3, 3);

        t0 = kp[0];                         //  fetch even subkey
        t1 = kp[1];
        t2 = kp[2];
        t3 = kp[3];

        if (kp == rk)                       //  final round
            break;
        kp -= 8;

        t0 = _saes_v3_decsm(u0, t0, 0); //  AES decryption round, 16 instr
        t0 = _saes_v3_decsm(u3, t0, 1);
        t0 = _saes_v3_decsm(u2, t0, 2);
        t0 = _saes_v3_decsm(u1, t0, 3);

        t1 = _saes_v3_decsm(u1, t1, 0);
        t1 = _saes_v3_decsm(u0, t1, 1);
        t1 = _saes_v3_decsm(u3, t1, 2);
        t1 = _saes_v3_decsm(u2, t1, 3);

        t2 = _saes_v3_decsm(u2, t2, 0);
        t2 = _saes_v3_decsm(u1, t2, 1);
        t2 = _saes_v3_decsm(u0, t2, 2);
        t2 = _saes_v3_decsm(u3, t2, 3);

        t3 = _saes_v3_decsm(u3, t3, 0);
        t3 = _saes_v3_decsm(u2, t3, 1);
        t3 = _saes_v3_decsm(u1, t3, 2);
        t3 = _saes_v3_decsm(u0, t3, 3);
    }

    t0 = _saes_v3_decs(u0, t0, 0);   //  final decryption round, 16 ins.
    t0 = _saes_v3_decs(u3, t0, 1);
    t0 = _saes_v3_decs(u2, t0, 2);
    t0 = _saes_v3_decs(u1, t0, 3);

    t1 = _saes_v3_decs(u1, t1, 0);
    t1 = _saes_v3_decs(u0, t1, 1);
    t1 = _saes_v3_decs(u3, t1, 2);
    t1 = _saes_v3_decs(u2, t1, 3);

    t2 = _saes_v3_decs(u2, t2, 0);
    t2 = _saes_v3_decs(u1, t2, 1);
    t2 = _saes_v3_decs(u0, t2, 2);
    t2 = _saes_v3_decs(u3, t2, 3);

    t3 = _saes_v3_decs(u3, t3, 0);
    t3 = _saes_v3_decs(u2, t3, 1);
    t3 = _saes_v3_decs(u1, t3, 2);
    t3 = _saes_v3_decs(u0, t3, 3);

    U32_TO_U8LE(pt , t0,  0);                      //  write plaintext block
    U32_TO_U8LE(pt , t1,  4);
    U32_TO_U8LE(pt , t2,  8);
    U32_TO_U8LE(pt , t3, 12);
}


//  Helper: apply inverse mixcolumns to a vector
//  If decryption keys are computed in the fly (inverse key schedule), there's
//  no need for the encryption instruction (but you need final subkey).

static void aes_dec_invmc(
    uint32_t *v,
    size_t len
) {
    size_t i;
    uint32_t x;
    uint32_t t;

    for (i = 0; i < len; i++) {
        x = v[i];

        t = _saes_v3_encs(x,0,0);           // Sub Word
        t = _saes_v3_encs(x,t,1);
        t = _saes_v3_encs(x,t,2);
        t = _saes_v3_encs(x,t,3);

        x = _saes_v3_decsm(t, 0, 0);        // Just want inv MixCol()
        x = _saes_v3_decsm(t, x, 1);        //
        x = _saes_v3_decsm(t, x, 2);        //
        x = _saes_v3_decsm(t, x, 3);        //

        v[i] = x;
    }
}

//  Key schedule for AES-128 decryption.

void aes_128_dec_key_schedule(
    uint32_t rk[AES_128_RK_WORDS  ],
    uint8_t  key[AES_128_KEY_BYTES]
)
{
    //  create an encryption key and modify middle rounds
    aes_128_enc_key_schedule(rk, key);
    aes_dec_invmc(rk + 4, AES_128_RK_WORDS - 8);
}


//!@}
