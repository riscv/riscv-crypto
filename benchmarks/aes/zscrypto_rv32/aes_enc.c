//  aes_enc.c
//  2020-01-22  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.


/*!
@addtogroup crypto_block_aes_rv32 AES RV32
@brief RV32 AES Example benchmark code
@ingroup crypto_block_aes
@{
*/

#include "riscvcrypto/share/util.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

#include "riscvcrypto/aes/api_aes.h"

//! round constants -- just iterations of the xtime() LFSR
static const uint8_t aes_rcon[] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

//! Encrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}
void aes_ecb_encrypt (
    uint8_t   ct[AES_BLOCK_BYTES],
    uint8_t   pt[AES_BLOCK_BYTES],
    uint32_t *rk,
    int nr
) {
    uint32_t t0, t1, t2, t3;                //  even round state registers
    uint32_t u0, u1, u2, u3;                //  odd round state registers
    const uint32_t *kp = &rk[4 * nr];       //  key pointer as loop condition

    t0 = rk[0];                             //  fetch even subkey
    t1 = rk[1];
    t2 = rk[2];
    t3 = rk[3];

    t0 ^= U8_TO_U32LE(pt     );               //  xor with plaintext block
    t1 ^= U8_TO_U32LE(pt +  4);
    t2 ^= U8_TO_U32LE(pt +  8);
    t3 ^= U8_TO_U32LE(pt + 12);

    while (1) {                             //  double round

        u0 = rk[4];                         //  fetch odd subkey
        u1 = rk[5];
        u2 = rk[6];
        u3 = rk[7];
        
        uint32_t tx;

        u0 = _saes32_encsm(u0, t0, 0); //  AES round, 16 instructions
        u0 = _saes32_encsm(u0, t1, 1);
        u0 = _saes32_encsm(u0, t2, 2);
        u0 = _saes32_encsm(u0, t3, 3);

        u1 = _saes32_encsm(u1, t1, 0);
        u1 = _saes32_encsm(u1, t2, 1);
        u1 = _saes32_encsm(u1, t3, 2);
        u1 = _saes32_encsm(u1, t0, 3);

        u2 = _saes32_encsm(u2, t2, 0);
        u2 = _saes32_encsm(u2, t3, 1);
        u2 = _saes32_encsm(u2, t0, 2);
        u2 = _saes32_encsm(u2, t1, 3);

        u3 = _saes32_encsm(u3, t3, 0);
        u3 = _saes32_encsm(u3, t0, 1);
        u3 = _saes32_encsm(u3, t1, 2);
        u3 = _saes32_encsm(u3, t2, 3);

        t0 = rk[8];                         //  fetch even subkey
        t1 = rk[9];
        t2 = rk[10];
        t3 = rk[11];

        rk += 8;                            //  step key pointer
        if (rk == kp)                       //  final round ?
            break;

        t0 = _saes32_encsm(t0, u0, 0); //  final encrypt round, 16 ins.
        t0 = _saes32_encsm(t0, u1, 1);
        t0 = _saes32_encsm(t0, u2, 2);
        t0 = _saes32_encsm(t0, u3, 3);

        t1 = _saes32_encsm(t1, u1, 0);
        t1 = _saes32_encsm(t1, u2, 1);
        t1 = _saes32_encsm(t1, u3, 2);
        t1 = _saes32_encsm(t1, u0, 3);

        t2 = _saes32_encsm(t2, u2, 0);
        t2 = _saes32_encsm(t2, u3, 1);
        t2 = _saes32_encsm(t2, u0, 2);
        t2 = _saes32_encsm(t2, u1, 3);

        t3 = _saes32_encsm(t3, u3, 0);
        t3 = _saes32_encsm(t3, u0, 1);
        t3 = _saes32_encsm(t3, u1, 2);
        t3 = _saes32_encsm(t3, u2, 3);
    }

    t0 = _saes32_encs(t0, u0, 0);     //  final round is different
    t0 = _saes32_encs(t0, u1, 1);
    t0 = _saes32_encs(t0, u2, 2);
    t0 = _saes32_encs(t0, u3, 3);

    t1 = _saes32_encs(t1, u1, 0);
    t1 = _saes32_encs(t1, u2, 1);
    t1 = _saes32_encs(t1, u3, 2);
    t1 = _saes32_encs(t1, u0, 3);

    t2 = _saes32_encs(t2, u2, 0);
    t2 = _saes32_encs(t2, u3, 1);
    t2 = _saes32_encs(t2, u0, 2);
    t2 = _saes32_encs(t2, u1, 3);

    t3 = _saes32_encs(t3, u3, 0);
    t3 = _saes32_encs(t3, u0, 1);
    t3 = _saes32_encs(t3, u1, 2);
    t3 = _saes32_encs(t3, u2, 3);

    U32_TO_U8LE(ct , t0,  0);                 //  write ciphertext block
    U32_TO_U8LE(ct , t1,  4);
    U32_TO_U8LE(ct , t2,  8);
    U32_TO_U8LE(ct , t3, 12);
}


//!  Key schedule for AES-128 Encryption.
void aes_128_enc_key_schedule(
    uint32_t  rk [AES_128_RK_WORDS    ],
    uint8_t   key[AES_128_KEY_BYTES   ]
) {
    uint32_t t0, t1, t2, t3, tr;            //  subkey registers
    const uint32_t *rke = &rk[44 - 4];      //  end pointer
    const uint8_t *rc = aes_rcon;           //  round constants

    t0 = U8_TO_U32LE(key +  0);               //  load secret key
    t1 = U8_TO_U32LE(key +  4);
    t2 = U8_TO_U32LE(key +  8);
    t3 = U8_TO_U32LE(key + 12);

    while (1) {

        rk[0] = t0;                         //  store subkey
        rk[1] = t1;
        rk[2] = t2;
        rk[3] = t3;

        if (rk == rke)                      //  end condition
            return;
        rk += 4;                            //  step pointer by one subkey

        t0 ^= (uint32_t) *rc++;             //  round constant
        tr = ROTL32(t3, 24);                //  rotate 8 bits (little endian!)

        t0 = _saes32_encs(t0, tr, 0);   //  SubWord()
        t0 = _saes32_encs(t0, tr, 1);   //
        t0 = _saes32_encs(t0, tr, 2);   //
        t0 = _saes32_encs(t0, tr, 3);   //

        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;
    }
}


//!@}
