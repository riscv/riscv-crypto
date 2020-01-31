
/*!
@addtogroup crypto_block_aes_zscrypto_v3 AES Proposal 3
@brief implementation of AES using the V3 proposals.
@details Code adapted from https://github.com/mjosaarinen/lwaes_isa/blob/master/aes_enc.c
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

//! AES Forward SBox
static const uint8_t e_sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
  0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
  0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
  0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
  0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
  0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
  0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
  0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
  0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  0xb0, 0x54, 0xbb, 0x16
};


static inline uint8_t aes_xtime(uint8_t x)
{
    return (x << 1) ^ ((x & 0x80) ? 0x11B : 0x00 );
}

uint32_t enc1s(uint32_t rs1, uint32_t rs2, int fa, int fc)
{
    uint32_t x, x2;

    //  select input byte

    x   = (rs1 >> (8*fa)) & 0xFF;               //  select byte

    //  8->8 bit s-box

    x = e_sbox[x];

    if(fc) {
        x2 = aes_xtime(x);              //  double x
        x = ((x ^ x2)   << 24) |        //  0x03    MixCol MDS Matrix
            (x          << 16) |        //  0x01
            (x          <<  8) |        //  0x01
            x2;                         //  0x02
    }

    //  rotate output left by fa bits

    if (fa != 0) {
        x = (x << (8*fa)) | (x >> (32 - (8*fa)));
    }

    return  x ^ rs2;                        //  XOR with rs2
}

/*!
@brief Apply the AES forward SBox to each byte in a 32-bit word.
*/
static uint32_t aes_sub_word(uint32_t in) {

    uint32_t t0 = e_sbox[(in >>  0) & 0xFF] <<  0;
    uint32_t t1 = e_sbox[(in >>  8) & 0xFF] <<  8;
    uint32_t t2 = e_sbox[(in >> 16) & 0xFF] << 16;
    uint32_t t3 = e_sbox[(in >> 24) & 0xFF] << 24;
    
    return t3 | t2 | t1 | t0;
}

/*!
*/
void    aes_128_enc_key_schedule (
    uint32_t    rk [AES_128_RK_BYTES ],
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
void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_BYTES ],
    uint8_t     ck [AES_128_KEY_BYTES]
){
    aes_128_enc_key_schedule(rk, ck);
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
