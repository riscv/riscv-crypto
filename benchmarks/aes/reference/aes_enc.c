
/*!
@addtogroup crypto_block_aes_reference AES Reference
@brief Byte-wise Reference implementation of AES.
@details Byte-orientated, un-optimised. Un-necessesarily spills to memory.
@ingroup crypto_block_aes
@{
*/

#include "riscvcrypto/share/util.h"

#include "riscvcrypto/aes/api_aes.h"

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
@brief A generic AES key schedule
*/
void    aes_key_schedule (
    uint32_t * const rk , //!< Output Nk*(Nr+1) word cipher key.
    uint8_t  * const ck , //!< Input Nk byte cipher key
    const int  Nk , //!< Number of words in the key.
    const int  Nr   //!< Number of rounds.
){
    for(int i = 0; i < Nk; i ++) {
        
        rk[i] = U8_TO_U32LE((ck +  4*i));

    }
    
    for(int i = Nk; i < 4*(Nr+1); i += 1) {

        uint32_t temp = rk[i-1];

        if( i % Nk == 0 ) {

            temp  = ROTR32(temp, 8);
            temp  = aes_sub_word(temp);
            temp ^= round_const[i/Nk];

        } else if ( (Nk > 6) && (i % Nk == 4)) {
            
            temp  = aes_sub_word(temp);

        }

        rk[i] = rk[i-Nk] ^ temp;
    }
}


/*!
*/
void    aes_128_enc_key_schedule (
    uint32_t * const rk,
    uint8_t  * const ck
){
    aes_key_schedule(rk, ck, AES_128_NK, AES_128_NR);
}

void    aes_192_enc_key_schedule (
    uint32_t * const rk,
    uint8_t  * const ck
){
    aes_key_schedule(rk, ck, AES_192_NK, AES_192_NR);
}


void    aes_256_enc_key_schedule (
    uint32_t * const rk,
    uint8_t  * const ck
){
    aes_key_schedule(rk, ck, AES_256_NK, AES_256_NR);
}


//! Combined sub-bytes and shift rows transformation.
static void aes_subbytes_shiftrows(
    uint8_t     ct [16]       //!< Current block state
){
    uint8_t tmp;

    // row 0
    ct[ 0] = e_sbox[ct[ 0]];
    ct[ 4] = e_sbox[ct[ 4]];
    ct[ 8] = e_sbox[ct[ 8]];
    ct[12] = e_sbox[ct[12]];

    // row 1
    tmp    = e_sbox[ct[ 1]];
    ct[ 1] = e_sbox[ct[ 5]];
    ct[ 5] = e_sbox[ct[ 9]];
    ct[ 9] = e_sbox[ct[13]];
    ct[13] = tmp;
    
    // row 2
    tmp    = e_sbox[ct[ 2]];
    ct[ 2] = e_sbox[ct[10]];
    ct[10] = tmp;

    tmp    = e_sbox[ct[ 6]];
    ct[ 6] = e_sbox[ct[14]];
    ct[14] = tmp;

    // row 3
    tmp    = e_sbox[ct[ 3]];
    ct[ 3] = e_sbox[ct[15]];
    ct[15] = e_sbox[ct[11]];
    ct[11] = e_sbox[ct[ 7]];
    ct[ 7] = tmp;
}

#define XT2(x) ((x << 1) ^ (x & 0x80 ? 0x1b : 0x00))
#define XT3(x) (XT2(x) ^ x)

//! Forward mix columns transformation.
static void aes_mix_columns_enc(
    uint8_t     ct [16]       //!< Current block state
){
    for(int i = 0; i < 4; i ++) {
        uint8_t b0,b1,b2,b3;
        uint8_t s0,s1,s2,s3;
        
        s0 = ct[4*i+0];
        s1 = ct[4*i+1];
        s2 = ct[4*i+2];
        s3 = ct[4*i+3];

        b0 = XT2(s0) ^ XT3(s1) ^    (s2) ^    (s3);
        b1 =    (s0) ^ XT2(s1) ^ XT3(s2) ^    (s3);
        b2 =    (s0) ^    (s1) ^ XT2(s2) ^ XT3(s3);
        b3 = XT3(s0) ^    (s1) ^    (s2) ^ XT2(s3);

        ct[4*i+0] = b0;
        ct[4*i+1] = b1;
        ct[4*i+2] = b2;
        ct[4*i+3] = b3;
    }
}


/*!
*/
void    aes_ecb_encrypt (
    uint8_t     ct [AES_BLOCK_BYTES],
    uint8_t     pt [AES_BLOCK_BYTES],
    uint32_t  * rk                  ,
    int         nr
){
    int round = 0;

    // AddRoundKey
    for(int i = 0; i < AES_BLOCK_BYTES; i ++) {
        ct[i] = pt[i] ^ ((uint8_t*)rk)[i];
    }
    
    for(round = 1; round < nr; round ++) {
        
        aes_subbytes_shiftrows(ct);
        aes_mix_columns_enc(ct);
    
        for(int i = 0; i < AES_BLOCK_BYTES; i ++) {
            ct[i] ^= ((uint8_t*)rk)[(16*round)+i];
        }

    }
        
    aes_subbytes_shiftrows(ct);
    
    for(int i = 0; i < AES_BLOCK_BYTES; i ++) {
        ct[i] ^= ((uint8_t*)rk)[(16*round)+i];
    }
}

void    aes_128_ecb_encrypt (
    uint8_t     ct [AES_BLOCK_BYTES],
    uint8_t     pt [AES_BLOCK_BYTES],
    uint32_t  * rk
){
    aes_ecb_encrypt(ct,pt,rk,AES_128_NR);
}


void    aes_192_ecb_encrypt (
    uint8_t     ct [AES_BLOCK_BYTES],
    uint8_t     pt [AES_BLOCK_BYTES],
    uint32_t  * rk
){
    aes_ecb_encrypt(ct,pt,rk,AES_192_NR);
}

void    aes_256_ecb_encrypt (
    uint8_t     ct [AES_BLOCK_BYTES],
    uint8_t     pt [AES_BLOCK_BYTES],
    uint32_t  * rk
){
    aes_ecb_encrypt(ct,pt,rk,AES_256_NR);
}

//!@}
