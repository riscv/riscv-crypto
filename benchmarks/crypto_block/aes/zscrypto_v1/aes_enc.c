
/*!
@addtogroup crypto_block_aes_reference AES Reference
@brief Reference implementation of AES.
@details Byte-orientated, un-optimised. Un-necessesarily spills to memory.
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
@brief A generic AES key schedule
*/
void    aes_key_schedule (
    uint32_t * rk , //!< Output Nk*(Nr+1) word cipher key.
    uint8_t  * ck , //!< Input Nk byte cipher key
    const int  Nk , //!< Number of words in the key.
    const int  Nr   //!< Number of rounds.
){
    const int        Nb = 4;

    for(int i = 0; i < Nb; i ++) {
        
        rk[i] = U8_TO_U32LE((ck +  4*i));

    }
    
    for(int i = 4; i < Nk*(Nr+1); i += 1) {

        uint32_t temp = rk[i-1];

        if( i % Nk == 0 ) {

            temp  = ROTR32(temp, 8);
            temp  = _saes_v1_enc(temp);
            temp ^= round_const[i/Nk];

        } else if ( (Nk > 6) && (i % Nk == 4)) {
            
            temp  = _saes_v1_enc(temp);

        }

        rk[i] = rk[i-Nk] ^ temp;
    }
}


/*!
*/
void    aes_128_enc_key_schedule (
    uint32_t    rk [AES_128_RK_BYTES ],
    uint8_t     ck [AES_128_KEY_BYTES]
){
    aes_key_schedule(rk, ck, 4, 10);
}

/*!
*/
void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_BYTES ],
    uint8_t     ck [AES_128_KEY_BYTES]
){
    aes_key_schedule(rk, ck, 4, 10);
}


//! Forward mix columns transformation.
static uint32_t aes_mix_column_enc(
    uint32_t col
){
    uint8_t b0,b1,b2,b3;
    uint8_t s0,s1,s2,s3;
    
    s0 = (col >>  0) & 0xFF;
    s1 = (col >>  8) & 0xFF;
    s2 = (col >> 16) & 0xFF;
    s3 = (col >> 24) & 0xFF;

    b0 = XT2(s0) ^ XT3(s1) ^    (s2) ^    (s3);
    b1 =    (s0) ^ XT2(s1) ^ XT3(s2) ^    (s3);
    b2 =    (s0) ^    (s1) ^ XT2(s2) ^ XT3(s3);
    b3 = XT3(s0) ^    (s1) ^    (s2) ^ XT2(s3);

    uint32_t tr = 
        (((uint32_t)b3) << 24) |
        (((uint32_t)b2) << 16) |
        (((uint32_t)b1) <<  8) |
        (((uint32_t)b0) <<  0) ;

    return tr;
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

    uint32_t n0, n1, n2, n3;

    uint32_t t0 = U8_TO_U32LE((pt+ 0)) ^ rk[0];
    uint32_t t1 = U8_TO_U32LE((pt+ 4)) ^ rk[1];
    uint32_t t2 = U8_TO_U32LE((pt+ 8)) ^ rk[2];
    uint32_t t3 = U8_TO_U32LE((pt+12)) ^ rk[3];

    
    for(round = 1; round < nr; round ++) {
        
        //
        // Sub Bytes
        t0 = _saes_v1_enc(t0);
        t1 = _saes_v1_enc(t1);
        t2 = _saes_v1_enc(t2);
        t3 = _saes_v1_enc(t3);

        //
        // Shift Rows
        n0 = (t0 & 0x000000FF) | (t1 & 0x0000FF00) |
             (t2 & 0x00FF0000) | (t3 & 0xFF000000) ;
        
        n1 = (t1 & 0x000000FF) | (t2 & 0x0000FF00) | 
             (t3 & 0x00FF0000) | (t0 & 0xFF000000) ;
        
        n2 = (t2 & 0x000000FF) | (t3 & 0x0000FF00) |
             (t0 & 0x00FF0000) | (t1 & 0xFF000000) ;

        n3 = (t3 & 0x000000FF) | (t0 & 0x0000FF00) |
             (t1 & 0x00FF0000) | (t2 & 0xFF000000) ;

        //
        // Mix Columns

        t0 = aes_mix_column_enc(n0);
        t1 = aes_mix_column_enc(n1);
        t2 = aes_mix_column_enc(n2);
        t3 = aes_mix_column_enc(n3);
        
        //
        // Add Round Key

        t0 ^= rk[4*round + 0];
        t1 ^= rk[4*round + 1];
        t2 ^= rk[4*round + 2];
        t3 ^= rk[4*round + 3];
    }
    //
    // Sub Bytes
    t0 = _saes_v1_enc(t0);
    t1 = _saes_v1_enc(t1);
    t2 = _saes_v1_enc(t2);
    t3 = _saes_v1_enc(t3);

    //
    // Shift Rows
    n0 = (t0 & 0x000000FF) | (t1 & 0x0000FF00) |
         (t2 & 0x00FF0000) | (t3 & 0xFF000000) ;
    
    n1 = (t1 & 0x000000FF) | (t2 & 0x0000FF00) | 
         (t3 & 0x00FF0000) | (t0 & 0xFF000000) ;
    
    n2 = (t2 & 0x000000FF) | (t3 & 0x0000FF00) |
         (t0 & 0x00FF0000) | (t1 & 0xFF000000) ;

    n3 = (t3 & 0x000000FF) | (t0 & 0x0000FF00) |
         (t1 & 0x00FF0000) | (t2 & 0xFF000000) ;

    
    //
    // Add Round Key

    t0 = n0 ^ rk[4*round + 0];
    t1 = n1 ^ rk[4*round + 1];
    t2 = n2 ^ rk[4*round + 2];
    t3 = n3 ^ rk[4*round + 3];
        
    U32_TO_U8LE(ct, t0, 0);
    U32_TO_U8LE(ct, t1, 4);
    U32_TO_U8LE(ct, t2, 8);
    U32_TO_U8LE(ct, t3,12);
}

//!@}
