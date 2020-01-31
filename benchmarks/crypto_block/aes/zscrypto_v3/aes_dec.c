
/*!
@addtogroup crypto_block_aes_reference AES Reference
@brief Reference implementation of AES.
@ingroup crypto_block_aes
@{
*/

#include "riscvcrypto/share/util.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

#include "riscvcrypto/crypto_block/aes/api_aes.h"

//! AES Inverse SBox
static const uint8_t d_sbox[256] = { 
0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81,
0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e,
0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23,
0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66,
0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72,
0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65,
0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46,
0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca,
0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91,
0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f,
0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93,
0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6,
0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


//  Multiply by 0x02 in AES's GF(256) - LFSR style

static inline uint8_t aes_xtime(uint8_t x)
{
    return (x << 1) ^ ((x & 0x80) ? 0x11B : 0x00 );
}

//  === THIS IS THE SINGLE LIGHTWEIGHT INSTRUCTION FOR AES AND SM4  ===

//  ENC1S: Instruction for a byte select, single S-box, and linear operation.

#define AES_FN_FWD  (1 << 2)
#define AES_FN_DEC  (2 << 2)
#define AES_FN_REV  (3 << 2)

uint32_t enc1s(uint32_t rs1, uint32_t rs2, int fn)
{
    uint32_t fa, fb, x, x2, x4, x8;

    fa  = 8 * (fn & 3);                     //  [1:0]   byte select / rotate
    fb  = (fn >> 2) & 7;                    //  [4:2]   cipher select

    //  select input byte

    x   = (rs1 >> fa) & 0xFF;               //  select byte

    //  8->8 bit s-box

    switch (fb) {

        case 2:                             //  1 : AES Inverse + MC
        case 3:                             //  2 : AES Inverse "key"
            x = d_sbox[x];
            break;

        default:                            //  none
            break;
    }

    //  8->32 bit linear transforms expressed as little-endian

    switch (fb) {

        case 0:     //  0 : AES Forward MixCol
            x2 = aes_xtime(x);              //  double x
            x = ((x ^ x2)   << 24) |        //  0x03    MixCol MDS Matrix
                (x          << 16) |        //  0x01
                (x          <<  8) |        //  0x01
                x2;                         //  0x02
            break;

        case 2:     //  2 : AES Inverse MixCol
//    ( case 6:     //  6 : AES Inverse MixCol *only* )
            x2 = aes_xtime(x);              //  double x
            x4 = aes_xtime(x2);             //  double to 4*x
            x8 = aes_xtime(x4);             //  double to 8*x
            x = ((x ^ x2 ^ x8)  << 24) |    //  0x0B    Inv MixCol MDS Matrix
                ((x ^ x4 ^ x8)  << 16) |    //  0x0D
                ((x ^ x8)       <<  8) |    //  0x09
                (x2 ^ x4 ^ x8);             //  0x0E
            break;

        default:                            //  none
            break;

    }

    //  rotate output left by fa bits

    if (fa != 0) {
        x = (x << fa) | (x >> (32 - fa));
    }

    return  x ^ rs2;                        //  XOR with rs2
}

//  ENC4S: Instruction or pseudoinstruction for four ENC1S's.
//  We may assume that rd == rs2 and fn[1:0] == 2'b00.

uint32_t enc4s(uint32_t rs1, uint32_t rs2, int fn)
{
    rs2 = enc1s(rs1, rs2, fn);
    rs2 = enc1s(rs1, rs2, fn | 1);
    rs2 = enc1s(rs1, rs2, fn | 2);
    rs2 = enc1s(rs1, rs2, fn | 3);

    return rs2;
}

//  Helper: apply inverse mixcolumns to a vector
//  If decryption keys are computed in the fly (inverse key schedule), there's
//  no need for the encryption instruction (but you need final subkey).

static void aes_dec_invmc(uint32_t *v, size_t len)
{
    size_t i;
    uint32_t x;

    for (i = 0; i < len; i++) {
        x = v[i];
        
        x = enc4s(x,0,AES_FN_FWD);
        x = enc4s(x,0,AES_FN_DEC);

        v[i] = x;
    }
}

/*!
*/
void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS ],
    uint8_t     ck [AES_128_KEY_BYTES]
){
    aes_128_enc_key_schedule(rk,ck);
    aes_dec_invmc(rk+4,AES_128_RK_BYTES / 8 - 8);
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
}

//!@}
