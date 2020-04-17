
/*!
@addtogroup crypto_block_aes_rv64 AES RV64
@brief RV64 AES Example benchmark code
@ingroup crypto_block_aes
@{
*/

#include "riscvcrypto/share/util.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

#include "riscvcrypto/aes/api_aes.h"

//! Decrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}
void aes_ecb_decrypt (
    uint8_t    pt[AES_BLOCK_BYTES],
    uint8_t    ct[AES_BLOCK_BYTES],
    uint32_t * rk,
    int nr
) {
    uint64_t   n0, n1               ;
    int        rnd = 0              ;

    uint64_t * ptp = (uint64_t*)pt   ;
    uint64_t * ctp = (uint64_t*)ct   ;
    uint64_t * rkp = (uint64_t*)rk + (nr*2);

    uint64_t   t0  = ctp[0]         ;
    uint64_t   t1  = ctp[1]         ;

               n0  = t0 ^ rkp[0]    ;
               n1  = t1 ^ rkp[1]    ;

              rkp -= 2              ;

    for(rnd = nr-1; rnd > 0; rnd --) {

        t0  = _saes64_decsm_lo(n0, n1);
        t1  = _saes64_decsm_hi(n0, n1);
               
        n0  = t0 ^ rkp[0]    ;
        n1  = t1 ^ rkp[1]    ;

        rkp-= 2              ;

    }
    
    t0  = _saes64_decs_lo(n0, n1);
    t1  = _saes64_decs_hi(n0, n1);
    t0 ^= rkp[0];
    t1 ^= rkp[1];

    ptp[0] = t0;
    ptp[1] = t1;
}


//! Key schedule for AES-128 decryption.
void aes_128_dec_key_schedule(
    uint32_t rk[AES_128_RK_WORDS  ],
    uint8_t  key[AES_128_KEY_BYTES]
)
{
    //  create an encryption key and modify middle rounds
    aes_128_enc_key_schedule(rk, key);

    uint64_t * rkp = (uint64_t*)(rk+4);

    for(int i = 0; i < 18 ; i +=2) {
        rkp[i+0] = _saes64_imix(rkp[i+0]);
        rkp[i+1] = _saes64_imix(rkp[i+1]);
    }
}


//!@}
