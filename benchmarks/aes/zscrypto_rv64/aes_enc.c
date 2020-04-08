

#include "riscvcrypto/share/util.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

#include "riscvcrypto/crypto_block/aes/api_aes.h"

/*!
@addtogroup crypto_block_aes_rv64 AES RV64
@brief RV64 AES Example benchmark code
@ingroup crypto_block_aes
@{
*/

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
    uint64_t   n0, n1               ;
    int        rnd = 0              ;

    uint64_t * ptp = (uint64_t*)pt   ;
    uint64_t * ctp = (uint64_t*)ct   ;
    uint64_t * rkp = (uint64_t*)rk   ;

    uint64_t   t0  = ptp[0]         ;
    uint64_t   t1  = ptp[1]         ;

               n0  = t0 ^ rkp[0]    ;
               n1  = t1 ^ rkp[1]    ;

              rkp += 2              ;

    for(rnd = 1; rnd < nr; rnd ++) {
        
        t0  = _saes64_encsm_lo(n0, n1);
        t1  = _saes64_encsm_hi(n0, n1);
        n0  = t0 ^ rkp[0];
        n1  = t1 ^ rkp[1];
        rkp+= 2;
    }

    t0  = _saes64_encs_lo(n0, n1);
    t1  = _saes64_encs_hi(n0, n1);
    t0 ^= rkp[0];
    t1 ^= rkp[1];

    ctp[0] = t0;
    ctp[1] = t1;
}


//!  Key schedule for AES-128 Encryption.
void aes_128_enc_key_schedule(
    uint32_t  rk [AES_128_RK_WORDS    ],
    uint8_t   key[AES_128_KEY_BYTES   ]
) {
    uint64_t   temp     ;

    uint64_t * rkp      = (uint64_t*)rk ;
    uint64_t * ckp      = (uint64_t*)key;

    uint64_t   rk_lo    = ckp[0];
    uint64_t   rk_hi    = ckp[1];

    rkp[0]              = rk_lo;
    rkp[1]              = rk_hi;
    rkp                += 2    ;

    #define AES_128_KS_STEP(RCON) { \
        temp                = _saes64_ks1(rk_hi, RCON ); \
        rk_lo               = _saes64_ks2(temp , rk_lo); \
        rk_hi               = _saes64_ks2(rk_lo, rk_hi); \
        rkp[0]              = rk_lo; \
        rkp[1]              = rk_hi; \
        rkp                += 2    ; \
    }

    
    AES_128_KS_STEP( 0)
    AES_128_KS_STEP( 1)
    AES_128_KS_STEP( 2)
    AES_128_KS_STEP( 3)
    AES_128_KS_STEP( 4)
    AES_128_KS_STEP( 5)
    AES_128_KS_STEP( 6)
    AES_128_KS_STEP( 7)
    AES_128_KS_STEP( 8)
    AES_128_KS_STEP( 9)
    AES_128_KS_STEP(10)
    
    #undef AES_128_KS_STEP
}


//!@}
