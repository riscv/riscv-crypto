
#include "aes_common.S"

.data

.text

//
// Computes 2 round keys per invocation.
.macro AES_256_KEY_ROUND RK0, RK1, RK2, RK3, T0, RKP, I
    sd  \RK0, ( 0+(\I*32))(\RKP)
    sd  \RK1, ( 8+(\I*32))(\RKP)
    sd  \RK2, (16+(\I*32))(\RKP)
    sd  \RK3, (24+(\I*32))(\RKP)
    saes64.ks1  \T0 , \RK3 , \I
    saes64.ks2  \RK0, \T0  , \RK0
    saes64.ks2  \RK1, \RK0 , \RK1
    saes64.ks1  \T0 , \RK1 , 0xA
    saes64.ks2  \RK2, \T0  , \RK2
    saes64.ks2  \RK3, \RK2 , \RK3
.endm

.func   aes_256_enc_key_schedule
.global aes_256_enc_key_schedule
aes_256_enc_key_schedule:       // a0 - uint32_t rk [AES_256_RK_WORDS]
                                // a1 - uint8_t  ck [AES_256_CK_BYTE ]

    #define RKP   a0
    #define CKP   a1
    #define T0    t0
    #define RK0   a2
    #define RK1   a3
    #define RK2   a4
    #define RK3   a5

    ld  RK0,  0(CKP)            // Load initial round/cipher key
    ld  RK1,  8(CKP)
    ld  RK2, 16(CKP)
    ld  RK3, 24(CKP)

    AES_256_KEY_ROUND RK0, RK1, RK2, RK3, T0, RKP, 0
    AES_256_KEY_ROUND RK0, RK1, RK2, RK3, T0, RKP, 1
    AES_256_KEY_ROUND RK0, RK1, RK2, RK3, T0, RKP, 2
    AES_256_KEY_ROUND RK0, RK1, RK2, RK3, T0, RKP, 3
    AES_256_KEY_ROUND RK0, RK1, RK2, RK3, T0, RKP, 4
    AES_256_KEY_ROUND RK0, RK1, RK2, RK3, T0, RKP, 5
    
    sd  RK0, ( 0+(6*32))(RKP)
    sd  RK1, ( 8+(6*32))(RKP)
    sd  RK2, (16+(6*32))(RKP)
    sd  RK3, (24+(6*32))(RKP)
    
    saes64.ks1  T0 , RK3 , 6
    saes64.ks2  RK0, T0  , RK0
    saes64.ks2  RK1, RK0 , RK1
    
    sd  RK0, ( 0+(7*32))(RKP)
    sd  RK1, ( 8+(7*32))(RKP)

    ret

.endfunc


.func   aes_256_dec_key_schedule
.global aes_256_dec_key_schedule
aes_256_dec_key_schedule:       // a0 - uint32_t rk [AES_256_RK_WORDS]
                                // a1 - uint8_t  ck [AES_256_CK_BYTE ]

    #define RKP t0
    #define RKE t1

    addi sp, sp, -32
    sd   ra, 0(sp)
    sd   a0, 8(sp)
    sd   a1,16(sp)

    call aes_256_enc_key_schedule

    addi a0, a0, 16
    addi a1, a0, 8*(60/2-4)

    call aes_ks_dec_invmc
        
    ld   ra, 0(sp)
    ld   a0, 8(sp)
    ld   a1,16(sp)
    addi sp, sp, 32
    
    ret
