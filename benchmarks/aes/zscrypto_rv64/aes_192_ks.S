
#include "aes_common.S"

.data

.text

//
// Computes 1.5 round keys per invocation.
.macro AES_192_KEY_ROUND RK0, RK1, RK2, T0, RKP, I
    sd          \RK0, ( 0+(24*\I))(\RKP)
    sd          \RK1, ( 8+(24*\I))(\RKP)
    sd          \RK2, (16+(24*\I))(\RKP)
    saes64.ks1  \T0 , \RK2 , \I
    saes64.ks2  \RK0, \T0  , \RK0
    saes64.ks2  \RK1, \RK0 , \RK1
    saes64.ks2  \RK2, \RK1 , \RK2
.endm

.func   aes_192_enc_key_schedule
.global aes_192_enc_key_schedule
aes_192_enc_key_schedule:       // a0 - uint32_t rk [AES_192_RK_WORDS]
                                // a1 - uint8_t  ck [AES_192_CK_BYTE ]

    #define RKP   a0
    #define CKP   a1
    #define T0    t0
    #define RK0   a2
    #define RK1   a3
    #define RK2   a4

    ld  RK0,  0(CKP)            // Load initial round/cipher key
    ld  RK1,  8(CKP)
    ld  RK2, 16(CKP)

    AES_192_KEY_ROUND RK0, RK1, RK2, T0, RKP, 0
    AES_192_KEY_ROUND RK0, RK1, RK2, T0, RKP, 1
    AES_192_KEY_ROUND RK0, RK1, RK2, T0, RKP, 2
    AES_192_KEY_ROUND RK0, RK1, RK2, T0, RKP, 3
    AES_192_KEY_ROUND RK0, RK1, RK2, T0, RKP, 4
    AES_192_KEY_ROUND RK0, RK1, RK2, T0, RKP, 5
    AES_192_KEY_ROUND RK0, RK1, RK2, T0, RKP, 6

    sd  RK0, ( 0+(24*7))(RKP)
    sd  RK1, ( 8+(24*7))(RKP)
    sd  RK2, (16+(24*7))(RKP)
    
    saes64.ks1  T0 , RK2 , 7
    saes64.ks2  RK0, T0  , RK0
    saes64.ks2  RK1, RK0 , RK1
    
    sd  RK0, ( 0+(24*8))(RKP)
    sd  RK1, ( 8+(24*8))(RKP)

    ret

.endfunc


.func   aes_192_dec_key_schedule
.global aes_192_dec_key_schedule
aes_192_dec_key_schedule:       // a0 - uint32_t rk [AES_192_RK_WORDS]
                                // a1 - uint8_t  ck [AES_192_CK_BYTE ]

    #define RKP t0
    #define RKE t1

    addi sp, sp, -32
    sd   ra, 0(sp)
    sd   a0, 8(sp)
    sd   a1,16(sp)

    call aes_192_enc_key_schedule

    addi a0, a0, 16
    addi a1, a0, 8*(52/2-4)

    call aes_ks_dec_invmc
        
    ld   ra, 0(sp)
    ld   a0, 8(sp)
    ld   a1,16(sp)
    addi sp, sp, 32
    
    ret
