
#include "aes_common.S"

.data

//
// Round constants for the AES Key Schedule
aes_round_const:
    .byte 0x01, 0x02, 0x04, 0x08, 0x10
    .byte 0x20, 0x40, 0x80, 0x1b, 0x36 


.text


.func     aes_128_enc_key_schedule
.global   aes_128_enc_key_schedule
aes_128_enc_key_schedule:       // a0 - uint32_t rk [AES_128_RK_WORDS]
                                // a1 - uint8_t  ck [AES_128_CK_BYTE ]

    #define C0  a2
    #define C1  a3
    #define C2  a4
    #define C3  a5

    #define RK  a0
    #define RKP a6
    #define CK  a1

    #define RKE t0
    #define RCP t1
    #define RCT t2

    #define T1  t3
    #define T2  t4

    AES_LOAD_STATE C0,C1,C2,C3,CK,t0,t1,t2,t3 
    
    mv      RKP, RK
    addi    RKE, RK, 160        // t0 = rke = rk + 40
    la      RCP, aes_round_const// t1 = round constant pointer

.aes_128_enc_ks_l0:             // Loop start

    sw      C0,  0(RKP)         // rkp[0] = a2
    sw      C1,  4(RKP)         // rkp[1] = a3
    sw      C2,  8(RKP)         // rkp[2] = a4
    sw      C3, 12(RKP)         // rkp[3] = a5
                                
                                // if rke==rkp, return - loop break
    beq     RKE, RKP, .aes_128_enc_ks_finish

    addi    RKP, RKP, 16        // increment rkp

    lbu     RCT, 0(RCP)         // Load round constant byte
    addi    RCP, RCP, 1         // Increment round constant byte
    xor     C0, C0, RCT         // c0 ^= rcp

    ROR32I T1, T2, C3, 8        // tr = ROR32(c3, 8)
    aes32esi C0, C0, T1, 0   // tr = sbox(tr)
    aes32esi C0, C0, T1, 1   //
    aes32esi C0, C0, T1, 2   //
    aes32esi C0, C0, T1, 3   //

    xor     C1, C1, C0          // C1 ^= C0
    xor     C2, C2, C1          // C1 ^= C0
    xor     C3, C3, C2          // C1 ^= C0

    j .aes_128_enc_ks_l0        // Loop continue

.aes_128_enc_ks_finish:
    ret

    #undef C0 
    #undef C1 
    #undef C2 
    #undef C3 
    #undef RK 
    #undef RKP
    #undef CK 
    #undef RKE
    #undef RCP
    #undef RCT
    #undef T1 
    #undef T2 

.endfunc


.func     aes_128_dec_key_schedule
.global   aes_128_dec_key_schedule
aes_128_dec_key_schedule:           // a0 - uint32_t rk [AES_128_RK_WORDS]
                                    // a1 - uint8_t  ck [AES_128_CK_BYTE ]
    
    #define RK  a0
    #define RKP a2
    #define RKE a3
    #define T0  t0
    #define T1  t1

    addi    sp, sp, -16              // Save stack
    sw      ra, 0(sp)

    call    aes_128_enc_key_schedule //

    addi    RKP, RK, 16              // a0 = &rk[ 4]
    addi    RKE, RK, 160             // a1 = &rk[40]

    .dec_ks_loop:
        
        lw   T0, 0(RKP)              // Load key word

        aes32esi  T1, zero, T0, 0 // Sub Word Forward
        aes32esi  T1, T1  , T0, 1 
        aes32esi  T1, T1  , T0, 2
        aes32esi  T1, T1  , T0, 3

        aes32dsmi T0, zero, T1, 0 // Sub Word Inverse & Inverse MixColumns
        aes32dsmi T0, T0  , T1, 1
        aes32dsmi T0, T0  , T1, 2
        aes32dsmi T0, T0  , T1, 3

        sw   T0, 0(RKP)             // Store key word.

        addi RKP, RKP, 4            // Increment round key pointer
        bne  RKP, RKE, .dec_ks_loop // Finished yet?

    lw      ra, 0(sp)
    addi    sp, sp,  16

    ret
    
    #undef RK
    #undef RKP
    #undef RKE
    #undef T0
    #undef T1
.endfunc

