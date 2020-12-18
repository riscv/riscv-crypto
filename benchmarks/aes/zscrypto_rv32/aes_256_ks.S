
#include "aes_common.S"

.data

//
// Round constants for the AES Key Schedule
aes_round_const:
    .byte 0x01, 0x02, 0x04, 0x08, 0x10
    .byte 0x20, 0x40, 0x80, 0x1b, 0x36 


.text


.func     aes_256_enc_key_schedule
.global   aes_256_enc_key_schedule
aes_256_enc_key_schedule:       // a0 - uint32_t rk [AES_256_RK_WORDS]
                                // a1 - uint8_t  ck [AES_256_CK_BYTE ]

    #define C0  a2
    #define C1  a3
    #define C2  a4
    #define C3  a5
    #define C4  a7
    #define C5  t5
    #define C6  t6
    #define C7  t2

    #define RK  a0
    #define RKP a6
    #define CK  a1

    #define RKE t0
    #define RCP t1
    #define RCT t4

    #define T1  t3
    #define T2  t4

    lw  C0,  0(CK)
    lw  C1,  4(CK)
    lw  C2,  8(CK)
    lw  C3, 12(CK)
    lw  C4, 16(CK)
    lw  C5, 20(CK)
    lw  C6, 24(CK)
    lw  C7, 28(CK)
    
    mv      RKP, RK
    addi    RKE, RK, 56*4       //
    la      RCP, aes_round_const// t1 = round constant pointer
    
    sw      C0,  0(RKP)         // rkp[0]
    sw      C1,  4(RKP)         // rkp[1]
    sw      C2,  8(RKP)         // rkp[2]
    sw      C3, 12(RKP)         // rkp[3]

.aes_256_enc_ks_l0:             // Loop start

    sw      C4, 16(RKP)         // rkp[4]
    sw      C5, 20(RKP)         // rkp[5]
    sw      C6, 24(RKP)         // rkp[6]
    sw      C7, 28(RKP)         // rkp[7]

    addi    RKP, RKP, 32        // increment rkp


    lbu     RCT, 0(RCP)         // Load round constant byte
    addi    RCP, RCP, 1         // Increment round constant byte
    xor     C0, C0, RCT         // c0 ^= rcp
                                
    ROR32I T1, T2, C7, 8        // tr = ROR32(c3, 8)
    aes32esi C0, T1, 0   // tr = sbox(tr)
    aes32esi C0, T1, 1   //
    aes32esi C0, T1, 2   //
    aes32esi C0, T1, 3   //
    
    xor     C1, C1, C0          // C1 ^= C0
    xor     C2, C2, C1          // C2 ^= C1
    xor     C3, C3, C2          // C3 ^= C2
    
    sw      C0,  0(RKP)         // rkp[0]
    sw      C1,  4(RKP)         // rkp[1]
    sw      C2,  8(RKP)         // rkp[2]
    sw      C3, 12(RKP)         // rkp[3]
    
    beq     RKE, RKP, .aes_256_enc_ks_finish
    
    aes32esi C4, C3, 0   // tr = sbox(tr)
    aes32esi C4, C3, 1   //
    aes32esi C4, C3, 2   //
    aes32esi C4, C3, 3   //

    xor     C5, C5, C4          // C5 ^= C4
    xor     C6, C6, C5          // C6 ^= C5
    xor     C7, C7, C6          // C7 ^= C6

    j .aes_256_enc_ks_l0        // Loop continue

.aes_256_enc_ks_finish:
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


.func     aes_256_dec_key_schedule
.global   aes_256_dec_key_schedule
aes_256_dec_key_schedule:           // a0 - uint32_t rk [AES_256_RK_WORDS]
                                    // a1 - uint8_t  ck [AES_256_CK_BYTE ]
    
    #define RK  a0
    #define RKP a2
    #define RKE a3
    #define T0  t0
    #define T1  t1

    addi    sp, sp, -16              // Save stack
    sw      ra, 0(sp)

    call    aes_256_enc_key_schedule //

    addi    RKP, RK, 16              // a0 = &rk[ 4]
    addi    RKE, RK, 56*4            // a1 = &rk[40]

    .dec_ks_loop:
        
        lw   T0, 0(RKP)              // Load key word

        li        T1, 0
        aes32esi  T1, T0, 0          // Sub Word Forward
        aes32esi  T1, T0, 1 
        aes32esi  T1, T0, 2
        aes32esi  T1, T0, 3

        li        T0, 0
        aes32dsmi T0, T1, 0          // Sub Word Inverse & Inverse MixColumns
        aes32dsmi T0, T1, 1
        aes32dsmi T0, T1, 2
        aes32dsmi T0, T1, 3

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


