
#include "aes_common.S"
    
#define T0 a4
#define T1 a5
#define T2 a6
#define T3 a7
#define U0 t0
#define U1 t1
#define U2 t2
#define U3 t3
#define PT a0
#define CT a1
#define RK a2
#define KP a3

.func   aes_128_ecb_decrypt                     // a0 - uint8_t     ct [16],
.global aes_128_ecb_decrypt                     // a1 - uint8_t     pt [16],
aes_128_ecb_decrypt:                            // a2 - uint32_t  * rk,
    addi    KP, RK, 16*10                       // kp = rk + 4*nr
    j       aes_ecb_decrypt
.endfunc

.func   aes_192_ecb_decrypt                     // a0 - uint8_t     ct [16],
.global aes_192_ecb_decrypt                     // a1 - uint8_t     pt [16],
aes_192_ecb_decrypt:                            // a2 - uint32_t  * rk,
    addi    KP, RK, 16*12                       // kp = rk + 4*nr
    j       aes_ecb_decrypt
.endfunc

.func   aes_256_ecb_decrypt                     // a0 - uint8_t     ct [16],
.global aes_256_ecb_decrypt                     // a1 - uint8_t     pt [16],
aes_256_ecb_decrypt:                            // a2 - uint32_t  * rk,
    addi    KP, RK, 16*14                       // kp = rk + 4*nr
    j       aes_ecb_decrypt
.endfunc


.func   aes_ecb_decrypt                         // a0 - uint8_t     pt [16],
                                                // a1 - uint8_t     ct [16],
aes_ecb_decrypt:                                // a2 - uint32_t  * rk,

    AES_LOAD_STATE T0,T1,T2,T3,CT,U0,U1,U2,U3   // Columns in T*

    lw      U0,  0(KP)                          // Load Round Key
    lw      U1,  4(KP)
    lw      U2,  8(KP)
    lw      U3, 12(KP)

    xor     T0, T0, U0                          // Add Round Key
    xor     T1, T1, U1
    xor     T2, T2, U2
    xor     T3, T3, U3

    addi    KP, KP, -32                         // Loop counter

.aes_dec_block_l0:
    
        lw      U0, 16(KP)                      // Load Round Key
        lw      U1, 20(KP)
        lw      U2, 24(KP)
        lw      U3, 28(KP)

        aes32dsmi  U0, T0, 0                    // Even Round
        aes32dsmi  U0, T3, 1
        aes32dsmi  U0, T2, 2
        aes32dsmi  U0, T1, 3

        aes32dsmi  U1, T1, 0
        aes32dsmi  U1, T0, 1
        aes32dsmi  U1, T3, 2
        aes32dsmi  U1, T2, 3

        aes32dsmi  U2, T2, 0
        aes32dsmi  U2, T1, 1
        aes32dsmi  U2, T0, 2
        aes32dsmi  U2, T3, 3

        aes32dsmi  U3, T3, 0
        aes32dsmi  U3, T2, 1
        aes32dsmi  U3, T1, 2
        aes32dsmi  U3, T0, 3                    // U* contains new state

        lw      T0,  0(KP)                      // Load Round Key
        lw      T1,  4(KP)
        lw      T2,  8(KP)
        lw      T3, 12(KP)

        beq     RK, KP, .aes_dec_block_l_finish // Break from loop
        addi    KP, KP, -32                     // Step Key pointer
        
        aes32dsmi  T0, U0, 0                    // Odd Round
        aes32dsmi  T0, U3, 1
        aes32dsmi  T0, U2, 2
        aes32dsmi  T0, U1, 3

        aes32dsmi  T1, U1, 0
        aes32dsmi  T1, U0, 1
        aes32dsmi  T1, U3, 2
        aes32dsmi  T1, U2, 3

        aes32dsmi  T2, U2, 0
        aes32dsmi  T2, U1, 1
        aes32dsmi  T2, U0, 2
        aes32dsmi  T2, U3, 3

        aes32dsmi  T3, U3, 0
        aes32dsmi  T3, U2, 1
        aes32dsmi  T3, U1, 2
        aes32dsmi  T3, U0, 3                    // T* contains new state

    j .aes_dec_block_l0                         // repeat loop

.aes_dec_block_l_finish:
    
    aes32dsi    T0, U0, 0                       // Final round, no MixColumns
    aes32dsi    T0, U3, 1
    aes32dsi    T0, U2, 2
    aes32dsi    T0, U1, 3

    aes32dsi    T1, U1, 0
    aes32dsi    T1, U0, 1
    aes32dsi    T1, U3, 2
    aes32dsi    T1, U2, 3

    aes32dsi    T2, U2, 0
    aes32dsi    T2, U1, 1
    aes32dsi    T2, U0, 2
    aes32dsi    T2, U3, 3

    aes32dsi    T3, U3, 0
    aes32dsi    T3, U2, 1
    aes32dsi    T3, U1, 2
    aes32dsi    T3, U0, 3                       // T* contains new state

    AES_DUMP_STATE  T0, T1, T2, T3, PT

    ret
    
    #undef T0 
    #undef T1 
    #undef T2 
    #undef T3 
    #undef U0 
    #undef U1 
    #undef U2 
    #undef U3 
    #undef TMP
    #undef HM 
    #undef MSK
    #undef CT 
    #undef PT 
    #undef RK 
    #undef KP 

.endfunc
