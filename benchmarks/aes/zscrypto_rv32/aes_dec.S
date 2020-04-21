
#include "aes_common.S"

.func   aes_128_ecb_decrypt                     // a0 - uint8_t     pt [16],
.global aes_128_ecb_decrypt                     // a1 - uint8_t     ct [16],
aes_128_ecb_decrypt:                            // a2 - uint32_t  * rk,
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

    addi    KP, RK, 160                         // kp = rk + 4*nr

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

        saes32.decsm   U0, U0, T0, 0            // Even Round
        saes32.decsm   U0, U0, T3, 1
        saes32.decsm   U0, U0, T2, 2
        saes32.decsm   U0, U0, T1, 3
                                 
        saes32.decsm   U1, U1, T1, 0
        saes32.decsm   U1, U1, T0, 1
        saes32.decsm   U1, U1, T3, 2
        saes32.decsm   U1, U1, T2, 3
                                 
        saes32.decsm   U2, U2, T2, 0
        saes32.decsm   U2, U2, T1, 1
        saes32.decsm   U2, U2, T0, 2
        saes32.decsm   U2, U2, T3, 3
                                 
        saes32.decsm   U3, U3, T3, 0
        saes32.decsm   U3, U3, T2, 1
        saes32.decsm   U3, U3, T1, 2
        saes32.decsm   U3, U3, T0, 3            // U* contains new state

        lw      T0,  0(KP)                      // Load Round Key
        lw      T1,  4(KP)
        lw      T2,  8(KP)
        lw      T3, 12(KP)

        beq     RK, KP, .aes_dec_block_l_finish // Break from loop
        addi    KP, KP, -32                     // Step Key pointer
        
        saes32.decsm   T0, T0, U0, 0            // Odd Round
        saes32.decsm   T0, T0, U3, 1
        saes32.decsm   T0, T0, U2, 2
        saes32.decsm   T0, T0, U1, 3
                                 
        saes32.decsm   T1, T1, U1, 0
        saes32.decsm   T1, T1, U0, 1
        saes32.decsm   T1, T1, U3, 2
        saes32.decsm   T1, T1, U2, 3
                                 
        saes32.decsm   T2, T2, U2, 0
        saes32.decsm   T2, T2, U1, 1
        saes32.decsm   T2, T2, U0, 2
        saes32.decsm   T2, T2, U3, 3
                                 
        saes32.decsm   T3, T3, U3, 0
        saes32.decsm   T3, T3, U2, 1
        saes32.decsm   T3, T3, U1, 2
        saes32.decsm   T3, T3, U0, 3            // T* contains new state

    j .aes_dec_block_l0                         // repeat loop

.aes_dec_block_l_finish:
    
    saes32.decs    T0, T0, U0, 0                // Final round, no MixColumns
    saes32.decs    T0, T0, U3, 1
    saes32.decs    T0, T0, U2, 2
    saes32.decs    T0, T0, U1, 3
                             
    saes32.decs    T1, T1, U1, 0
    saes32.decs    T1, T1, U0, 1
    saes32.decs    T1, T1, U3, 2
    saes32.decs    T1, T1, U2, 3
                             
    saes32.decs    T2, T2, U2, 0
    saes32.decs    T2, T2, U1, 1
    saes32.decs    T2, T2, U0, 2
    saes32.decs    T2, T2, U3, 3
                             
    saes32.decs    T3, T3, U3, 0
    saes32.decs    T3, T3, U2, 1
    saes32.decs    T3, T3, U1, 2
    saes32.decs    T3, T3, U0, 3               // T* contains new state

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
