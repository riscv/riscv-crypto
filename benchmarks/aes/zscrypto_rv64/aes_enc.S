
#include "aes_common.S"

.text

.macro DOUBLE_ROUND RK, K0, K1, K2, K3, S0, S1, N0, N1, OFFSET
    ld  \K0, (\OFFSET + 0)(\RK)                // Load round keys in
    ld  \K1, (\OFFSET + 8)(\RK)                // batches of 4 double words
    ld  \K2, (\OFFSET +16)(\RK)
    ld  \K3, (\OFFSET +24)(\RK)
    xor \S0, \S0, \K0                          // AddRoundKey
    xor \S1, \S1, \K1
    saes64.encsm.lo \N0, \S0, \S1              // Rest of round
    saes64.encsm.lo \N1, \S1, \S0
    xor \N0, \N0, \K2                          // AddRoundKey
    xor \N1, \N1, \K3
    saes64.encsm.lo \S0, \N0, \N1              // Rest of round
    saes64.encsm.lo \S1, \N1, \N0
.endm

.macro LAST_2ROUNDS RK, K0, K1, K2, K3, S0, S1, N0, N1, OFFSET
    ld  \K0, (\OFFSET + 0)(\RK)                // Load two round keys
    ld  \K1, (\OFFSET + 8)(\RK)
    ld  \K2, (\OFFSET +16)(\RK)
    ld  \K3, (\OFFSET +24)(\RK)
    xor \S0, \S0, \K0                          // AddRoundKey
    xor \S1, \S1, \K1
    ld  \K0, (\OFFSET +32)(\RK)                // Load final round key
    ld  \K1, (\OFFSET +40)(\RK)
    saes64.encsm.lo \N0, \S0, \S1              // Rest of round
    saes64.encsm.lo \N1, \S1, \S0
    xor \N0, \N0, \K2                          // AddRoundKey
    xor \N1, \N1, \K3
    saes64.encs.lo  \S0, \N0, \N1              // Rest of round
    saes64.encs.lo  \S1, \N1, \N0
    xor \S0, \S0, \K0                          // Final AddRoundKey
    xor \S1, \S1, \K1
.endm

.func   aes_128_ecb_encrypt                    // a0 - uint8_t     ct [16],
.global aes_128_ecb_encrypt                    // a1 - uint8_t     pt [16],
aes_128_ecb_encrypt:                           // a2 - uint32_t  * rk,
    
    #define T0      t0
    #define T1      t1
    #define K0      t2
    #define K1      t3
    #define CT      a0
    #define PT      a1
    #define RK      a2
    #define NR      a3
    #define S0      a5
    #define S1      a6
    #define N0      a7
    #define N1      t5

    AES_LOAD_STATE S0, S1, PT, T0, T1       // Load plaintext

    DOUBLE_ROUND   RK, K0, K1, T0, T1, S0, S1, N0, N1, 0
    DOUBLE_ROUND   RK, K0, K1, T0, T1, S0, S1, N0, N1, 32
    DOUBLE_ROUND   RK, K0, K1, T0, T1, S0, S1, N0, N1, 64
    DOUBLE_ROUND   RK, K0, K1, T0, T1, S0, S1, N0, N1, 96
    LAST_2ROUNDS   RK, K0, K1, T0, T1, S0, S1, N0, N1, 128

    AES_DUMP_STATE S0, S1, CT, T0, T1, 0    // Save ciphertext

    ret
    
    #undef T0
    #undef T1
    #undef K0
    #undef K1
    #undef CT
    #undef PT
    #undef RK
    #undef NR
    #undef S0
    #undef S1
    #undef N0
    #undef N1
.endfunc
