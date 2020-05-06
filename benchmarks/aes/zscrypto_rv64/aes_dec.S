
#include "aes_common.S"
    
#define T0      t0
#define T1      t1
#define K0      t2
#define K1      t3
#define CT      a1
#define PT      a0
#define RK      a2
#define NR      a3
#define S0      a5
#define S1      a6
#define N0      a7
#define N1      t6

.text

.macro DOUBLE_ROUND RK, K0, K1, K2, K3, S0, S1, N0, N1, OFFSET
    ld           \K0, \OFFSET +16(\RK)      // Load two roundkeys in a
    ld           \K1, \OFFSET +24(\RK)      // batch
    ld           \K2, \OFFSET + 0(\RK)
    ld           \K3, \OFFSET + 8(\RK)
    saes64.decsm \N0, \S0, \S1              // InvShiftRows, InvSubBytes
    saes64.decsm \N1, \S1, \S0              // InvMixColumns
    xor          \S0, \N0, \K0              // Add Round Key
    xor          \S1, \N1, \K1
    saes64.decsm \N0, \S0, \S1              // InvShiftRows, InvSubBytes
    saes64.decsm \N1, \S1, \S0              // InvMixColumns
    xor          \S0, \N0, \K2              // AddRoundKey
    xor          \S1, \N1, \K3
.endm

.macro LAST_2ROUNDS RK, K0, K1, K2, K3, S0, S1, N0, N1, OFFSET
    ld           \K0,\OFFSET +16(\RK)       // Load two round keys
    ld           \K1,\OFFSET +24(\RK)
    ld           \K2,\OFFSET + 0(\RK)
    ld           \K3,\OFFSET + 8(\RK)
    saes64.decsm \N0, \S0, \S1              // InvShiftRows, InvSubBytes
    saes64.decsm \N1, \S1, \S0              // InvMixColumns
    xor          \S0, \N0, \K0              // Add Round Key
    xor          \S1, \N1, \K1
    saes64.decs  \N0, \S0, \S1              // InvShiftRows, InvSubBytes
    saes64.decs  \N1, \S1, \S0
    xor          \S0, \N0, \K2              // Final AddRoundKey
    xor          \S1, \N1, \K3
.endm

//
// AES 128 Decrypt
//

.func   aes_128_ecb_decrypt                    // a0 - uint8_t     pt [16],
.global aes_128_ecb_decrypt                    // a1 - uint8_t     ct [16],
aes_128_ecb_decrypt:                           // a2 - uint32_t  * rk

    AES_LOAD_STATE S0, S1, CT, T0, T1       // Load ciphertext

    ld      K0, 5*32+0(RK)
    ld      K1, 5*32+8(RK)

    xor     S0, S0, K0
    xor     S1, S1, K1

    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 4*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 3*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 2*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 1*32
    LAST_2ROUNDS RK, K0, K1, T0, T1, S0, S1, N0, N1, 0*32

    AES_DUMP_STATE S0, S1, PT, T0, T1, 0    // Save plaintext

    ret
.endfunc


//
// AES 192 Decrypt
//

.func   aes_192_ecb_decrypt                    // a0 - uint8_t     pt [16],
.global aes_192_ecb_decrypt                    // a1 - uint8_t     ct [16],
aes_192_ecb_decrypt:                           // a2 - uint32_t  * rk

    AES_LOAD_STATE S0, S1, CT, T0, T1       // Load ciphertext

    ld      K0, 6*32+0(RK)
    ld      K1, 6*32+8(RK)

    xor     S0, S0, K0
    xor     S1, S1, K1

    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 5*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 4*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 3*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 2*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 1*32
    LAST_2ROUNDS RK, K0, K1, T0, T1, S0, S1, N0, N1, 0*32

    AES_DUMP_STATE S0, S1, PT, T0, T1, 0    // Save plaintext

    ret
.endfunc

//
// AES 256 Decrypt
//

.func   aes_256_ecb_decrypt                    // a0 - uint8_t     pt [16],
.global aes_256_ecb_decrypt                    // a1 - uint8_t     ct [16],
aes_256_ecb_decrypt:                           // a2 - uint32_t  * rk

    AES_LOAD_STATE S0, S1, CT, T0, T1       // Load ciphertext

    ld      K0, 7*32+0(RK)
    ld      K1, 7*32+8(RK)

    xor     S0, S0, K0
    xor     S1, S1, K1

    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 6*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 5*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 4*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 3*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 2*32
    DOUBLE_ROUND RK, K0, K1, T0, T1, S0, S1, N0, N1, 1*32
    LAST_2ROUNDS RK, K0, K1, T0, T1, S0, S1, N0, N1, 0*32

    AES_DUMP_STATE S0, S1, PT, T0, T1, 0    // Save plaintext

    ret
.endfunc

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
