
#include "aes_common.S"

.data

.text


//
// Computes 1 round key per invocation.
.macro AES_128_KEY_ROUND RK_LO, RK_HI, RK, TMP1, TMP2, OFFSET, RCON
    saes64.ks1      \TMP1 , \RK_HI, \RCON
    saes64.ks2      \RK_LO, \TMP1 , \RK_LO
    saes64.ks2      \RK_HI, \RK_LO, \RK_HI
    AES_DUMP_STATE  \RK_LO, \RK_HI, \RK   , \TMP1, \TMP2, \OFFSET
.endm

.func   aes_128_enc_key_schedule
.global aes_128_enc_key_schedule
aes_128_enc_key_schedule:       // a0 - uint32_t rk [AES_128_RK_WORDS]
                                // a1 - uint8_t  ck [AES_128_CK_BYTE ]

    #define RK    a0
    #define CK    a1
    #define TMP1  t0
    #define TMP2  t1
    #define TMP3  t2
    #define RK_LO a2
    #define RK_HI a3
                                // See aes_common.S for load/dump_state macros
    AES_LOAD_STATE  RK_LO, RK_HI, CK, TMP1, TMP2

    AES_DUMP_STATE  RK_LO, RK_HI, RK, TMP1, TMP2, 0*16

    AES_128_KEY_ROUND   RK_LO, RK_HI, RK, TMP1, TMP2, 1*16, 0
    AES_128_KEY_ROUND   RK_LO, RK_HI, RK, TMP1, TMP2, 2*16, 1
    AES_128_KEY_ROUND   RK_LO, RK_HI, RK, TMP1, TMP2, 3*16, 2
    AES_128_KEY_ROUND   RK_LO, RK_HI, RK, TMP1, TMP2, 4*16, 3
    AES_128_KEY_ROUND   RK_LO, RK_HI, RK, TMP1, TMP2, 5*16, 4
    AES_128_KEY_ROUND   RK_LO, RK_HI, RK, TMP1, TMP2, 6*16, 5
    AES_128_KEY_ROUND   RK_LO, RK_HI, RK, TMP1, TMP2, 7*16, 6
    AES_128_KEY_ROUND   RK_LO, RK_HI, RK, TMP1, TMP2, 8*16, 7
    AES_128_KEY_ROUND   RK_LO, RK_HI, RK, TMP1, TMP2, 9*16, 8
    AES_128_KEY_ROUND   RK_LO, RK_HI, RK, TMP1, TMP2,10*16, 9

    ret

    #undef RK
    #undef CK
    #undef TMP1
    #undef TMP2
    #undef TMP3
    #undef RK_LO
    #undef RK_HI

.endfunc

// Defined in aes_ks_dec_invmc.S
.extern aes_ks_dec_invmc

.func   aes_128_dec_key_schedule
.global aes_128_dec_key_schedule
aes_128_dec_key_schedule:       // a0 - uint32_t rk [AES_128_RK_WORDS]
                                // a1 - uint8_t  ck [AES_128_CK_BYTE ]

    #define RKP t0
    #define RKE t1

    addi sp, sp, -32
    sd   ra, 0(sp)
    sd   a0, 8(sp)
    sd   a1,16(sp)

    call aes_128_enc_key_schedule

    addi a0, a0, 16
    addi a1, a0, 8*(44/2-4)

    call aes_ks_dec_invmc
        
    ld   ra, 0(sp)
    ld   a0, 8(sp)
    ld   a1,16(sp)
    addi sp, sp, 32
    
    ret

