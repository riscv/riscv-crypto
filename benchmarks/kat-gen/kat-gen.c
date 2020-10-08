
#include <stdio.h>
#include <stdint.h>

#include "riscv-crypto-intrinsics.h"

// How many input/output value pairs to create per instruction?
const int NUM_KATS = 10;

// Stringification macros
#define XSTR(s) #s
#define STR(s) XSTR(s)

//! Current XLEN-bit state of the PRNG used to create inputs.
static uint_xlen_t __rng_state;

//! Print a 0-padded XLEN-bit value as hexadecimal.
void puthex_xlen(uint_xlen_t x) {
    #if __riscv_xlen == 32
    printf("%08lX",x);
    #elif __riscv_xlen == 64
    printf("%016lX",x);
    #else
    #error "Unsupported __riscv_xlen value. Expected 32 or 64"
    #endif
}

/*
@brief A very, very simple LFSR random number generator.
@details Tap positions taken from:
https://www.xilinx.com/support/documentation/application_notes/xapp210.pdf
*/
uint_xlen_t sample_rng () {
    #if __riscv_xlen == 32
    __rng_state =
        ((__rng_state << 1 )      ) ^
        ((__rng_state >> 31) & 0x1) ^
        ((__rng_state >> 21) & 0x1) ^
        ((__rng_state >>  1) & 0x1) ^
        ((__rng_state >>  0) & 0x1) ;
    #elif __riscv_xlen == 64
    __rng_state =
        ((__rng_state << 1 )      ) ^
        ((__rng_state >> 63) & 0x1) ^
        ((__rng_state >> 62) & 0x1) ^
        ((__rng_state >> 60) & 0x1) ^
        ((__rng_state >> 59) & 0x1) ;
    #else
    #error "Unsupported __riscv_xlen value. Expected 32 or 64"
    #endif
    return __rng_state;
}


/*!
@brief Macro for creating input/output values for a 2-reg address instruction.
*/
#define TEST_RD_RS1(INTRINSIC_FUNCTION,MNEMONIC) {                  \
    for(int i = 0; i < NUM_KATS; i ++) {                            \
        uint_xlen_t rs1= sample_rng();                              \
        uint_xlen_t rd = INTRINSIC_FUNCTION (rs1);                  \
        printf("# " STR(MNEMONIC) " ");                             \
        printf(" rd=0x" ); puthex_xlen(rd ); printf("," );          \
        printf(" rs1=0x"); puthex_xlen(rs1); printf("\n");          \
    }                                                               \
}


/*!
@brief Macro for creating input/output values for a 2-reg address instruction
       with an immediate.
*/
#define TEST_RD_RS1_IMM(INTRINSIC_FUNCTION,MNEMONIC, IMM) {         \
    for(int i = 0; i < NUM_KATS; i ++) {                            \
        uint_xlen_t rs1= sample_rng();                              \
        uint_xlen_t rd = INTRINSIC_FUNCTION (rs1, IMM);             \
        printf("# " STR(MNEMONIC) " ");                             \
        printf(" rd=0x" ); puthex_xlen(rd ); printf("," );          \
        printf(" rs1=0x"); puthex_xlen(rs1); printf("," );          \
        printf(" imm=0x"); puthex_xlen(IMM); printf("\n");          \
    }                                                               \
}

/*!
@brief Macro for creating input/output values for a 3-reg address instruction.
*/
#define TEST_RD_RS1_RS2(INTRINSIC_FUNCTION,MNEMONIC) {              \
    for(int i = 0; i < NUM_KATS; i ++) {                            \
        uint_xlen_t rs1= sample_rng();                              \
        uint_xlen_t rs2= sample_rng();                              \
        uint_xlen_t rd = INTRINSIC_FUNCTION (rs1, rs2);             \
        printf("# " STR(MNEMONIC) " ");                             \
        printf(" rd=0x" ); puthex_xlen(rd ); printf("," );          \
        printf(" rs1=0x"); puthex_xlen(rs1); printf("," );          \
        printf(" rs2=0x"); puthex_xlen(rs2); printf("\n");          \
    }                                                               \
}


/*!
@brief Macro for creating input/output values for a 3-reg address instruction.
       with a small immediate.
*/
#define TEST_RD_RS1_RS2_IMM(INTRINSIC_FUNCTION,MNEMONIC,IMM) { \
    for(int i = 0; i < NUM_KATS; i ++) {                            \
        uint_xlen_t rs1= sample_rng();                              \
        uint_xlen_t rs2= sample_rng();                              \
        uint_xlen_t rd = INTRINSIC_FUNCTION (rs1, rs2, IMM);        \
        printf("# " STR(MNEMONIC) " ");                             \
        printf(" rd=0x" ); puthex_xlen(rd ); printf("," );          \
        printf(" rs1=0x"); puthex_xlen(rs1); printf("," );          \
        printf(" rs2=0x"); puthex_xlen(rs2); printf("," );          \
        printf(" imm=0x"); puthex_xlen(IMM); printf("\n");          \
    }                                                               \
}

void generate_kats() {

    // 32/64-bit SHA256 instructions.
    TEST_RD_RS1(_sha256sig0, sha256sig0)
    TEST_RD_RS1(_sha256sig1, sha256sig1)
    TEST_RD_RS1(_sha256sum0, sha256sum0)
    TEST_RD_RS1(_sha256sum1, sha256sum1)
    
    // 32/64-bit SM3    instructions.
    TEST_RD_RS1(_sm3p0, sm3p0)
    TEST_RD_RS1(_sm3p1, sm3p1)

    // 32/64-bit SM4    instructions.
    TEST_RD_RS1_RS2_IMM(_sm4ed, sm4ed, 0x0)
    TEST_RD_RS1_RS2_IMM(_sm4ed, sm4ed, 0x1)
    TEST_RD_RS1_RS2_IMM(_sm4ed, sm4ed, 0x2)
    TEST_RD_RS1_RS2_IMM(_sm4ed, sm4ed, 0x3)

    TEST_RD_RS1_RS2_IMM(_sm4ks, sm4ks, 0x0)
    TEST_RD_RS1_RS2_IMM(_sm4ks, sm4ks, 0x1)
    TEST_RD_RS1_RS2_IMM(_sm4ks, sm4ks, 0x2)
    TEST_RD_RS1_RS2_IMM(_sm4ks, sm4ks, 0x3)

    #if __riscv_xlen == 32

        // 32-bit SHA-512 instructions.
        TEST_RD_RS1_RS2(_sha512sig0l, sha512sig0l)
        TEST_RD_RS1_RS2(_sha512sig1l, sha512sig1l)
        TEST_RD_RS1_RS2(_sha512sig0h, sha512sig0h)
        TEST_RD_RS1_RS2(_sha512sig1h, sha512sig1h)
        TEST_RD_RS1_RS2(_sha512sum0r, sha512sum0r)
        TEST_RD_RS1_RS2(_sha512sum1r, sha512sum1r)

        // 32-bit AES instructions.
        TEST_RD_RS1_RS2_IMM(_aes32esi , aes32esi , 0x0)
        TEST_RD_RS1_RS2_IMM(_aes32esi , aes32esi , 0x1)
        TEST_RD_RS1_RS2_IMM(_aes32esi , aes32esi , 0x2)
        TEST_RD_RS1_RS2_IMM(_aes32esi , aes32esi , 0x3)

        TEST_RD_RS1_RS2_IMM(_aes32esmi, aes32esmi, 0x0)
        TEST_RD_RS1_RS2_IMM(_aes32esmi, aes32esmi, 0x1)
        TEST_RD_RS1_RS2_IMM(_aes32esmi, aes32esmi, 0x2)
        TEST_RD_RS1_RS2_IMM(_aes32esmi, aes32esmi, 0x3)
        
        TEST_RD_RS1_RS2_IMM(_aes32dsi , aes32dsi , 0x0)
        TEST_RD_RS1_RS2_IMM(_aes32dsi , aes32dsi , 0x1)
        TEST_RD_RS1_RS2_IMM(_aes32dsi , aes32dsi , 0x2)
        TEST_RD_RS1_RS2_IMM(_aes32dsi , aes32dsi , 0x3)

        TEST_RD_RS1_RS2_IMM(_aes32dsmi, aes32dsmi, 0x0)
        TEST_RD_RS1_RS2_IMM(_aes32dsmi, aes32dsmi, 0x1)
        TEST_RD_RS1_RS2_IMM(_aes32dsmi, aes32dsmi, 0x2)
        TEST_RD_RS1_RS2_IMM(_aes32dsmi, aes32dsmi, 0x3)
    
    #elif __riscv_xlen == 64

        // 64-bit SHA-512 instructions.
        TEST_RD_RS1(_sha512sig0, sha512sig0)
        TEST_RD_RS1(_sha512sig1, sha512sig1)
        TEST_RD_RS1(_sha512sum0, sha512sum0)
        TEST_RD_RS1(_sha512sum1, sha512sum1)
        
        // 64-bit AES instructions.
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0x0)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0x1)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0x2)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0x3)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0x4)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0x5)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0x6)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0x7)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0x8)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0x9)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64_ks1i, 0xA)

        TEST_RD_RS1_RS2(_aes64ks2 , aes64ks2      )
        TEST_RD_RS1(_aes64im  , aes64im       )
        TEST_RD_RS1_RS2(_aes64es  , aes64es       )
        TEST_RD_RS1_RS2(_aes64esm , aes64esm      )
        TEST_RD_RS1_RS2(_aes64ds  , aes64ds       )
        TEST_RD_RS1_RS2(_aes64dsm , aes64dsm      )
    #endif

}

int main(int argc, char ** argv) {

    printf("# RISC-V Crypto KAT GEN\n");
    printf("# XLEN = %d\n", __riscv_xlen);

    #if __riscv_xlen == 32
    __rng_state = 0x78ABCDEF;
    #elif __riscv_xlen == 64
    __rng_state = 0x34ABCDEF01234567UL;
    #else
    #error "Unsupported __riscv_xlen value. Expected 32 or 64"
    #endif

    printf("# Initial PRNG Seed: 0x"); puthex_xlen(__rng_state); printf("\n");

    generate_kats();
}
