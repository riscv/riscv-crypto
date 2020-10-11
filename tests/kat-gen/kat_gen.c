
#include "kat_gen.h"


// How many input/output value pairs to create per instruction?
int NUM_KATS = 1000;

// Stringification macros
#define XSTR(s) #s
#define STR(s) XSTR(s)

/*!
@brief IO function underlying all output from the KAT test generator.
@details Everything is implemented this way to make the function
        extremely easy to replace with something SoC/Simulator specific.
*/
void (*kat_put_char) (
    char c
);

/*
@brief Super simple put string function. Prints a null-terminated string
       using <kat_put_char> as the underlying I/O function.
*/
static void kat_put_str (
    char * str
) {
    for(int i = 0; str[i]; i ++) {
        kat_put_char(str[i]);
    }
}

/*!
@brief Print a 0-padded XLEN-bit value as hexadecimal.
@param x - The 32/64 bit number to print.
*/
static void kat_puthex_xlen(uint_xlen_t x) {
    const char * lut = "0123456789ABCDEF";
    #if __riscv_xlen == 32
    int i = 3;
    #elif __riscv_xlen == 64
    int i = 7;
    #else
    #error "Unsupported __riscv_xlen value. Expected 32 or 64"
    #endif
    while ( i >= 0 ) {
        uint8_t b_0 = (x >> (8*i    )) & 0xF;
        uint8_t b_1 = (x >> (8*i + 4)) & 0xF;
        kat_put_char(lut[b_1]);
        kat_put_char(lut[b_0]);
        i -= 1;
    }
}


/*!
@brief Current XLEN-bit state of the PRNG used to create inputs.
@note  Initialised in the <kat_generate> function.
*/
static uint_xlen_t __rng_state;

/*
@brief A very, very simple LFSR random number generator.
@details Tap positions taken from:
https://www.xilinx.com/support/documentation/application_notes/xapp210.pdf
*/
static uint_xlen_t sample_rng () {
    #if __riscv_xlen == 32
    __rng_state =
        ((__rng_state << 1 )      )  ^
        ~((__rng_state >> 31) & 0x1) ^
        ~((__rng_state >> 21) & 0x1) ^
        ~((__rng_state >>  1) & 0x1) ^
        ~((__rng_state >>  0) & 0x1) ;
    #elif __riscv_xlen == 64
    __rng_state =
        ((__rng_state << 1 )      )  ^
        ~((__rng_state >> 63) & 0x1) ^
        ~((__rng_state >> 62) & 0x1) ^
        ~((__rng_state >> 60) & 0x1) ^
        ~((__rng_state >> 59) & 0x1) ;
    #else
    #error "Unsupported __riscv_xlen value. Expected 32 or 64"
    #endif
    return __rng_state;
}

/*!
@brief Macro for starting an instruction result line.
@param MNEMONIC - The binutils mnemonic for the instruction.
*/
#define DICT_LINE_BEGIN(MNEMONIC) kat_put_str("  ('" STR(MNEMONIC) "',{")

/*!
@param Macro for adding a variable to an instruciton result line.
@note Must be used between a DICT_LINE_BEGIN/DICT_LINE_END macro pair.
@param NAME - the name of the input/output value for the instruction.
              Should correspond to a register/immediate operand.
@param VALUE - the value of the input/output.
*/
#define DICT_VAR(NAME,VALUE)            \
    kat_put_str("'" STR(NAME) "': 0x");    \
    kat_puthex_xlen(VALUE);             \
    kat_put_str(",")

/*!
@brief Macro for finishing an instruction result line.
@param MNEMONIC - The binutils mnemonic for the instruction.
*/
#define DICT_LINE_END(MNEMONIC)   kat_put_str("}),\n")

/*!
@brief Macro for creating input/output values for a 2-reg address instruction.
@param INTRINSIC_FUNCTION - The C intrinsic function name mapping to MNEMONIC
@param MNEMONIC - The assembly instruction mnemonic for the instruction
*/
#define TEST_RD_RS1(INTRINSIC_FUNCTION,MNEMONIC) {                          \
    for(int i = 0; i < NUM_KATS; i ++) {                                    \
        uint_xlen_t rs1= sample_rng();                                      \
        uint_xlen_t rd = INTRINSIC_FUNCTION (rs1);                          \
        DICT_LINE_BEGIN(MNEMONIC);                                          \
        DICT_VAR(rd,rd);                                                    \
        DICT_VAR(rs1,rs1);                                                  \
        DICT_LINE_END(MNEMONIC);                                            \
    }                                                                       \
}


/*!
@brief Macro for creating input/output values for a 2-reg address instruction
       with an immediate.
@param INTRINSIC_FUNCTION - The C intrinsic function name mapping to MNEMONIC
@param MNEMONIC - The assembly instruction mnemonic for the instruction
@param IMM - A literal immediate value. You must only feed values valid for
        the instruction which will be accepted by binutils. Otherwise,
        compilation will fail.
*/
#define TEST_RD_RS1_IMM(INTRINSIC_FUNCTION,MNEMONIC, IMM) {                 \
    for(int i = 0; i < NUM_KATS; i ++) {                                    \
        uint_xlen_t rs1= sample_rng();                                      \
        uint_xlen_t rd = INTRINSIC_FUNCTION (rs1, IMM);                     \
        DICT_LINE_BEGIN(MNEMONIC);                                          \
        DICT_VAR(rd,rd);                                                    \
        DICT_VAR(rs1,rs1);                                                  \
        DICT_VAR(imm,IMM);                                                  \
        DICT_LINE_END(MNEMONIC);                                            \
    }                                                                       \
}

/*!
@brief Macro for creating input/output values for a 3-reg address instruction.
@param INTRINSIC_FUNCTION - The C intrinsic function name mapping to MNEMONIC
@param MNEMONIC - The assembly instruction mnemonic for the instruction
*/
#define TEST_RD_RS1_RS2(INTRINSIC_FUNCTION,MNEMONIC) {                      \
    for(int i = 0; i < NUM_KATS; i ++) {                                    \
        uint_xlen_t rs1= sample_rng();                                      \
        uint_xlen_t rs2= sample_rng();                                      \
        uint_xlen_t rd = INTRINSIC_FUNCTION (rs1, rs2);                     \
        DICT_LINE_BEGIN(MNEMONIC);                                          \
        DICT_VAR(rd,rd);                                                    \
        DICT_VAR(rs1,rs1);                                                  \
        DICT_VAR(rs2,rs2);                                                  \
        DICT_LINE_END(MNEMONIC);                                            \
    }                                                                       \
}


/*!
@brief Macro for creating input/output values for a 3-reg address instruction.
       with a small immediate.
@param INTRINSIC_FUNCTION - The C intrinsic function name mapping to MNEMONIC
@param MNEMONIC - The assembly instruction mnemonic for the instruction
@param IMM - A literal immediate value. You must only feed values valid for
        the instruction which will be accepted by binutils. Otherwise,
        compilation will fail.
*/
#define TEST_RD_RS1_RS2_IMM(INTRINSIC_FUNCTION,MNEMONIC,IMM) { \
    for(int i = 0; i < NUM_KATS; i ++) {                                    \
        uint_xlen_t rs1= sample_rng();                                      \
        uint_xlen_t rs2= sample_rng();                                      \
        uint_xlen_t rd = INTRINSIC_FUNCTION (rs1, rs2, IMM);                \
        DICT_LINE_BEGIN(MNEMONIC);                                          \
        DICT_VAR(rd,rd);                                                    \
        DICT_VAR(rs1,rs1);                                                  \
        DICT_VAR(rs2,rs2);                                                  \
        DICT_VAR(imm,IMM);                                                  \
        DICT_LINE_END(MNEMONIC);                                            \
    }                                                                       \
}


void kat_generate(
    uint_xlen_t prng_seed , //!< Initial value for the internal PRNG.
    void (*put_char)(char), //!< Put character function used for IO.
    int num_tests           //!< Number of tests per instruction to perform.
) {
    __rng_state = prng_seed;
    kat_put_char= put_char;
    NUM_KATS    = num_tests;
    
    kat_put_str("# -- begin kat generation -- #\n");
    kat_put_str("xlen = " STR(__riscv_xlen) "\n");

    kat_put_str("prng_seed = 0x");
    kat_puthex_xlen(prng_seed);
    kat_put_str("\n");
    
    kat_put_str("num_tests = 0x");
    kat_puthex_xlen(num_tests);
    kat_put_str("\n");

    kat_put_str("kat_results = [\n");

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
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0x0)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0x1)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0x2)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0x3)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0x4)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0x5)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0x6)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0x7)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0x8)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0x9)
        TEST_RD_RS1_IMM(_aes64ks1i, aes64ks1i, 0xA)

        TEST_RD_RS1_RS2(_aes64ks2 , aes64ks2      )
        TEST_RD_RS1(_aes64im  , aes64im       )
        TEST_RD_RS1_RS2(_aes64es  , aes64es       )
        TEST_RD_RS1_RS2(_aes64esm , aes64esm      )
        TEST_RD_RS1_RS2(_aes64ds  , aes64ds       )
        TEST_RD_RS1_RS2(_aes64dsm , aes64dsm      )
    #endif
    
    kat_put_str("\n]\n");
    kat_put_str("# -- end kat generation -- #\n");

}
