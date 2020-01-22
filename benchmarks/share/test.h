
/*!
@defgroup test_utils Test Utils
@{
*/

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#ifndef __SHARE_TEST_H__

//! Length of test input for a hash function.
#define TEST_HASH_INPUT_LENGTH 1024

/*!
@brief Prints a 64-bit input as hex to stdout.
@details Prints in LITTLE ENDIAN mode.
@param in - The thing to print.
*/
void puthex64(uint64_t in) {
    for(int i = 0; i < 16; i += 1) {
        unsigned char x = (in >> (60-4*i)) & 0xF;
        printf("%x", x);
    }
}


/*!
@brief Read the `minstret` CSR register to get instructions retired.
*/
volatile uint64_t test_rdinstret() {
    uint64_t result = 0;

#if ( __riscv_xlen == 32 )

    uint32_t hi1,hi2,lo;

    do {
        asm volatile (
            "rdinstreth %0;"
            "rdinstret  %1;" 
            "rdinstreth %2;" 
            : "=r"(hi1), "=r"(lo), "=r"(hi2)
        );
    } while(hi1 != hi2);

    result = (((uint64_t)hi1) << 32) | lo;

#elif ( __riscv_xlen == 64 )
        
    asm volatile (
        "rdinstret  %0;" 
        : "=r"(result)
    );

#else
    #error "Unsupported RISC-V XLEN: __riscv_xlen, expected 32 or 64"
#endif

    return result;
}

/*!
@brief Read the `mcycle` CSR register to get cycles elapsed.
*/
volatile uint64_t test_rdcycle() {
    uint64_t result = 0;

#if ( __riscv_xlen == 32 )

    uint32_t hi1,hi2,lo;

    do {
        __asm__ volatile (
            "rdcycleh %0;"
            "rdcycle  %1;" 
            "rdcycleh %2;" 
            : "=r"(hi1), "=r"(lo), "=r"(hi2)
            : 
        );
    } while(hi1 != hi2);

    result = (((uint64_t)hi1) << 32) | lo;

#elif ( __riscv_xlen == 64 )
        
    __asm__ volatile (
        "rdcycle  %0;" 
        : "=r"(result)
        : 
    );

#else
    #error "Unsupported RISC-V XLEN: __riscv_xlen, expected 32 or 64"
#endif

    return result;
}

/*!
@brief Read the `mtime` CSR register to get *time* elapsed.
@note This may simply be identical to __rdcycle depending on the platform.
*/
volatile uint64_t test_rdtime() {
    uint64_t result = 0;

#if ( __riscv_xlen == 32 )

    uint32_t hi1,hi2,lo;

    do {
        __asm__ volatile (
            "rdtimeh %0;"
            "rdtime  %1;" 
            "rdtimeh %2;" 
            : "=r"(hi1), "=r"(lo), "=r"(hi2)
            : 
        );
    } while(hi1 != hi2);

    result = (((uint64_t)hi1) << 32) | lo;

#elif ( __riscv_xlen == 64 )
        
    __asm__ volatile (
        "rdtime  %0;" 
        : "=r"(result)
        : 
    );

#else
    #error "Unsupported RISC-V XLEN: __riscv_xlen, expected 32 or 64"
#endif

    return result;
}

/*!
@brief Read len random bytes into dest.
*/
size_t test_rdrandom(unsigned char * dest, size_t len) {
    
    FILE * fh       = fopen("/dev/random", "rb");

    size_t result   = fread(dest, sizeof(unsigned char), len, fh);

    fclose(fh)      ;
    
    return result   ;

}

#endif

//! @}
