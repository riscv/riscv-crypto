

/*! @addtogroup test_utils
@{
*/

#include <stdlib.h>
#include <string.h>

#include "test.h"

//
// Misc IO
// ----------------------------------------------------------------------

void puthex64(uint64_t in) {
    for(int i = 0; i < 16; i += 1) {
        unsigned char x = (in >> (60-4*i)) & 0xF;
        printf("%x", x);
    }
}


void puthex(unsigned char * in, size_t len) {
    for(size_t i = 0; i < len ; i ++) {
        unsigned char c1 = (in[i] >> 4) & 0xF;
        unsigned char c2 = (in[i]     ) & 0xF;
        printf("%x%x",c1,c2);
    }
}


void puthex_py(unsigned char * in, size_t len){
    printf("binascii.a2b_hex(\"");
    puthex(in,len);
    printf("\")");
}


size_t test_rdrandom(unsigned char * dest, size_t len) {
    
    FILE * fh       = fopen("/dev/random", "rb");

    size_t result   = fread(dest, sizeof(unsigned char), len, fh);

    fclose(fh)      ;
    
    return result   ;

}

//
// Low level register access.
// ------------------------------------------------------------------

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


//!@}

