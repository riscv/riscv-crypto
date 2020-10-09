

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <kat_gen.h>

#if __riscv_xlen == 64
extern volatile uint64_t tohost;
#elif __riscv_xlen == 32
extern volatile uint32_t tohost;
#endif

/*!
@brief IO function underlying all output from the KAT test generator.
@details Everything is implemented this way to make the function
        extremely easy to replace with something SoC/Simulator specific.
*/
static void kat_put_char (
    char c
) {
    #if __riscv_xlen == 64
    uint64_t newval = 
        ((uint64_t)0x1UL << 56)|
        ((uint64_t)0x1UL << 48)|
        c            ;
    #elif __riscv_xlen == 32
    uint32_t newval = 
        ((uint32_t)0x1UL << 24)|
        ((uint32_t)0x1UL << 16)|
        c            ;
    #endif
    tohost = newval;
}

void finish() {
    tohost = 1;
}


int main(int argc, char ** argv) {

    uint_xlen_t prng_seed = 12345678;
    int         num_tests = 10;

    kat_put_char('\n');
    kat_generate(prng_seed, &kat_put_char, num_tests);
    finish();
}

