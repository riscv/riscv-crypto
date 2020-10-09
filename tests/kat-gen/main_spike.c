
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <kat_gen.h>

/*!
@brief IO function underlying all output from the KAT test generator.
@details Everything is implemented this way to make the function
        extremely easy to replace with something SoC/Simulator specific.
*/
static void kat_put_char (
    char c
) {
    printf("%c",c);
}


int main(int argc, char ** argv) {

    uint_xlen_t prng_seed;

    #if __riscv_xlen == 32
    prng_seed = 0x78ABCDEF;
    #elif __riscv_xlen == 64
    prng_seed = 0x34ABCDEF01234567UL;
    #else
    #error "Unsupported __riscv_xlen value. Expected 32 or 64"
    #endif

    if(argc == 2) {
        prng_seed = atoi(argv[1]);
    }

    kat_generate(prng_seed, &kat_put_char);
}
