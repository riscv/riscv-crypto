
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
    int         num_tests;

    if(argc == 3) {
        prng_seed = atoi(argv[1]);
        num_tests = atoi(argv[2]);
        kat_generate(prng_seed, &kat_put_char, num_tests);
        return 0;
    } else {
        printf("Usage: %s <SEED> <NUM TESTS>\n", argv[0]);
        return 1;
    }
}
