
/*
 * Some demonstrations of using the Bitmanip permutation instructions
 * to perform useful cryptographic operations.
 */


#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "riscvcrypto/share/test.h"
#include "riscvcrypto/share/util.h"

#include "riscvcrypto/permutation/permutation.h"

// Show how we can implement the Prince Block Cipher sbox using xperm.n
void demo_prince_sbox() {
    uint64_t sbox   = 0x4d5e087619ca23fb;
    uint64_t input  = 0xFEDCBA9876543210;
    uint64_t output = sbox_4bit(sbox, input);

    printf("# Prince SBox Demo\n");
    printf("prince_sbox    = %#018"PRIx64"\n", sbox     );
    printf("prince_input   = %#018"PRIx64"\n", input    );
    printf("prince_output  = %#018"PRIx64"\n", output   );
    printf("if(prince_output != prince_sbox):\n");
    printf("    exit(1)\n");
}

int main(int argc, char ** argv) {

    demo_prince_sbox();

    return 0;

}
