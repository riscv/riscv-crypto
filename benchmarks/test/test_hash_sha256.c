
#include "riscvcrypto/share/test.h"

#include "riscvcrypto/crypto_hash/sha256/api_sha256.h"

int main(int argc, char ** argv) {

    printf("Running SHA2 benchmark...\n");

    unsigned char       hash_signature  [CRYPTO_HASH_SHA256_BYTES];
    unsigned char       hash_input      [TEST_HASH_INPUT_LENGTH  ];
    unsigned long long  hash_input_len = TEST_HASH_INPUT_LENGTH   ;

    printf("Reading %d random bytes as input...\n", TEST_HASH_INPUT_LENGTH);
    test_rdrandom(hash_input, TEST_HASH_INPUT_LENGTH);

    const uint64_t start_instrs   = test_rdinstret();
    const uint64_t start_cycles   = test_rdcycle  ();

    crypto_hash_sha256(
        hash_signature,
        hash_input    ,
        hash_input_len
    );
    
    const uint64_t end_instrs     = test_rdinstret();
    const uint64_t end_cycles     = test_rdcycle  ();

    const uint64_t final_instrs   = end_instrs - start_instrs;
    const uint64_t final_cycles   = end_cycles - start_cycles;

    printf("SHA2:\n");
    printf("- instrs: 0x"); puthex64(final_instrs); printf("\n");
    printf("- cycles: 0x"); puthex64(final_cycles); printf("\n");

    return 0;
}
