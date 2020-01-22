
#include <string.h>

#include "riscvcrypto/share/test.h"

#include "riscvcrypto/crypto_hash/sha256/api_sha256.h"

/*!
@brief KAT test function for SHA256
@details checks that we get the correct known answer for a given input.
*/
int sha256_kat() {

    char *     hash_input = "abc";
    char       hash_signature  [CRYPTO_HASH_SHA256_BYTES];
    unsigned long long  hash_input_len = strlen(hash_input);

    const char expected[] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    
    crypto_hash_sha256(
        (unsigned char*)hash_signature,
        (unsigned char*)hash_input    ,
        hash_input_len
    );

    if(strncmp(expected,hash_signature,CRYPTO_HASH_SHA256_BYTES) == 0) {
        
        return 0;

    } else {
        
        return 1;

    }

}

int main(int argc, char ** argv) {
    
    printf("Running SHA256 "STR(TEST_NAME)" KAT... ");

    if(sha256_kat()) {
        printf("[Fail]\n");
        return 1;
    } else {
        printf("[Pass]\n");
    }

    printf("Running SHA256 "STR(TEST_NAME)" benchmark...\n");

    unsigned char       hash_signature  [CRYPTO_HASH_SHA256_BYTES];
    unsigned char       hash_input      [TEST_HASH_INPUT_LENGTH  ];
    unsigned long long  hash_input_len = TEST_HASH_INPUT_LENGTH   ;

    printf("Reading %d random bytes as input...\n", TEST_HASH_INPUT_LENGTH);
    test_rdrandom(hash_input, TEST_HASH_INPUT_LENGTH);

    const uint64_t start_instrs   = test_rdinstret();

    crypto_hash_sha256(
        hash_signature,
        hash_input    ,
        hash_input_len
    );
    
    const uint64_t end_instrs     = test_rdinstret();

    const uint64_t final_instrs   = end_instrs - start_instrs;

    printf("Input: ");
    puthex(hash_input,TEST_HASH_INPUT_LENGTH);
    printf("\n");
    printf("Signature: ");
    puthex(hash_signature, CRYPTO_HASH_SHA256_BYTES);
    printf("\n");

    printf("PERF: "STR(TEST_NAME) " instrs: 0x");
    puthex64(final_instrs); printf("\n");

    return 0;
}
