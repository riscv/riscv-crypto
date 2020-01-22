
#include <string.h>

#include "riscvcrypto/share/test.h"

#include "riscvcrypto/crypto_hash/sha512/api_sha512.h"

/*!
@brief KAT test function for SHA512
@details checks that we get the correct known answer for a given input.
*/
int sha512_kat() {

    char *     hash_input = "abc";
    char       hash_signature  [CRYPTO_HASH_SHA512_BYTES];
    unsigned long long  hash_input_len = strlen(hash_input);

    const char expected[] = {0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f};
    
    crypto_hash_sha512(
        (unsigned char*)hash_signature,
        (unsigned char*)hash_input    ,
        hash_input_len
    );

    if(strncmp(expected,hash_signature,CRYPTO_HASH_SHA512_BYTES) == 0) {
        
        return 0;

    } else {
        
        return 1;

    }

}

int main(int argc, char ** argv) {
    
    printf("Running SHA512 "STR(TEST_NAME)" KAT... ");

    if(sha512_kat()) {
        printf("[Fail]\n");
        return 1;
    } else {
        printf("[Pass]\n");
    }

    printf("Running SHA512 " STR(TEST_NAME) " benchmark...\n");

    unsigned char       hash_signature  [CRYPTO_HASH_SHA512_BYTES];
    unsigned char       hash_input      [TEST_HASH_INPUT_LENGTH  ];
    unsigned long long  hash_input_len = TEST_HASH_INPUT_LENGTH   ;

    printf("Reading %d random bytes as input...\n", TEST_HASH_INPUT_LENGTH);
    test_rdrandom(hash_input, TEST_HASH_INPUT_LENGTH);

    const uint64_t start_instrs   = test_rdinstret();

    crypto_hash_sha512(
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
    puthex(hash_signature, CRYPTO_HASH_SHA512_BYTES);
    printf("\n");

    printf("PERF: "STR(TEST_NAME) " instrs: 0x");
    puthex64(final_instrs); printf("\n");

    return 0;
}
