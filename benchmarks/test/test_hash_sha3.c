
#include "riscvcrypto/share/test.h"
#include "riscvcrypto/share/util.h"

#include "riscvcrypto/crypto_hash/sha3/fips202.h"

/*!
@brief KAT test function for SHA3
@details checks that we get the correct known answer for a given input.
*/
int sha3_kat() {
    
    char *     hash_input = "abc";
    char       hash_signature  [CRYPTO_HASH_SHA3_512_OUTPUT_LENGTH];
    unsigned long long  hash_input_len = strlen(hash_input);

    const char expected[] = {0xb7,0x51,0x85,0x0b,0x1a,0x57,0x16,0x8a,0x56,0x93,0xcd,0x92,0x4b,0x6b,0x09,0x6e,0x08,0xf6,0x21,0x82,0x74,0x44,0xf7,0x0d,0x88,0x4f,0x5d,0x02,0x40,0xd2,0x71,0x2e,0x10,0xe1,0x16,0xe9,0x19,0x2a,0xf3,0xc9,0x1a,0x7e,0xc5,0x76,0x47,0xe3,0x93,0x40,0x57,0x34,0x0b,0x4c,0xf4,0x08,0xd5,0xa5,0x65,0x92,0xf8,0x27,0x4e,0xec,0x53,0xf0};
    
    FIPS202_SHA3_512(
        (unsigned char*)hash_input      ,
        hash_input_len                  ,
        (unsigned char*)hash_signature
    );

    if(strncmp(expected,hash_signature,CRYPTO_HASH_SHA3_512_OUTPUT_LENGTH) == 0) {
        
        return 0;

    } else {
        
        return 1;

    }
}


int main(int argc, char ** argv) {

    printf("Running SHA3"STR(TEST_NAME)" KAT... ");

    if(sha3_kat()) {
        printf("[Fail]\n");
        return 1;
    } else {
        printf("[Pass]\n");
    }

    printf("Running SHA3 " STR(TEST_NAME) " benchmark...\n");

    unsigned char       hash_input      [TEST_HASH_INPUT_LENGTH  ];
    unsigned long long  hash_input_len = TEST_HASH_INPUT_LENGTH   ;
    unsigned char       hash_signature  [CRYPTO_HASH_SHA3_512_OUTPUT_LENGTH];

    printf("Reading %d random bytes as input...\n", TEST_HASH_INPUT_LENGTH);
    test_rdrandom(hash_input, TEST_HASH_INPUT_LENGTH);

    const uint64_t start_instrs   = test_rdinstret();

    FIPS202_SHA3_512(
        hash_input    ,
        hash_input_len,
        hash_signature 
    );
    
    const uint64_t end_instrs     = test_rdinstret();

    const uint64_t final_instrs   = end_instrs - start_instrs;


    printf("PERF: "STR(TEST_NAME) " instrs: 0x");
    puthex64(final_instrs); printf("\n");

    return 0;
}
