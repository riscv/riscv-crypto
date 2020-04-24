
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "riscvcrypto/share/test.h"
#include "riscvcrypto/share/util.h"

#include "riscvcrypto/sm4/api_sm4.h"

uint8_t pts [1][16]  = {
    {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10},
};

uint8_t mks [1][16] = {
    {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10},
};

int main(int argc, char ** argv) {
    
    printf("import sys, binascii, Crypto.Cipher.AES as AES\n");
    printf("benchmark_name = \"" STR(TEST_NAME)"\"\n");

    for(int test = 0; test < 1; test ++) {

        uint8_t * pt = pts[test];
        uint8_t * mk = mks[test];
        uint8_t   ct [16];

        uint32_t  rk [32];

        sm4_key_schedule_enc(rk, mk);
        
        printf("pt  = ");
        puthex_py(pt, 16);
        printf("\n");

        printf("mk  = ");
        puthex_py(mk, 16);
        printf("\n");
        
        printf("rk  = ");
        puthex_py((uint8_t*)rk , 32*4);
        printf("\n");

    }

}
