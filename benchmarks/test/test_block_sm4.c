
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

uint8_t cts [1][16] = {
    {0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
     0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46},
};

int main(int argc, char ** argv) {
    
    printf("import sys, binascii, Crypto.Cipher.AES as AES\n");
    printf("benchmark_name = \"" STR(TEST_NAME)"\"\n");

    for(int test = 0; test < 1; test ++) {

        uint8_t * pt = pts[test];
        uint8_t * mk = mks[test];
        uint8_t   ct [16];
        uint8_t   fi [16];

        uint32_t  erk[32];
        uint32_t  drk[32];

        sm4_key_schedule_enc(erk, mk);
        sm4_key_schedule_dec(drk, mk);
        sm4_block_enc_dec   (ct,pt,erk);
        sm4_block_enc_dec   (fi,ct,drk);
        
        printf("pt  = ");
        puthex_py(pt, 16);
        printf("\n");

        printf("mk  = ");
        puthex_py(mk, 16);
        printf("\n");
        
        printf("erk = ");
        puthex_py((uint8_t*)erk , 32*4);
        printf("\n");
        printf("drk = ");
        puthex_py((uint8_t*)drk , 32*4);
        printf("\n");
        
        printf("ct  = ");
        puthex_py(ct, 16);
        printf("\n");
        printf("fi  = ");
        puthex_py(fi, 16);
        printf("\n");

        int tr = 0;
        for(int i = 0; i < 16; i ++) {

            if(ct[i] != cts[test][i]) {
                tr |= 1; 
            }
            if(fi[i] != pt[i])        {
                tr |= 2;
            }

        }

        if(tr) {
            printf("print('"STR(TEST_NAME)"Test %d Failed with code: %d')\n", test, tr);
            printf("sys.exit(1)\n", test, tr);
            return tr;
        } else {
            printf("print('"STR(TEST_NAME)" Test %d passed.')\n", test);
        }
    }

    return 0;
}
