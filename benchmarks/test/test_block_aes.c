
#include <stdlib.h>
#include <string.h>

#include "riscvcrypto/share/test.h"
#include "riscvcrypto/share/util.h"

#include "riscvcrypto/crypto_block/aes/api_aes.h"


int main(int argc, char ** argv) {

    printf("import sys, binascii, Crypto.Cipher.AES as AES\n");
    printf("benchmark_name = \"" STR(TEST_NAME)"\"\n");

    const int num_tests = 10;
        
    unsigned long long   pt_len = AES_BLOCK_BYTES;
    unsigned char        key     [AES_128_KEY_BYTES ];
    unsigned char        rk      [AES_128_RK_BYTES  ];
    unsigned char        pt      [AES_BLOCK_BYTES   ];
    unsigned char        ct      [AES_BLOCK_BYTES   ];

    for(int i = 0; i < num_tests; i ++) {

        test_rdrandom(pt    , AES_BLOCK_BYTES   );
        test_rdrandom(key   , AES_128_KEY_BYTES );

        const uint64_t start_instrs   = test_rdinstret();

        aes_128_key_schedule(rk, key    );
        aes_128_ecb_encrypt (ct, pt , rk);
        
        const uint64_t end_instrs     = test_rdinstret();

        const uint64_t final_instrs   = end_instrs - start_instrs;

        printf("#\n# test %d/%d\n",i , num_tests);

        printf("key             = ");
        puthex_py(key, AES_128_KEY_BYTES);
        printf("\n");
        
        printf("rk              = ");
        puthex_py(rk , AES_128_RK_BYTES );
        printf("\n");

        printf("pt              = ");
        puthex_py(pt , AES_BLOCK_BYTES  );
        printf("\n");

        printf("ct              = ");
        puthex_py(ct , AES_BLOCK_BYTES  );
        printf("\n");

        printf("instr_count     = 0x");
        puthex64(final_instrs);
        printf("\n");

        printf("ref_ct          = AES.new(key).encrypt(pt)\n");
        printf("if( ref_ct     != ct        ):\n");
        printf("    print(\"Test %d failed.\")\n", i);
        printf("    print( 'key == %%s' %% ( binascii.b2a_hex( key    )))\n");
        printf("    print( 'rk  == %%s' %% ( binascii.b2a_hex( rk     )))\n");
        printf("    print( 'pt  == %%s' %% ( binascii.b2a_hex( pt     )))\n");
        printf("    print( 'ct  == %%s' %% ( binascii.b2a_hex( ct     )))\n");
        printf("    print( '    != %%s' %% ( binascii.b2a_hex( ref_ct )))\n");
        printf("    sys.exit(1)\n");
        printf("else:\n");
        printf("    print(\""STR(TEST_NAME)" Test %d passed.\")\n", i);

    }

    return 0;

}
