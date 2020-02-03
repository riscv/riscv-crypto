
#include <stdlib.h>
#include <string.h>

#include "riscvcrypto/share/test.h"
#include "riscvcrypto/share/util.h"

#include "riscvcrypto/crypto_block/aes/api_aes.h"


int main(int argc, char ** argv) {

    printf("import sys, binascii, Crypto.Cipher.AES as AES\n");
    printf("benchmark_name = \"" STR(TEST_NAME)"\"\n");

    const int num_tests = 10;

    // Start with known inputs from FIPS 197, Appendix B.
    uint8_t  key [AES_128_KEY_BYTES ] = {0x2b ,0x7e ,0x15 ,0x16 ,0x28 ,0xae ,0xd2 ,0xa6 ,0xab ,0xf7 ,0x15 ,0x88 ,0x09 ,0xcf ,0x4f ,0x3c};
    uint8_t  pt  [AES_BLOCK_BYTES   ] = {0x32 ,0x43 ,0xf6 ,0xa8 ,0x88 ,0x5a ,0x30 ,0x8d ,0x31 ,0x31 ,0x98 ,0xa2 ,0xe0 ,0x37 ,0x07 ,0x34};
    uint32_t erk [AES_128_RK_BYTES  ]; //!< Roundkeys (encrypt)
    uint32_t drk [AES_128_RK_BYTES  ]; //!< Roundkeys (decrypt)
    uint8_t  ct  [AES_BLOCK_BYTES   ];
    uint8_t  pt2 [AES_BLOCK_BYTES   ];
    uint64_t start_instrs;

    for(int i = 0; i < num_tests; i ++) {

        start_instrs = test_rdinstret();
        aes_128_enc_key_schedule(erk, key    );
        uint64_t kse_icount   = test_rdinstret() - start_instrs;

        start_instrs = test_rdinstret();
        aes_128_ecb_encrypt     (ct , pt, erk);
        uint64_t enc_icount   = test_rdinstret() - start_instrs;
        
        start_instrs = test_rdinstret();
        aes_128_dec_key_schedule(drk, key    );
        uint64_t ksd_icount   = test_rdinstret() - start_instrs;

        start_instrs = test_rdinstret();
        aes_128_ecb_decrypt     (pt2, ct, drk);
        uint64_t dec_icount   = test_rdinstret() - start_instrs;
        
        printf("#\n# test %d/%d\n",i , num_tests);

        printf("key             = ");
        puthex_py(key, AES_128_KEY_BYTES);
        printf("\n");
        
        printf("erk             = ");
        puthex_py((uint8_t*)erk , AES_128_RK_BYTES );
        printf("\n");
        
        printf("drk             = ");
        puthex_py((uint8_t*)drk , AES_128_RK_BYTES );
        printf("\n");

        printf("pt              = ");
        puthex_py(pt , AES_BLOCK_BYTES  );
        printf("\n");
        
        printf("pt2             = ");
        puthex_py(pt2, AES_BLOCK_BYTES  );
        printf("\n");

        printf("ct              = ");
        puthex_py(ct , AES_BLOCK_BYTES  );
        printf("\n");

        printf("kse_icount      = 0x"); puthex64(kse_icount); printf("\n");
        printf("ksd_icount      = 0x"); puthex64(ksd_icount); printf("\n");
        printf("enc_icount      = 0x"); puthex64(enc_icount); printf("\n");
        printf("dec_icount      = 0x"); puthex64(dec_icount); printf("\n");

        printf("testnum         = %d\n",i);

        printf("ref_ct          = AES.new(key).encrypt(pt    )\n");
        printf("ref_pt          = AES.new(key).decrypt(ref_ct)\n");
        printf("if( ref_ct     != ct        ):\n");
        printf("    print(\"Test %d encrypt failed.\")\n", i);
        printf("    print( 'key == %%s' %% ( binascii.b2a_hex( key    )))\n");
        printf("    print( 'rk  == %%s' %% ( binascii.b2a_hex(erk     )))\n");
        printf("    print( 'pt  == %%s' %% ( binascii.b2a_hex( pt     )))\n");
        printf("    print( 'ct  == %%s' %% ( binascii.b2a_hex( ct     )))\n");
        printf("    print( '    != %%s' %% ( binascii.b2a_hex( ref_ct )))\n");
        printf("    sys.exit(1)\n");
        printf("elif( ref_pt     != pt2       ):\n");
        printf("    print(\"Test %d decrypt failed.\")\n", i);
        printf("    print( 'key == %%s' %% ( binascii.b2a_hex( key    )))\n");
        printf("    print( 'rk  == %%s' %% ( binascii.b2a_hex(drk     )))\n");
        printf("    print( 'ct  == %%s' %% ( binascii.b2a_hex( ct     )))\n");
        printf("    print( 'pt  == %%s' %% ( binascii.b2a_hex( pt2    )))\n");
        printf("    print( '    != %%s' %% ( binascii.b2a_hex( ref_pt )))\n");
        printf("    sys.exit(1)\n");
        printf("else:\n");
        printf("    sys.stdout.write(\""STR(TEST_NAME)" Test passed.\")\n");
        printf("    sys.stdout.write(\"enc: %%d, \" %% (enc_icount))\n");
        printf("    sys.stdout.write(\"dec: %%d, \" %% (dec_icount))\n");
        printf("    sys.stdout.write(\"kse: %%d, \" %% (kse_icount))\n");
        printf("    sys.stdout.write(\"ksd: %%d, \" %% (ksd_icount))\n");
        printf("    print(\"\")\n");
        
        // New random inputs
        test_rdrandom(pt    , AES_BLOCK_BYTES   );
        test_rdrandom(key   , AES_128_KEY_BYTES );

    }

    return 0;

}
