
#include <stdlib.h>
#include <string.h>

#include "riscvcrypto/share/test.h"
#include "riscvcrypto/share/util.h"

#include "riscvcrypto/aes/api_aes.h"

void test_aes_256(int num_tests) {

    // Start with known inputs from
    //  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core256.pdf
    uint8_t  key [AES_256_KEY_BYTES ] = {
        0x60,0x3D,0xEB,0x10,
        0x15,0xCA,0x71,0xBE,
        0x2B,0x73,0xAE,0xF0,
        0x85,0x7D,0x77,0x81,
        0x1F,0x35,0x2C,0x07,
        0x3B,0x61,0x08,0xD7,
        0x2D,0x98,0x10,0xA3,
        0x09,0x14,0xDF,0xF4
    };
    uint8_t  pt  [AES_BLOCK_BYTES   ] = {
        0x6B,0xC1,0xBE,0xE2,
        0x2E,0x40,0x9F,0x96,
        0xE9,0x3D,0x7E,0x11,
        0x73,0x93,0x17,0x2A,
    };
    uint32_t erk [AES_256_RK_WORDS  ]; //!< Roundkeys (encrypt)
    uint32_t drk [AES_256_RK_WORDS  ]; //!< Roundkeys (decrypt)
    uint8_t  ct  [AES_BLOCK_BYTES   ];
    uint8_t  pt2 [AES_BLOCK_BYTES   ];
    uint64_t start_instrs;

    for(int i = 0; i < num_tests; i ++) {

        for(int i = 0; i < AES_256_RK_WORDS; i ++) {
            erk[i] = 0;
            drk[i] = 0;
        }

        start_instrs = test_rdinstret();
        aes_256_enc_key_schedule(erk, key    );
        uint64_t kse_icount   = test_rdinstret() - start_instrs;

        start_instrs = test_rdinstret();
        aes_256_ecb_encrypt     (ct , pt, erk);
        uint64_t enc_icount   = test_rdinstret() - start_instrs;
        
        start_instrs        = test_rdinstret();
        aes_256_dec_key_schedule(drk, key    );
        uint64_t ksd_icount   = test_rdinstret() - start_instrs;
        
        start_instrs        = test_rdinstret();
        aes_256_ecb_decrypt     (pt2, ct, drk);
        uint64_t dec_icount = test_rdinstret() - start_instrs;
        
        printf("#\n# AES 256 test %d/%d\n",i , num_tests);

        printf("key=");puthex_py(key, AES_256_KEY_BYTES); printf("\n");
        printf("erk=");puthex_py((uint8_t*)erk,AES_256_RK_BYTES);printf("\n");
        printf("drk=");puthex_py((uint8_t*)drk,AES_256_RK_BYTES);printf("\n");
        printf("pt =");puthex_py(pt , AES_BLOCK_BYTES  ); printf("\n");
        printf("pt2=");puthex_py(pt2, AES_BLOCK_BYTES  ); printf("\n");
        printf("ct =");puthex_py(ct , AES_BLOCK_BYTES  ); printf("\n");

        printf("kse_icount = 0x"); puthex64(kse_icount); printf("\n");
        printf("ksd_icount = 0x"); puthex64(ksd_icount); printf("\n");
        printf("enc_icount = 0x"); puthex64(enc_icount); printf("\n");
        printf("dec_icount = 0x"); puthex64(dec_icount); printf("\n");

        printf("testnum         = %d\n",i);

        printf("ref_ct          = AES.new(key,AES.MODE_ECB).encrypt(pt    )\n");
        printf("ref_pt          = AES.new(key,AES.MODE_ECB).decrypt(ref_ct)\n");
        printf("if( ref_ct     != ct        ):\n");
        printf("    print(\"AES 256 Test %d encrypt failed.\")\n", i);
        printf("    print( 'key == %%s' %% ( binascii.b2a_hex( key    )))\n");
        printf("    print( 'rk  == %%s' %% ( binascii.b2a_hex(erk     )))\n");
        printf("    print( 'pt  == %%s' %% ( binascii.b2a_hex( pt     )))\n");
        printf("    print( 'ct  == %%s' %% ( binascii.b2a_hex( ct     )))\n");
        printf("    print( '    != %%s' %% ( binascii.b2a_hex( ref_ct )))\n");
        printf("    sys.exit(1)\n");
        printf("elif( ref_pt     != pt2       ):\n");
        printf("    print(\"AES 256 Test %d decrypt failed.\")\n", i);
        printf("    print( 'key == %%s' %% ( binascii.b2a_hex( key    )))\n");
        printf("    print( 'rk  == %%s' %% ( binascii.b2a_hex(drk     )))\n");
        printf("    print( 'ct  == %%s' %% ( binascii.b2a_hex( ct     )))\n");
        printf("    print( 'pt  == %%s' %% ( binascii.b2a_hex( pt2    )))\n");
        printf("    print( '    != %%s' %% ( binascii.b2a_hex( ref_pt )))\n");
        printf("    sys.exit(1)\n");
        printf("else:\n");
        printf("    sys.stdout.write(\""STR(TEST_NAME)" AES 256 Test passed. \")\n");
        printf("    sys.stdout.write(\"enc: %%d, \" %% (enc_icount))\n");
        printf("    sys.stdout.write(\"dec: %%d, \" %% (dec_icount))\n");
        printf("    sys.stdout.write(\"kse: %%d, \" %% (kse_icount))\n");
        printf("    sys.stdout.write(\"ksd: %%d, \" %% (ksd_icount))\n");
        printf("    print(\"\")\n");
        
        // New random inputs
        test_rdrandom(pt    , AES_BLOCK_BYTES   );
        test_rdrandom(key   , AES_256_KEY_BYTES );

    }

}


int main(int argc, char ** argv) {

    printf("import sys, binascii, Crypto.Cipher.AES as AES\n");
    printf("benchmark_name = \"" STR(TEST_NAME)"\"\n");

    test_aes_256(10);

    return 0;

}
