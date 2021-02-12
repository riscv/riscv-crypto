
#include <stdlib.h>
#include <string.h>

#include "riscvcrypto/share/test.h"
#include "riscvcrypto/sm3/api_sm3.h"

int main(int argc, char **argv) {

  printf("import sys, binascii\n");
  printf("benchmark_name = \"" STR(TEST_NAME) "\"\n");

  #define TEST_COUNT 5
  size_t message_lengths[TEST_COUNT] = {
      0,
      3,
      60,
      72,
      5978,
  };
  uint8_t *messages[TEST_COUNT] = {
      (uint8_t *)"",
      (uint8_t *)"abc",
      (uint8_t *)"LCSqGlpVqORfakSUVcXWDOUjQeUWEeAMqmMEL6F85gM3faBCepnFm7bWTFD4",
      (uint8_t *)"HHr8sy98NzzqM4xwmhXa55EMubcSHc8wdFxsMhDCLx5EiknvyA9S9qKu5Q4iW"
                 "vxEHnOpLTuK",
      (uint8_t *)"OBSDlpLxLNM3bgCZiC5vqCabShTXnwTfeJRnIbOiWojmYu9Ves7dFJvGWerCg"
                 "8IrLuN1nHkuY9xOJhAgaMTU0kkIHi3UlsNLw74EzjmZ3Ce1tbWmxsrljOsU4r"
                 "eI57kLq55SGvPRgbl6xQwhScZsN7aEGV1f8PVW41aCPr453fKPPnYZSbI2e5A"
                 "er5jFM0MyOT219BwqzEKalHC6pElwlJE7DFJZEGiUpl9ctbAKQUxuaYUFfEzR"
                 "aLoI54PsQT8U5GKOTMVgQpv0xErFGgeqOOzZ9hp7EAILv8JjlZZCNbKChiAZd"
                 "XQnAvf2Uz5wyeJKhg95YXNy6hW1vRZgEIoLd3FMezyixW3AAkUTLpeTiLnDgy"
                 "YeaGkZqDF8GhHt3ZoqeKCRPZ36bgMr9Ny7QrDFDEzrgp2radGUUrYGKpwpr5s"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "OGuufVf6Ml1fRSD3jytNy7aLcHNm2wmf9IbWztOYwfrz56omtmYdTl0dasdas"
                 "OBSDlpLxLNM3bgCZiC5vqCabShTXnwTfeJRnIbOiWojmYu9Ves7dFJvGWerCg"
                 "8IrLuN1nHkuY9xOJhAgaMTU0kkIHi3UlsNLw74EzjmZ3Ce1tbWmxsrljOsU4r"
                 "eI57kLq55SGvPRgbl6xQwhScZsN7aEGV1f8PVW41aCPr453fKPPnYZSbI2e5A"
                 "er5jFM0MyOT219BwqzEKalHC6pElwlJE7DFJZEGiUpl9ctbAKQUxuaYUFfEzR"
                 "aLoI54PsQT8U5GKOTMVgQpv0xErFGgeqOOzZ9hp7EAILv8JjlZZCNbKChiAZd"
                 "XQnAvf2Uz5wyeJKhg95YXNy6hW1vRZgEIoLd3FMezyixW3AAkUTLpeTiLnDgy"
                 "YeaGkZqDF8GhHt3ZoqeKCRPZ36bgMr9Ny7QrDFDEzrgp2radGUUrYGKpwpr5s"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "OGuufVf6Ml1fRSD3jytNy7aLcHNm2wmf9IbWztOYwfrz56omtmYdTl0dasdas"
                 "OBSDlpLxLNM3bgCZiC5vqCabShTXnwTfeJRnIbOiWojmYu9Ves7dFJvGWerCg"
                 "8IrLuN1nHkuY9xOJhAgaMTU0kkIHi3UlsNLw74EzjmZ3Ce1tbWmxsrljOsU4r"
                 "eI57kLq55SGvPRgbl6xQwhScZsN7aEGV1f8PVW41aCPr453fKPPnYZSbI2e5A"
                 "er5jFM0MyOT219BwqzEKalHC6pElwlJE7DFJZEGiUpl9ctbAKQUxuaYUFfEzR"
                 "aLoI54PsQT8U5GKOTMVgQpv0xErFGgeqOOzZ9hp7EAILv8JjlZZCNbKChiAZd"
                 "XQnAvf2Uz5wyeJKhg95YXNy6hW1vRZgEIoLd3FMezyixW3AAkUTLpeTiLnDgy"
                 "YeaGkZqDF8GhHt3ZoqeKCRPZ36bgMr9Ny7QrDFDEzrgp2radGUUrYGKpwpr5s"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "OGuufVf6Ml1fRSD3jytNy7aLcHNm2wmf9IbWztOYwfrz56omtmYdTl0dasdas"
                 "OBSDlpLxLNM3bgCZiC5vqCabShTXnwTfeJRnIbOiWojmYu9Ves7dFJvGWerCg"
                 "8IrLuN1nHkuY9xOJhAgaMTU0kkIHi3UlsNLw74EzjmZ3Ce1tbWmxsrljOsU4r"
                 "eI57kLq55SGvPRgbl6xQwhScZsN7aEGV1f8PVW41aCPr453fKPPnYZSbI2e5A"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "OGuufVf6Ml1fRSD3jytNy7aLcHNm2wmf9IbWztOYwfrz56omtmYdTl0dasdas"
                 "OBSDlpLxLNM3bgCZiC5vqCabShTXnwTfeJRnIbOiWojmYu9Ves7dFJvGWerCg"
                 "8IrLuN1nHkuY9xOJhAgaMTU0kkIHi3UlsNLw74EzjmZ3Ce1tbWmxsrljOsU4r"
                 "eI57kLq55SGvPRgbl6xQwhScZsN7aEGV1f8PVW41aCPr453fKPPnYZSbI2e5A"
                 "er5jFM0MyOT219BwqzEKalHC6pElwlJE7DFJZEGiUpl9ctbAKQUxuaYUFfEzR"
                 "aLoI54PsQT8U5GKOTMVgQpv0xErFGgeqOOzZ9hp7EAILv8JjlZZCNbKChiAZd"
                 "XQnAvf2Uz5wyeJKhg95YXNy6hW1vRZgEIoLd3FMezyixW3AAkUTLpeTiLnDgy"
                 "YeaGkZqDF8GhHt3ZoqeKCRPZ36bgMr9Ny7QrDFDEzrgp2radGUUrYGKpwpr5s"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "OGuufVf6Ml1fRSD3jytNy7aLcHNm2wmf9IbWztOYwfrz56omtmYdTl0dasdas"
                 "OBSDlpLxLNM3bgCZiC5vqCabShTXnwTfeJRnIbOiWojmYu9Ves7dFJvGWerCg"
                 "8IrLuN1nHkuY9xOJhAgaMTU0kkIHi3UlsNLw74EzjmZ3Ce1tbWmxsrljOsU4r"
                 "eI57kLq55SGvPRgbl6xQwhScZsN7aEGV1f8PVW41aCPr453fKPPnYZSbI2e5A"
                 "er5jFM0MyOT219BwqzEKalHC6pElwlJE7DFJZEGiUpl9ctbAKQUxuaYUFfEzR"
                 "aLoI54PsQT8U5GKOTMVgQpv0xErFGgeqOOzZ9hp7EAILv8JjlZZCNbKChiAZd"
                 "XQnAvf2Uz5wyeJKhg95YXNy6hW1vRZgEIoLd3FMezyixW3AAkUTLpeTiLnDgy"
                 "YeaGkZqDF8GhHt3ZoqeKCRPZ36bgMr9Ny7QrDFDEzrgp2radGUUrYGKpwpr5s"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "er5jFM0MyOT219BwqzEKalHC6pElwlJE7DFJZEGiUpl9ctbAKQUxuaYUFfEzR"
                 "aLoI54PsQT8U5GKOTMVgQpv0xErFGgeqOOzZ9hp7EAILv8JjlZZCNbKChiAZd"
                 "XQnAvf2Uz5wyeJKhg95YXNy6hW1vRZgEIoLd3FMezyixW3AAkUTLpeTiLnDgy"
                 "YeaGkZqDF8GhHt3ZoqeKCRPZ36bgMr9Ny7QrDFDEzrgp2radGUUrYGKpwpr5s"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "OGuufVf6Ml1fRSD3jytNy7aLcHNm2wmf9IbWztOYwfrz56omtmYdTl0dasdas"
                 "OBSDlpLxLNM3bgCZiC5vqCabShTXnwTfeJRnIbOiWojmYu9Ves7dFJvGWerCg"
                 "8IrLuN1nHkuY9xOJhAgaMTU0kkIHi3UlsNLw74EzjmZ3Ce1tbWmxsrljOsU4r"
                 "eI57kLq55SGvPRgbl6xQwhScZsN7aEGV1f8PVW41aCPr453fKPPnYZSbI2e5A"
                 "er5jFM0MyOT219BwqzEKalHC6pElwlJE7DFJZEGiUpl9ctbAKQUxuaYUFfEzR"
                 "aLoI54PsQT8U5GKOTMVgQpv0xErFGgeqOOzZ9hp7EAILv8JjlZZCNbKChiAZd"
                 "XQnAvf2Uz5wyeJKhg95YXNy6hW1vRZgEIoLd3FMezyixW3AAkUTLpeTiLnDgy"
                 "YeaGkZqDF8GhHt3ZoqeKCRPZ36bgMr9Ny7QrDFDEzrgp2radGUUrYGKpwpr5s"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "OGuufVf6Ml1fRSD3jytNy7aLcHNm2wmf9IbWztOYwfrz56omtmYdTl0dasdas"
                 "OBSDlpLxLNM3bgCZiC5vqCabShTXnwTfeJRnIbOiWojmYu9Ves7dFJvGWerCg"
                 "8IrLuN1nHkuY9xOJhAgaMTU0kkIHi3UlsNLw74EzjmZ3Ce1tbWmxsrljOsU4r"
                 "eI57kLq55SGvPRgbl6xQwhScZsN7aEGV1f8PVW41aCPr453fKPPnYZSbI2e5A"
                 "er5jFM0MyOT219BwqzEKalHC6pElwlJE7DFJZEGiUpl9ctbAKQUxuaYUFfEzR"
                 "aLoI54PsQT8U5GKOTMVgQpv0xErFGgeqOOzZ9hp7EAILv8JjlZZCNbKChiAZd"
                 "XQnAvf2Uz5wyeJKhg95YXNy6hW1vRZgEIoLd3FMezyixW3AAkUTLpeTiLnDgy"
                 "YeaGkZqDF8GhHt3ZoqeKCRPZ36bgMr9Ny7QrDFDEzrgp2radGUUrYGKpwpr5s"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "OGuufVf6Ml1fRSD3jytNy7aLcHNm2wmf9IbWztOYwfrz56omtmYdTl0dasdas"
                 "OBSDlpLxLNM3bgCZiC5vqCabShTXnwTfeJRnIbOiWojmYu9Ves7dFJvGWerCg"
                 "8IrLuN1nHkuY9xOJhAgaMTU0kkIHi3UlsNLw74EzjmZ3Ce1tbWmxsrljOsU4r"
                 "eI57kLq55SGvPRgbl6xQwhScZsN7aEGV1f8PVW41aCPr453fKPPnYZSbI2e5A"
                 "er5jFM0MyOT219BwqzEKalHC6pElwlJE7DFJZEGiUpl9ctbAKQUxuaYUFfEzR"
                 "aLoI54PsQT8U5GKOTMVgQpv0xErFGgeqOOzZ9hp7EAILv8JjlZZCNbKChiAZd"
                 "XQnAvf2Uz5wyeJKhg95YXNy6hW1vRZgEIoLd3FMezyixW3AAkUTLpeTiLnDgy"
                 "YeaGkZqDF8GhHt3ZoqeKCRPZ36bgMr9Ny7QrDFDEzrgp2radGUUrYGKpwpr5s"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "OGuufVf6Ml1fRSD3jytNy7aLcHNm2wmf9IbWztOYwfrz56omtmYdTl0dasdas"
                 "OBSDlpLxLNM3bgCZiC5vqCabShTXnwTfeJRnIbOiWojmYu9Ves7dFJvGWerCg"
                 "8IrLuN1nHkuY9xOJhAgaMTU0kkIHi3UlsNLw74EzjmZ3Ce1tbWmxsrljOsU4r"
                 "eI57kLq55SGvPRgbl6xQwhScZsN7aEGV1f8PVW41aCPr453fKPPnYZSbI2e5A"
                 "er5jFM0MyOT219BwqzEKalHC6pElwlJE7DFJZEGiUpl9ctbAKQUxuaYUFfEzR"
                 "aLoI54PsQT8U5GKOTMVgQpv0xErFGgeqOOzZ9hp7EAILv8JjlZZCNbKChiAZd"
                 "XQnAvf2Uz5wyeJKhg95YXNy6hW1vRZgEIoLd3FMezyixW3AAkUTLpeTiLnDgy"
                 "YeaGkZqDF8GhHt3ZoqeKCRPZ36bgMr9Ny7QrDFDEzrgp2radGUUrYGKpwpr5s"
                 "moAqGIMHGckuaMNu1VCjhwZpPUNdt8ETxmIbODsDxgTGNL5P1NbfE6VvsFBWT"
                 "OGuufVf6Ml1fRSD3jytNy7aLcHNm2wmf9IbWztOYwfrz56omtmYdTl0dsadas",
  };
  uint8_t expected_digests[TEST_COUNT][32] = {
      {0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F, 0x8E, 0x61, 0x19,
       0x48, 0x31, 0xE8, 0x1A, 0x8F, 0x22, 0xBE, 0xC8, 0xC7, 0x28, 0xFE,
       0xFB, 0x74, 0x7E, 0xD0, 0x35, 0xEB, 0x50, 0x82, 0xAA, 0x2B},
      {0x66, 0xC7, 0xF0, 0xF4, 0x62, 0xEE, 0xED, 0xD9, 0xD1, 0xF2, 0xD4,
       0x6B, 0xDC, 0x10, 0xE4, 0xE2, 0x41, 0x67, 0xC4, 0x87, 0x5C, 0xF2,
       0xF7, 0xA2, 0x29, 0x7D, 0xA0, 0x2B, 0x8F, 0x4B, 0xA8, 0xE0},
      {0x44, 0x9E, 0x07, 0xB6, 0xA7, 0xCE, 0xAF, 0x7F, 0x1F, 0xAD, 0xD9,
       0x27, 0xAC, 0xF8, 0xA9, 0x50, 0x53, 0x9E, 0x29, 0x24, 0x73, 0xD4,
       0x6C, 0xFC, 0xD0, 0x04, 0xB9, 0xCD, 0xB6, 0x16, 0x6D, 0x64},
      {0x92, 0xA2, 0x58, 0x45, 0x27, 0x64, 0x32, 0x98, 0xF8, 0xE6, 0x65,
       0xCE, 0xE4, 0x25, 0x4C, 0xAF, 0x1D, 0xC0, 0xA4, 0xAF, 0xFA, 0x23,
       0x69, 0xED, 0x9F, 0xBA, 0x6E, 0xDF, 0x63, 0x69, 0xCE, 0x9B},
      {0x04, 0xA1, 0x68, 0x86, 0x3B, 0x4B, 0x3B, 0x17, 0x11, 0xB7, 0x60,
       0x9A, 0xEA, 0x16, 0xC3, 0xC0, 0xC2, 0x5A, 0x0A, 0xC1, 0xF4, 0x74,
       0xE1, 0x7F, 0x4F, 0x3C, 0xBE, 0xAD, 0xE6, 0x68, 0x1D, 0xE9},
  };

  for (int i = 0; i < TEST_COUNT; i++) {

    const uint64_t start_instrs = test_rdinstret();

    uint8_t actual_digest[32];
    sm3_hash(actual_digest, messages[i], message_lengths[i]);

    const uint64_t end_instrs = test_rdinstret();

    const uint64_t final_instrs = end_instrs - start_instrs;

    printf("#\n# test %d/%d\n", i, TEST_COUNT);

    printf("input_len       = %lu\n", (long unsigned int)message_lengths[i]);

    printf("input_data      = ");
    puthex_py(messages[i], message_lengths[i]);
    printf("\n");

    printf("actual_digest   = ");
    puthex_py(actual_digest, 32);
    printf("\n");

    printf("instr_count     = 0x");
    puthex64(final_instrs);
    printf("\n");

    printf("testnum         = %d\n", i);
    printf("ipb             = 0 if input_len == 0 else instr_count / "
           "input_len\n");

    printf("expected_digest = ");
    puthex_py(expected_digests[i], 32);
    printf("\n");

    printf("if( actual_digest  != expected_digest ):\n");
    printf("    print(\"Test %d failed.\")\n", i);
    printf(
        "    print( 'input     == %%s' %% ( binascii.b2a_hex( input_data ) ) )"
        "\n");
    printf("    print( 'actual_digest == %%s' %% ( binascii.b2a_hex( "
           "actual_digest ) ) )"
           "\n");
    printf("    print( '          != %%s' %% ( binascii.b2a_hex( "
           "expected_digest ) ) )"
           "\n");
    printf("    sys.exit(1)\n");
    printf("else:\n");
    printf(
        "    print(\"" STR(TEST_NAME) " Test %%d passed. "
                                      "%%d instrs / %%d bytes. IPB=%%f\" %% "
                                      "(testnum,instr_count,input_len,ipb))\n");
  }

  return 0;
}
