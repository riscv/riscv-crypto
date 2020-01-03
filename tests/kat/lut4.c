
/* Known answer tests for the LUT4 instruction. Used to check that the
    simulator / thing operating it implements it correctly with some
    degree of confidence.
*/

#include <stdio.h>
#include <stdint.h>


int test_lut4() {

    uint32_t rs1 = 0x01234567;
    uint32_t rs2 = 0x89ABCDEF;

    uint32_t in  = 0x10234567;
    uint32_t rd  = in;

    // TEST 1

    uint32_t expect = 0xEFDCBA98;

    __asm__ volatile("lut4 %0, %1, %2" : "+r"(rd): "r"(rs1), "r"(rs2));

    if(rd != expect) {
        printf("\nFail T1: RS1=%X, RS2=%X, In=%X, rd=%X, expected=%X\n",
            rs1,rs2,in,rd, expect);
        return 1;
    }


    // TEST 2

    in = 0x89ABCDEF;
    rd = in;

    __asm__("lut4 %0, %1, %2" : "+r"(rd): "r"(rs1), "r"(rs2));

    if(rd != 0x76543210) {
        printf("\nFail T2: RS1=%X, RS2=%X, In=%X, out=%X\n",
            rs1,rs2,in,rd);
        return 2;
    }

    // END of tests.

    return 0;

}

int main (int argc, char ** argv) {

    printf("Running lut4 KAT... ");

    int fail = test_lut4();

    if(fail == 0)  {

        printf("Test passed.\n");

        return 0;

    } else {
        
        printf("Test %d Failed.\n", fail);

        return 1;
    }

}
