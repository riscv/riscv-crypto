
/* Known answer tests for the LUT4 instruction. Used to check that the
    simulator / thing operating it implements it correctly with some
    degree of confidence.
*/

#include <stdio.h>


int test_lut4() {

    uint32_t rs1 = 0x01234567;
    uint32_t rs2 = 0x89ABCDEF;

    uint32_t rd  = 0x01234567;

    // TEST 1

    __asm__("lut4 %0, %1, %2" : "+r"(rd): "r"(rs1), "r"(rs2));

    if(rd != 0xFEDCBA98) {
        return 1;
    }


    // TEST 2

    rd = 0x89ABCDEF;

    __asm__("lut4 %0, %1, %2" : "+r"(rd): "r"(rs1), "r"(rs2));

    if(rd != 0x76543210) {
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
