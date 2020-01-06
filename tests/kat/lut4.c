
/* Known answer tests for the LUT4 instruction. Used to check that the
 * simulator / thing operating it implements it correctly with some degree of
 * confidence.
*/

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

int test_lut4() {

    uint32_t rs1 = 0x01234567;
    uint32_t rs2 = 0x89ABCDEF;

    uint32_t in  = 0x10234567;
    uint32_t rd  = 0x10234567;

    // TEST 1

    __asm__ ("lut4 %0, %1, %2" : "+r"(rd): "r"(rs1), "r"(rs2));

    uint32_t expect = 0xEFDCBA98;
        
    printf("lut4: RS1=%lX, RS2=%lX, In=%lX, rd=%lX, expected=%lX\n",
        rs1,rs2,in,rd, expect);

    assert(rd == expect);


    // TEST 2

    in      = 0x89ABCDEF;
    expect  = 0x76543210;
    rd      = in;

    __asm__("lut4 %0, %1, %2" : "+r"(rd): "r"(rs1), "r"(rs2));
    
    printf("lut4: RS1=%lX, RS2=%lX, In=%lX, rd=%lX, expected=%lX\n",
        rs1,rs2,in,rd, expect);
    
    assert(rd == expect);

    // END of tests.

    return 0;

}

int main (int argc, char ** argv) {

    printf("Running lut4 KAT...\n");

    int fail = test_lut4();

    if(fail == 0)  {

        printf("Test passed.\n");

        return 0;

    } else {

        printf("Test %d Failed.\n", fail);

        return 1;
    }

}
