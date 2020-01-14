
/* Known answer tests for the LUT42 instruction. Used to check that the
 * simulator / thing operating it implements it correctly with some degree of
 * confidence.
*/

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

void putbin32(uint32_t in) {
    for(int i = 0; i < 32; i ++) {
        printf("%lu", (in >> (31-i)) & 0x1);
    }
}

int test_lut4hi() {

    uint32_t rs1 = 0x76543210; // indexes
    uint32_t rs2 = 0x01234567; // the lut

    uint32_t rd , expect;

    // TEST 1
    

    __asm__ ("lut4hi %0, %1, %2" : "=r"(rd): "r"(rs1), "r"(rs2));

    expect = 0x00000000;
    
    printf("rs1   : "); putbin32(rs1    ); printf("\n");
    printf("rs2   : "); putbin32(rs2    ); printf("\n");
    printf("rd    : "); putbin32(rd     ); printf("\n");
    printf("expect: "); putbin32(expect ); printf("\n");
    printf("lut4hi: RS1=%lX, RS2=%lX, rd=%lX, expected=%lX\n",
        rs1,rs2,rd, expect);

    assert(rd == expect);
    
    // TEST 2

    rs1 = 0x89ABCDEF;

    __asm__ ("lut4hi %0, %1, %2" : "=r"(rd): "r"(rs1), "r"(rs2));

    expect = 0x76543210;
    
    printf("rs1   : "); putbin32(rs1    ); printf("\n");
    printf("rs2   : "); putbin32(rs2    ); printf("\n");
    printf("rd    : "); putbin32(rd     ); printf("\n");
    printf("expect: "); putbin32(expect ); printf("\n");
    printf("lut4hi:RS1=%lX, RS2=%lX, rd=%lX, expected=%lX\n",
        rs1,rs2,rd, expect);

    assert(rd == expect);

    return 0;

}

int main (int argc, char ** argv) {

    printf("Running lut4hi KAT...\n");

    int fail = test_lut4hi();

    if(fail == 0)  {

        printf("Test passed.\n");

        return 0;

    } else {

        printf("Test %d Failed.\n", fail);

        return 1;
    }

}
