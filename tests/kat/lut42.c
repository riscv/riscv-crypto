
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

int test_lut42() {

    uint32_t rs1 = 0x76543210; // indexes
    uint32_t rs2 = 0x01234567; // the lut

    uint32_t rd  ;

    // TEST 1

    __asm__ ("lut42 %0, %1, %2" : "=r"(rd): "r"(rs1), "r"(rs2));

    uint32_t expect = 0x01230123;
    
    printf("rs1   : "); putbin32(rs1    ); printf("\n");
    printf("rs2   : "); putbin32(rs2    ); printf("\n");
    printf("rd    : "); putbin32(rd     ); printf("\n");
    printf("expect: "); putbin32(expect ); printf("\n");
    printf("lut42: RS1=%lX, RS2=%lX, rd=%lX, expected=%lX\n",
        rs1,rs2,rd, expect);

    assert(rd == expect);

    return 0;

}

int main (int argc, char ** argv) {

    printf("Running lut42 KAT...\n");

    int fail = test_lut42();

    if(fail == 0)  {

        printf("Test passed.\n");

        return 0;

    } else {

        printf("Test %d Failed.\n", fail);

        return 1;
    }

}
