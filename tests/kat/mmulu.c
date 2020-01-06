
/* Known answer tests for the MMULU instruction. Used to check that the
 * simulator / thing operating it implements it correctly with some degree of
 * confidence.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

//
// TODO: This test *assumes* we are running on an RV32 target.
//       It will need fixing when an RV64 toolchain comes along.

unsigned long int __attribute__ ((noinline))
__mmulu(unsigned int rs1, unsigned int rs2, unsigned int rs3) {
    uint32_t rd2, rd1;
    __asm__ ("mmulu (%0,%1), %2, %3, %4" 
        : "=r"(rd2), "=r"(rd1)
        : "r"(rs1), "r"(rs2), "r"(rs3)
    );
    uint64_t result = rd2;
    return (result << 32) | rd1;
}

int test_mmulu() {
    
    unsigned int  rs1, rs2, rs3;
    unsigned long result, expect;

    // Constant seed for repeatability...
    srand(1);

    for(int i = 0; i < 10; i ++) {
        
        rs1 = rand();
        rs2 = rand();
        rs3 = rand();

        result = __mmulu(rs1,rs2,rs3);

        expect = (((uint64_t)rs1) * rs2) + rs3;
        
        // TODO: Why does printf ignore the "l" in "%lx" ?
        printf("mmulu (%x * %x) + %x, got %lx, expect, %lx\n",
            rs1, rs2, rs3, result, expect);

        assert(result == expect);
    }

    return 0;

}

int main (int argc, char ** argv) {

    printf("Running mmulu KAT...\n");

    int fail = test_mmulu();

    if(fail == 0)  {

        printf("Test passed.\n");

        return 0;

    } else {

        printf("Test %d Failed.\n", fail);

        return 1;
    }

}
