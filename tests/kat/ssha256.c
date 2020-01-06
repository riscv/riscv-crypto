
/* Known answer tests for the ssha256 instructions. Used to check that the
    simulator / thing operating it implements it correctly with some
    degree of confidence.
*/

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#define ROR32(x, y) ((x >> y) | (x << (-y & 31)))
#define LSR32(x, y)  (x >> y)

int test_ssha256() {

    uint32_t rs1        = 0xa1b2c3d4;

    uint32_t expected_s0= ROR32(rs1, 7) ^ ROR32(rs1,18) ^ LSR32(rs1, 3);
    uint32_t expected_s1= ROR32(rs1,17) ^ ROR32(rs1,19) ^ LSR32(rs1,10);
    uint32_t expected_s2= ROR32(rs1, 2) ^ ROR32(rs1,13) ^ ROR32(rs1,22);
    uint32_t expected_s3= ROR32(rs1, 6) ^ ROR32(rs1,11) ^ ROR32(rs1,25);

    uint32_t rd_s0      = 0;
    uint32_t rd_s1      = 0;
    uint32_t rd_s2      = 0;
    uint32_t rd_s3      = 0;
    
    __asm__("ssha256.s0 %0, %1" : "=r"(rd_s0): "r"(rs1));
    __asm__("ssha256.s1 %0, %1" : "=r"(rd_s1): "r"(rs1));
    __asm__("ssha256.s2 %0, %1" : "=r"(rd_s2): "r"(rs1));
    __asm__("ssha256.s3 %0, %1" : "=r"(rd_s3): "r"(rs1));

    printf("ssha256.s0: RS1=%X Expected %X, got %X\n",rs1,expected_s0,rd_s0);
    assert(expected_s0 == rd_s0);
    
    printf("ssha256.s1: RS1=%X Expected %X, got %X\n",rs1,expected_s1,rd_s1);
    assert(expected_s1 == rd_s1);
    
    printf("ssha256.s2: RS1=%X Expected %X, got %X\n",rs1,expected_s2,rd_s2);
    assert(expected_s2 == rd_s2);

    printf("ssha256.s3: RS1=%X Expected %X, got %X\n",rs1,expected_s3,rd_s3);
    assert(expected_s3 == rd_s3);

    return 0;

}


int main (int argc, char ** argv) {

    printf("Running ssha256.s* KAT...\n");

    int fail = test_ssha256();

    if(fail == 0)  {

        printf("Test passed.\n");

        return 0;

    } else {
        
        printf("Test %d Failed.\n", fail);

        return 1;
    }

}

