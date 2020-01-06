
/* Known answer tests for the ssha3 instructions. Used to check that the
 * simulator / thing operating it implements it correctly with some
 * degree of confidence.
*/

#include <stdio.h>
#include <stdint.h>

#define SHA3_XY(rs1,rs2) ((( (rs1&0x7)    % 5) + 5*((rs2&0x7) % 5)) << 3)
#define SHA3_X1(rs1,rs2) (((((rs1&0x7)+1) % 5) + 5*((rs2&0x7) % 5)) << 3)
#define SHA3_X2(rs1,rs2) (((((rs1&0x7)+2) % 5) + 5*((rs2&0x7) % 5)) << 3)
#define SHA3_X4(rs1,rs2) (((((rs1&0x7)+4) % 5) + 5*((rs2&0x7) % 5)) << 3)
#define SHA3_YX(rs1,rs2) ((( (rs2&0x7)    % 5) + 5*((2*(rs1&0x7) + 3*(rs2&0x7))% 5)) << 3)


#define CHECK(VAR,RS1,RS2,EXPECTED,GOT) \
    if(GOT != EXPECTED) { \
        printf("\n" VAR " Fail. RS1=%d, RS2=%d. Expected %d, got %d\n", \
            RS1, RS2, EXPECTED, GOT); \
        return 1; \
    }

int test_ssha3() {

    for (int rs1 = 0; rs1 < 10; rs1 ++) {

        for (int rs2 = 0; rs2 < 10; rs2 ++) {

            int rd_xy;
            int rd_x1;
            int rd_x2;
            int rd_x4;
            int rd_yx;

            int expected_xy = SHA3_XY(rs1,rs2);
            int expected_x1 = SHA3_X1(rs1,rs2);
            int expected_x2 = SHA3_X2(rs1,rs2);
            int expected_x4 = SHA3_X4(rs1,rs2);
            int expected_yx = SHA3_YX(rs1,rs2);

            __asm__("ssha3.xy %0, %1, %2" : "=r"(rd_xy): "r"(rs1), "r"(rs2));
            __asm__("ssha3.x1 %0, %1, %2" : "=r"(rd_x1): "r"(rs1), "r"(rs2));
            __asm__("ssha3.x2 %0, %1, %2" : "=r"(rd_x2): "r"(rs1), "r"(rs2));
            __asm__("ssha3.x4 %0, %1, %2" : "=r"(rd_x4): "r"(rs1), "r"(rs2));
            __asm__("ssha3.yx %0, %1, %2" : "=r"(rd_yx): "r"(rs1), "r"(rs2));

            if(rd_xy != expected_xy) {
                printf("\nXY Fail. RS1=%d, RS2=%d. Expected %d, got %d\n",
                    rs1, rs2, expected_xy, rd_xy);
                return 1;
            }

            CHECK("xy", rs1, rs2, expected_xy, rd_xy)
            CHECK("x1", rs1, rs2, expected_x1, rd_x1)
            CHECK("x2", rs1, rs2, expected_x2, rd_x2)
            CHECK("x4", rs1, rs2, expected_x4, rd_x4)
            CHECK("yx", rs1, rs2, expected_yx, rd_yx)

        }

    }

    return 0;

}


int main (int argc, char ** argv) {

    printf("Running ssha3.* KAT... ");

    int fail = test_ssha3();

    if(fail == 0)  {

        printf("Test passed.\n");

        return 0;

    } else {

        printf("Test %d Failed.\n", fail);

        return 1;
    }

}
