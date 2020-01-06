
/* Known answer tests for the indexed load instructions. Used to check that
 * the simulator / thing operating it implements it correctly with some
 * degree of confidence.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define ALEN 10

uint8_t  arry_lbu[ALEN];
uint16_t arry_lhu[ALEN];
uint32_t arry_lwu[ALEN];

 int8_t  arry_lb [ALEN];
 int16_t arry_lh [ALEN];
 int32_t arry_lw [ALEN];

int test_load_byte (int8_t * sarry, uint8_t * uarry) {

    for(int i = 0; i < ALEN;  i++) {

        uint32_t result_u;
         int32_t result_s;

        uint32_t expect_u = uarry[i];
         int32_t expect_s = sarry[i];

        __asm__ ("lbux %0, %1(%2)" : "=r"(result_u) : "r"(i), "r"(uarry));
        __asm__ ("lbx  %0, %1(%2)" : "=r"(result_s) : "r"(i), "r"(sarry));

        printf("lbux rd, %x(%x) - Got %x, expected %x\n",
            i, uarry, result_u, expect_u);

        printf("lbx  rd, %x(%x) - Got %x, expected %x\n",
            i, sarry, result_s, expect_s);

        if(result_u != expect_u) {
            return 1;
        }
        if(result_s != expect_s) {
            return 1;
        }

    }

    return 0;

}


int test_load_half (int16_t * sarry, uint16_t * uarry) {

    for(int i = 0; i < ALEN;  i++) {

        uint32_t result_u;
         int32_t result_s;

        uint32_t expect_u = uarry[i];
         int32_t expect_s = sarry[i];

        __asm__ ("lhux %0, %1(%2)" : "=r"(result_u) : "r"(i), "r"(uarry));
        __asm__ ("lhx  %0, %1(%2)" : "=r"(result_s) : "r"(i), "r"(sarry));

        printf("lhux rd, %x(%x) - Got %x, expected %x\n",
            i, uarry, result_u, expect_u);

        printf("lhx  rd, %x(%x) - Got %x, expected %x\n",
            i, sarry, result_s, expect_s);

        if(result_u != expect_u) {
            return 1;
        }
        if(result_s != expect_s) {
            return 1;
        }

    }

    return 0;

}


int test_load_word (int32_t * sarry, uint32_t * uarry) {

    for(int i = 0; i < ALEN;  i++) {

         int32_t result_s;

         int32_t expect_s = sarry[i];

        __asm__ ("lwx  %0, %1(%2)" : "=r"(result_s) : "r"(i), "r"(sarry));

        printf("lwx  rd, %x(%x) - Got %x, expected %x\n",
            i, sarry, result_s, expect_s);

        if(result_s != expect_s) {
            return 1;
        }

    }

    return 0;

}

//
// TODO LWUX test for RV64 only.


//
// TODO LDX test for RV64 only.

int main (int argc, char ** argv) {

    // Seed rand with something stupid for repeatability.
    srand(1);

    for(int i = 0; i < ALEN; i ++ ) {
        arry_lbu[i] = rand();
        arry_lhu[i] = rand();
        arry_lwu[i] = rand();

        arry_lb [i] = rand();
        arry_lh [i] = rand();
        arry_lw [i] = rand();
    }

    int fail = 0;

    fail |= test_load_byte(arry_lb, arry_lbu);
    fail |= test_load_half(arry_lh, arry_lhu);
    fail |= test_load_word(arry_lw, arry_lwu);


    return fail;

}
