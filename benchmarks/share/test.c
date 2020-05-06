

/*! @addtogroup test_utils
@{
*/

#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

//
// Misc IO
// ----------------------------------------------------------------------

void puthex64(uint64_t in) {
    for(int i = 0; i < 16; i += 1) {
        unsigned char x = (in >> (60-4*i)) & 0xF;
        printf("%x", x);
    }
}


void puthex(unsigned char * in, size_t len) {
    for(size_t i = 0; i < len ; i ++) {
        unsigned char c1 = (in[i] >> 4) & 0xF;
        unsigned char c2 = (in[i]     ) & 0xF;
        printf("%x%x",c1,c2);
    }
}


void puthex_py(unsigned char * in, size_t len){
    printf("binascii.a2b_hex(\"");
    puthex(in,len);
    printf("\")");
}


size_t test_rdrandom(unsigned char * dest, size_t len) {
    
    // Dumb random seed generation. Originally used to read
    // /dev/random, but this caused hangs on some machines.
    srand(time(NULL));

    for(size_t i =0; i < len; i ++) {
        dest[i] = (unsigned char)rand();
    }
    
    return len      ;

}



//!@}

