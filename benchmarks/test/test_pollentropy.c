
#include <stdint.h>
#include <stdio.h>

#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

int main(int argc, char ** argv) {

    for(int i = 0 ; i < 100; i ++) {

        uint64_t sample = _pollentropy();
        uint16_t seed   = (uint16_t)sample;
        uint8_t  status = (sample >> 30) & 0x3;

        switch(status) {
            case 0:
                printf("# BIST:\n");
                break;
            case 1:
                printf("# ES16: %02X\n", seed);
                break;
            case 2:
                printf("# WAIT:\n");
                break;
            case 3:
                printf("# DEAD:\n");
                break;
            default:
                // This should never happen.
                break;
        }

    }

    return 0;

}
