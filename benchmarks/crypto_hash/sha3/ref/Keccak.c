/*
Implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
hereby denoted as "the implementer".

For more information, feedback or questions, please refer to our website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include "riscvcrypto/crypto_hash/sha3/Keccak.h"

/*
================================================================
A readable and compact implementation of the Keccak-f[1600] permutation.
================================================================
*/

/**
  * Function that computes the linear feedback shift register (LFSR) used to
  * define the round constants (see [Keccak Reference, Section 1.2]).
  */
static int LFSR86540(uint8_t *LFSR)
{
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

/**
 * Function that computes the Keccak-f[1600] permutation on the given state.
 */
static void KeccakF1600_StatePermute(void *state)
{
    unsigned int round, x, y, j, t;
    uint8_t LFSRstate = 0x01;

    for(round=0; round<24; round++) {
        {   /* === θ step (see [Keccak Reference, Section 2.3.2]) === */
            uint64_t C[5], D;

            /* Compute the parity of the columns */
            for(x=0; x<5; x++) {
                C[x] = readLane(x, 0) ^ readLane(x, 1) ^ readLane(x, 2) ^ readLane(x, 3) ^ readLane(x, 4);
            }
            for(x=0; x<5; x++) {
                /* Compute the θ effect for a given column */
                D = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
                /* Add the θ effect to the whole column */
                for (y=0; y<5; y++) {
                    XORLane(x, y, D);
                }
            }
        }

        {   /* === ρ and π steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4]) === */
            uint64_t current, temp;
            /* Start at coordinates (1 0) */
            x = 1; y = 0;
            current = readLane(x, y);
            /* Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23 */
            for(t=0; t<24; t++) {
                /* Compute the rotation constant r = (t+1)(t+2)/2 */
                unsigned int r = ((t+1)*(t+2)/2)%64;
                /* Compute ((0 1)(2 3)) * (x y) */
                unsigned int Y = (2*x+3*y)%5; x = y; y = Y;
                /* Swap current and state(x,y), and rotate */
                temp = readLane(x, y);
                writeLane(x, y, ROL64(current, r));
                current = temp;
            }
        }

        {   /* === χ step (see [Keccak Reference, Section 2.3.1]) === */
            uint64_t temp[5];
            for(y=0; y<5; y++) {
                /* Take a copy of the plane */
                for(x=0; x<5; x++) {
                    temp[x] = readLane(x, y);
                }
                /* Compute χ on the plane */
                for(x=0; x<5; x++) {
                    writeLane(x, y, temp[x] ^((~temp[(x+1)%5]) & temp[(x+2)%5]));
                }
            }
        }

        {   /* === ι step (see [Keccak Reference, Section 2.3.5]) === */
            for(j=0; j<7; j++) {
                unsigned int bitPosition = (1<<j)-1; /* 2^j-1 */
                if (LFSR86540(&LFSRstate)) {
                    XORLane(0, 0, (uint64_t)1<<bitPosition);
                }
            }
        }
    }
}

/*
================================================================
A readable and compact implementation of the Keccak sponge functions
that use the Keccak-f[1600] permutation.
================================================================
*/

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen)
{
    uint8_t state[200];
    unsigned int rateInBytes = rate/8;
    unsigned int blockSize = 0;
    unsigned int i;

    if (((rate + capacity) != 1600) || ((rate % 8) != 0))
        return;

    /* === Initialize the state === */
    memset(state, 0, sizeof(state));

    /* === Absorb all the input blocks === */
    while(inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        for(i=0; i<blockSize; i++)
            state[i] ^= input[i];
        input += blockSize;
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            KeccakF1600_StatePermute(state);
            blockSize = 0;
        }
    }

    /* === Do the padding and switch to the squeezing phase === */
    /* Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix) */
    state[blockSize] ^= delimitedSuffix;
    /* If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
    if (((delimitedSuffix & 0x80) != 0) && (blockSize == (rateInBytes-1)))
        KeccakF1600_StatePermute(state);
    /* Add the second bit of padding */
    state[rateInBytes-1] ^= 0x80;
    /* Switch to the squeezing phase */
    KeccakF1600_StatePermute(state);

    /* === Squeeze out all the output blocks === */
    while(outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        memcpy(output, state, blockSize);
        output += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0)
            KeccakF1600_StatePermute(state);
    }
}

