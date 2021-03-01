
#include "riscvcrypto/sha3/Keccak.h"

/*!
@addtogroup crypto_hash_sha3_reference SHA3 Reference
@brief Reference implementation of SHA3.
@ingroup crypto_hash_sha3
@{
*/


#define readLane(x, y)          (((uint64_t*)state)[index(x, y)])
#define writeLane(x, y, lane)   (((uint64_t*)state)[index(x, y)]) = (lane)
#define XORLane(x, y, lane)     (((uint64_t*)state)[index(x, y)]) ^= (lane)

static const uint64_t KeccakP1600RoundConstants[24] =
{
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
};

static inline uint64_t roli(uint64_t rs1, int i) {
    uint64_t rd;
    asm ("rori %0, %1, 64-%2" : "=r"(rd) :"r"(rs1),"i"(i));
    return rd;
}

static inline uint64_t andn(uint64_t rs1, uint64_t rs2) {
    uint64_t rd;
    asm ("andn %0, %1, %2" : "=r"(rd) :"r"(rs1),"r"(rs2));
    return rd;
}

#define ROL64(a, offset) roli(a,offset)
#define ANDN(x,y) andn(y,x)

/**
 * Function that computes the Keccak-f[1600] permutation on the given state.
 */
static void KeccakF1600_StatePermute(uint64_t *s)
{
    int round, y;

    for(round=0; round<24; round++) {
        uint64_t C0, C1, C2, C3;

        C0 = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20] ;
        C1 = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21] ;
        C3 = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24] ;
        
        C2 = ROL64(C1, 1) ^ C3;

        s[ 0] = s[ 0] ^ C2;
        s[ 5] = s[ 5] ^ C2;
        s[10] = s[10] ^ C2;
        s[15] = s[15] ^ C2;
        s[20] = s[20] ^ C2;
        
        C2 = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22] ;

        C3 = ROL64(C3, 1) ^ C2;
        C2 = ROL64(C2, 1) ^ C0;
             
        s[ 1] = s[ 1] ^ C2;
        s[ 6] = s[ 6] ^ C2;
        s[11] = s[11] ^ C2;
        s[16] = s[16] ^ C2;
        s[21] = s[21] ^ C2;
        
        C2 = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23] ;
        
        C0 = ROL64(C0, 1) ^ C2;
        C2 = ROL64(C2, 1) ^ C1;
             
        s[ 4] = s[ 4] ^ C0;
        s[ 9] = s[ 9] ^ C0;
        s[14] = s[14] ^ C0;
        s[19] = s[19] ^ C0;
        s[24] = s[24] ^ C0;
             
        s[ 3] = s[ 3] ^ C3;
        s[ 8] = s[ 8] ^ C3;
        s[13] = s[13] ^ C3;
        s[18] = s[18] ^ C3;
        s[23] = s[23] ^ C3;
        
        s[ 2] = s[ 2] ^ C2;
        s[ 7] = s[ 7] ^ C2;
        s[12] = s[12] ^ C2;
        s[17] = s[17] ^ C2;
        s[22] = s[22] ^ C2;
        
        C1    = s[5];
        s[ 5] = ROL64(s[ 3],28);
        s[ 3] = ROL64(s[18],21);
        s[18] = ROL64(s[17],15);
        s[17] = ROL64(s[11],10);
        s[11] = ROL64(s[ 7], 6);
        s[ 7] = ROL64(s[10], 3);
        s[10] = ROL64(s[ 1], 1);
        s[ 1] = ROL64(s[ 6],44);
        s[ 6] = ROL64(s[ 9],20);
        s[ 9] = ROL64(s[22],61);
        s[22] = ROL64(s[14],39);
        s[14] = ROL64(s[20],18);
        s[20] = ROL64(s[ 2],62);
        s[ 2] = ROL64(s[12],43);
        s[12] = ROL64(s[13],25);
        s[13] = ROL64(s[19], 8);
        s[19] = ROL64(s[23],56);
        s[23] = ROL64(s[15],41);
        s[15] = ROL64(s[ 4],27);
        s[ 4] = ROL64(s[24],14);
        s[24] = ROL64(s[21], 2);
        s[21] = ROL64(s[ 8],55);
        s[ 8] = ROL64(s[16],45);
        s[16] = ROL64(C1,36);

        C0    = (~s[ 3]) & s[ 4];
        s[ 4] = s[ 4] ^ ANDN(s[ 0], s[ 1]);
        s[ 1] = s[ 1] ^ ANDN(s[ 2], s[ 3]);
        s[ 3] = s[ 3] ^ ANDN(s[ 4], s[ 0]);
        s[ 0] = s[ 0] ^ ANDN(s[ 1], s[ 2]);
        s[ 2] = s[ 2] ^ (C0              );

        C0    = (~s[ 8]) & s[ 9];
        s[ 9] = s[ 9] ^ ANDN(s[ 5], s[ 6]);
        s[ 6] = s[ 6] ^ ANDN(s[ 7], s[ 8]);
        s[ 8] = s[ 8] ^ ANDN(s[ 9], s[ 5]);
        s[ 5] = s[ 5] ^ ANDN(s[ 6], s[ 7]);
        s[ 7] = s[ 7] ^ (C0              );

        C0    = (~s[13]) & s[14];
        s[14] = s[14] ^ ANDN(s[10], s[11]);
        s[11] = s[11] ^ ANDN(s[12], s[13]);
        s[13] = s[13] ^ ANDN(s[14], s[10]);
        s[10] = s[10] ^ ANDN(s[11], s[12]);
        s[12] = s[12] ^ (C0                );
                     
        C0    = (~s[18]) & s[19];
        s[19] = s[19] ^ ANDN(s[15], s[16]);
        s[16] = s[16] ^ ANDN(s[17], s[18]);
        s[18] = s[18] ^ ANDN(s[19], s[15]);
        s[15] = s[15] ^ ANDN(s[16], s[17]);
        s[17] = s[17] ^ (C0                );

        C0    = (~s[23]) & s[24];
        s[24] = s[24] ^ ANDN(s[20], s[21]);
        s[21] = s[21] ^ ANDN(s[22], s[23]);
        s[23] = s[23] ^ ANDN(s[24], s[20]);
        s[20] = s[20] ^ ANDN(s[21], s[22]);
        s[22] = s[22] ^ (C0                );

        s[0] ^= KeccakP1600RoundConstants[round];
    }
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen)
{
    // Extra 8 bytes for saving SP in KeccakPermute.S
    uint8_t state[200 + 8];
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
            KeccakF1600_StatePermute((uint64_t*)state);
            blockSize = 0;
        }
    }

    /* === Do the padding and switch to the squeezing phase === */
    /* Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix) */
    state[blockSize] ^= delimitedSuffix;
    /* If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
    if (((delimitedSuffix & 0x80) != 0) && (blockSize == (rateInBytes-1)))
        KeccakF1600_StatePermute((uint64_t*)state);
    /* Add the second bit of padding */
    state[rateInBytes-1] ^= 0x80;
    /* Switch to the squeezing phase */
    KeccakF1600_StatePermute((uint64_t*)state);

    /* === Squeeze out all the output blocks === */
    while(outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        memcpy(output, state, blockSize);
        output += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0)
            KeccakF1600_StatePermute((uint64_t*)state);
    }
}

/*! @} */

