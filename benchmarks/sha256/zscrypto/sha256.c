
#include <stdio.h>
#include <string.h>

#include "riscvcrypto/sha256/api_sha256.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

static uint32_t K [64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline void sha256_hash_init (
    uint32_t    H [8]  //!< out - message block hash
){
    H[0] = 0x6a09e667;
    H[1] = 0xbb67ae85;
    H[2] = 0x3c6ef372;
    H[3] = 0xa54ff53a;
    H[4] = 0x510e527f;
    H[5] = 0x9b05688c;
    H[6] = 0x1f83d9ab;
    H[7] = 0x5be0cd19;
}


#define SHA256_LOAD32_BE(X, A, I) {    \
    X = ((uint32_t*)A)[I];             \
    X = __builtin_bswap32(X);   \
}

#define SHA256_STORE32_BE(X, A, I) {    \
    A[I] = __builtin_bswap32(X) ;   \
}

#define ROR32(X,Y) ((X>>Y) | (X << (32-Y)))
#define SHR32(X,Y) ((X>>Y)                )

#define CH(X,Y,Z)  ((X&Y)^(~X&Z))
#define MAJ(X,Y,Z) ((X&Y)^(X&Z)^(Y&Z))

#define SUM_0(X)   (_sha256sum0(X))
#define SUM_1(X)   (_sha256sum1(X))

#define SIGMA_0(X) (_sha256sig0(X))
#define SIGMA_1(X) (_sha256sig1(X))

#define ROUND(A,B,C,D,E,F,G,H,K,W) { \
    H  = H + SUM_1(E) + CH(E,F,G) + K + W   ; \
    D  = D + H                              ; \
    H  = H + SUM_0(A) + MAJ(A,B,C)          ; \
}

#define SCHEDULE(M0,M1,M9,ME) { \
    M0 = SIGMA_1(ME) + M9 + SIGMA_0(M1) + M0; \
}

static void sha256_hash_block (
    uint32_t    H[ 8], //!< in,out - message block hash
    uint32_t    M[16]  //!< in - The message block to add to the hash
){
    uint32_t    a,b,c,d,e,f,g,h ;   // Working variables.

    a   =   H[0];                   // Initialise working variables.
    b   =   H[1];
    c   =   H[2];
    d   =   H[3];
    e   =   H[4];
    f   =   H[5];
    g   =   H[6];
    h   =   H[7];

    uint32_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, ma, mb, mc, md, me, mf;

    SHA256_LOAD32_BE(m0, M,  0);
    SHA256_LOAD32_BE(m1, M,  1);
    SHA256_LOAD32_BE(m2, M,  2);
    SHA256_LOAD32_BE(m3, M,  3);
    SHA256_LOAD32_BE(m4, M,  4);
    SHA256_LOAD32_BE(m5, M,  5);
    SHA256_LOAD32_BE(m6, M,  6);
    SHA256_LOAD32_BE(m7, M,  7);
    SHA256_LOAD32_BE(m8, M,  8);
    SHA256_LOAD32_BE(m9, M,  9);
    SHA256_LOAD32_BE(ma, M, 10);
    SHA256_LOAD32_BE(mb, M, 11);
    SHA256_LOAD32_BE(mc, M, 12);
    SHA256_LOAD32_BE(md, M, 13);
    SHA256_LOAD32_BE(me, M, 14);
    SHA256_LOAD32_BE(mf, M, 15);

    uint32_t *kp = K     ;
    uint32_t *ke = K + 48;

    while(1) {
        
        ROUND(a, b, c, d, e, f, g, h, kp[ 0], m0)
        ROUND(h, a, b, c, d, e, f, g, kp[ 1], m1)
        ROUND(g, h, a, b, c, d, e, f, kp[ 2], m2)
        ROUND(f, g, h, a, b, c, d, e, kp[ 3], m3)
        ROUND(e, f, g, h, a, b, c, d, kp[ 4], m4)
        ROUND(d, e, f, g, h, a, b, c, kp[ 5], m5)
        ROUND(c, d, e, f, g, h, a, b, kp[ 6], m6)
        ROUND(b, c, d, e, f, g, h, a, kp[ 7], m7)
        ROUND(a, b, c, d, e, f, g, h, kp[ 8], m8)
        ROUND(h, a, b, c, d, e, f, g, kp[ 9], m9)
        ROUND(g, h, a, b, c, d, e, f, kp[10], ma)
        ROUND(f, g, h, a, b, c, d, e, kp[11], mb)
        ROUND(e, f, g, h, a, b, c, d, kp[12], mc)
        ROUND(d, e, f, g, h, a, b, c, kp[13], md)
        ROUND(c, d, e, f, g, h, a, b, kp[14], me)
        ROUND(b, c, d, e, f, g, h, a, kp[15], mf)

        if(kp == ke){break;}
        kp+=16;

        SCHEDULE(m0, m1, m9, me)
        SCHEDULE(m1, m2, ma, mf)
        SCHEDULE(m2, m3, mb, m0)
        SCHEDULE(m3, m4, mc, m1)
        SCHEDULE(m4, m5, md, m2)
        SCHEDULE(m5, m6, me, m3)
        SCHEDULE(m6, m7, mf, m4)
        SCHEDULE(m7, m8, m0, m5)
        SCHEDULE(m8, m9, m1, m6)
        SCHEDULE(m9, ma, m2, m7)
        SCHEDULE(ma, mb, m3, m8)
        SCHEDULE(mb, mc, m4, m9)
        SCHEDULE(mc, md, m5, ma)
        SCHEDULE(md, me, m6, mb)
        SCHEDULE(me, mf, m7, mc)
        SCHEDULE(mf, m0, m8, md)

    }
    
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}


void sha256_hash (
    uint32_t    H[ 8], //!< in,out - message block hash
    uint8_t   * M    , //!< in - The message to be hashed
    size_t      len    //!< Length of the message in *bytes*.
){
    uint32_t   p_H[ 8] ;
    uint32_t   p_B[16] ;
    uint8_t  * p_M     = M ;

    size_t     len_bits= len << 3;

    sha256_hash_init(p_H);

    while(len >= 64) {
        memcpy(p_B, p_M, 64);           // Copy 64 bytes/512 bits to process. 

        sha256_hash_block (p_H, p_B);   // Digest another block

        p_M += 64;                      // Adjust pointers and length.
        len -= 64;
    }

    memcpy(p_B, p_M, len);              // Copy remaining bytes into block

    uint8_t * bp = (uint8_t*)p_B;
    bp[len++] = 0x80;                   // Append `1` to end of message

    if(len > 56) {                      // Do we spill into another block?
        memset(bp+len, 0, 64-len);      // If yes, clear rest of this block
        sha256_hash_block(p_H, p_B);    // Length will be added in a new block
        len = 0;                        //
    }

    size_t i = 64;
    while(len_bits) {                   // Add length to end of this block
        bp[--i] = len_bits  & 0xFF;
        len_bits= len_bits >>    8;
    }

    memset(bp + len, 0, i-len);         // Clear fstart of block/EoM to len

    sha256_hash_block(p_H,p_B);

    for(size_t i = 0; i < 8; i ++) {    // Store result in big endian
        uint32_t x = p_H[i];
        SHA256_STORE32_BE(x,H,i);
    }
}





