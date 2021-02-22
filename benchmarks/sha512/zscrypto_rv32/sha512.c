
#include <stdio.h>
#include <string.h>

#include "riscvcrypto/sha512/api_sha512.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"

static uint64_t K [80] = {
    0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL,
    0xe9b5dba58189dbbcL, 0x3956c25bf348b538L, 0x59f111f1b605d019L,
    0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L,
    0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
    0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L,
    0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L,
    0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L, 0x2de92c6f592b0275L,
    0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
    0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL,
    0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L,
    0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL,
    0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
    0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L,
    0x92722c851482353bL, 0xa2bfe8a14cf10364L, 0xa81a664bbc423001L,
    0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L,
    0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
    0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L,
    0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL,
    0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL,
    0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
    0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L,
    0xc67178f2e372532bL, 0xca273eceea26619cL, 0xd186b8c721c0c207L,
    0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL,
    0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
    0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL,
    0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL,
    0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
};

static inline void sha512_hash_init (
    uint64_t    H [8]  //!< out - message block hash
){
	H[0] = 0x6A09E667F3BCC908L;
	H[1] = 0xBB67AE8584CAA73BL;
	H[2] = 0x3C6EF372FE94F82BL;
	H[3] = 0xA54FF53A5F1D36F1L;
	H[4] = 0x510E527FADE682D1L;
	H[5] = 0x9B05688C2B3E6C1FL;
	H[6] = 0x1F83D9ABFB41BD6BL;
	H[7] = 0x5BE0CD19137E2179L;
}


#define SHA512_LOAD64_BE(X, A, I) {    \
    X = ((uint64_t*)A)[I];             \
    X = __builtin_bswap64(X);          \
}

#define SHA512_STORE64_BE(X, A, I) {    \
    A[I] = __builtin_bswap64(X);  \
}

#define ROR64(X,Y) ((X>>Y) | (X << (64-Y)))
#define SHR64(X,Y) ((X>>Y)                )

#define CH(X,Y,Z)  ((X&Y)^(~X&Z))
#define MAJ(X,Y,Z) ((X&Y)^(X&Z)^(Y&Z))

#define SUM_0(x)   (((uint64_t)_sha512sum0r((uint32_t)(x>>32),(uint32_t)x))<<32 | ((uint64_t)_sha512sum0r((uint32_t)x,(uint32_t)(x>>32))))
#define SUM_1(x)   (((uint64_t)_sha512sum1r((uint32_t)(x>>32),(uint32_t)x))<<32 | ((uint64_t)_sha512sum1r((uint32_t)x,(uint32_t)(x>>32))))
#define SIGMA_0(x) (((uint64_t)_sha512sig0h((uint32_t)(x>>32),(uint32_t)x))<<32 | ((uint64_t)_sha512sig0l((uint32_t)x,(uint32_t)(x>>32))))
#define SIGMA_1(x) (((uint64_t)_sha512sig1h((uint32_t)(x>>32),(uint32_t)x))<<32 | ((uint64_t)_sha512sig1l((uint32_t)x,(uint32_t)(x>>32))))

#define ROUND(A,B,C,D,E,F,G,H,K,W) { \
    H  = H + SUM_1(E) + CH(E,F,G) + K + W   ; \
    D  = D + H                              ; \
    H  = H + SUM_0(A) + MAJ(A,B,C)          ; \
}

#define SCHEDULE(M0,M1,M9,ME) { \
    M0 = SIGMA_1(ME) + M9 + SIGMA_0(M1) + M0; \
}

static void sha512_hash_block (
    uint64_t    H[ 8], //!< in,out - message block hash
    uint64_t    M[16]  //!< in - The message block to add to the hash
){
    uint64_t    a,b,c,d,e,f,g,h ;   // Working variables.

    a   =   H[0];                   // Initialise working variables.
    b   =   H[1];
    c   =   H[2];
    d   =   H[3];
    e   =   H[4];
    f   =   H[5];
    g   =   H[6];
    h   =   H[7];

    uint64_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, ma, mb, mc, md, me, mf;

    SHA512_LOAD64_BE(m0, M,  0);
    SHA512_LOAD64_BE(m1, M,  1);
    SHA512_LOAD64_BE(m2, M,  2);
    SHA512_LOAD64_BE(m3, M,  3);
    SHA512_LOAD64_BE(m4, M,  4);
    SHA512_LOAD64_BE(m5, M,  5);
    SHA512_LOAD64_BE(m6, M,  6);
    SHA512_LOAD64_BE(m7, M,  7);
    SHA512_LOAD64_BE(m8, M,  8);
    SHA512_LOAD64_BE(m9, M,  9);
    SHA512_LOAD64_BE(ma, M, 10);
    SHA512_LOAD64_BE(mb, M, 11);
    SHA512_LOAD64_BE(mc, M, 12);
    SHA512_LOAD64_BE(md, M, 13);
    SHA512_LOAD64_BE(me, M, 14);
    SHA512_LOAD64_BE(mf, M, 15);

    uint64_t *kp = K     ;
    uint64_t *ke = K + 64;

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


void sha512_hash (
    uint64_t    H[ 8], //!< in,out - message block hash
    uint8_t   * M    , //!< in - The message to be hashed
    size_t      len    //!< Length of the message in *bytes*.
){
    uint64_t   p_H[ 8] ;
    uint64_t   p_B[16] ;
    uint8_t  * p_M     = M ;

    size_t     len_bits= len << 3;

    sha512_hash_init(p_H);

    while(len >= 128) {
        memcpy(p_B, p_M, 128);          // Copy 128 bytes / 1024 bits . 

        sha512_hash_block (p_H, p_B);   // Digest another block

        p_M += 128;                     // Adjust pointers and length.
        len -= 128;
    }

    memcpy(p_B, p_M, len);              // Copy remaining bytes into block

    uint8_t * bp = (uint8_t*)p_B;
    bp[len++] = 0x80;                   // Append `1` to end of message

    if(len > 112) {                     // Do we spill into another block?
        memset(bp+len, 0, 128-len);     // If yes, clear rest of this block
        sha512_hash_block(p_H, p_B);    // Length will be added in a new block
        len = 0;                        //
    }

    size_t i = 128;
    while(len_bits) {                   // Add length to end of this block
        bp[--i] = len_bits  & 0xFF;
        len_bits= len_bits >>    8;
    }

    memset(bp + len, 0, i-len);         // Clear fstart of block/EoM to len

    sha512_hash_block(p_H,p_B);

    for(size_t i = 0; i < 8; i ++) {    // Store result in big endian
        uint64_t x = p_H[i];
        SHA512_STORE64_BE(x,H,i);
    }
}




