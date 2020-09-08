
#include "permutation.h"

#if __riscv_xlen == 64
typedef uint64_t uint_xlen_t;
#else
typedef uint32_t uint_xlen_t;
#endif

// Taken from Section 2.24 of bitmanip-draft.pdf
uint_xlen_t xperm(uint_xlen_t rs1, uint_xlen_t rs2, int sz_log2)
{
    uint_xlen_t r = 0;
    uint_xlen_t sz = 1LL << sz_log2;
    uint_xlen_t mask = (1LL << sz) - 1;
    for (int i = 0; i < __riscv_xlen ; i += sz) {
        uint_xlen_t pos = ((rs2 >> i) & mask) << sz_log2;
        if (pos < __riscv_xlen) {
            r |= ((rs1 >> pos) & mask) << i;
        }
    }
    return r;
}

// Taken from Section 2.24 of bitmanip-draft.pdf
uint_xlen_t xperm_n(uint_xlen_t rs1,uint_xlen_t rs2){return xperm(rs1,rs2,2);}
uint_xlen_t xperm_b(uint_xlen_t rs1,uint_xlen_t rs2){return xperm(rs1,rs2,3);}
uint_xlen_t xperm_h(uint_xlen_t rs1,uint_xlen_t rs2){return xperm(rs1,rs2,4);}
uint_xlen_t xperm_w(uint_xlen_t rs1,uint_xlen_t rs2){return xperm(rs1,rs2,5);}


#if __riscv_xlen == 64

uint64_t sbox_4bit(uint64_t sbox, uint64_t in) {
    return xperm_n(sbox, in); // 1 instruction.
}

#elif __riscv_xlen == 32

uint64_t sbox_4bit(uint64_t sbox, uint64_t in) {
    uint32_t sbox_h = sbox >> 32;                    // All arguments
    uint32_t sbox_l = sbox      ;                    // passed in a0-3
    uint32_t in_h   = in   >> 32;                    //
    uint32_t in_l   = in        ;                    //
    uint32_t msk    = 0x88888888;                    // +2 instructions.
    uint32_t rd_h   = xperm_n(sbox_l, in_h      ) |  // +2 instructions
                      xperm_n(sbox_h, in_h ^ msk);   // +2 instructions
    uint32_t rd_l   = xperm_n(sbox_l, in_l      ) |  // +2 instructions
                      xperm_n(sbox_h, in_l ^ msk);
    uint64_t rd     = (((uint64_t)rd_h) << 32)    |  // Return values in
                      rd_l;                          // a0, a1
    return   rd     ;                                // +1 instruciton
    // 9 instructions for entire function.
}

#else
#error Unknown XLEN
#endif
