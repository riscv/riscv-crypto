
/*
 * Some demonstrations of using the Bitmanip permutation instructions
 * to perform useful cryptographic operations.
 * Examples re-produced from Claire's SVN repository:
 * - http://svn.clairexen.net/handicraft/2020/lut4perm/
 */

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
uint_xlen_t xperm4(uint_xlen_t rs1,uint_xlen_t rs2){return xperm(rs1,rs2,2);}
uint_xlen_t xperm8(uint_xlen_t rs1,uint_xlen_t rs2){return xperm(rs1,rs2,3);}
uint_xlen_t xperm16(uint_xlen_t rs1,uint_xlen_t rs2){return xperm(rs1,rs2,4);}
uint_xlen_t xperm32(uint_xlen_t rs1,uint_xlen_t rs2){return xperm(rs1,rs2,5);}


uint64_t rv32_xpermb(uint64_t rs1, uint64_t rs2) {
    uint32_t r1_h = rs1 >> 32;
    uint32_t r1_l = rs1      ;
    uint32_t r2_h = rs2 >> 32;
    uint32_t r2_l = rs2      ;
    uint32_t rd_h = xperm8(r1_l, r2_h              ) |
                    xperm8(r1_h, r2_h ^ 0x80808080 ) ;
    uint32_t rd_l = xperm8(r1_l, r2_h              ) |
                    xperm8(r1_h, r2_h ^ 0x80808080 ) ;
    return ((uint64_t)rd_h) << 32 | rd_l;
}


#if __riscv_xlen == 64

/*
@details 64-bit 4-bit SBox. Apply 4-bit SBox to each nibble in "in" and
return the new value.
*/
uint64_t sbox_4bit(uint64_t sbox, uint64_t in) {
    return xperm4(sbox, in); // 1 instruction.
}

#elif __riscv_xlen == 32

/*
@details 32-bit 4-bit sbox. Functionally identical to 64-bit variant, but
requires extra instructions to handle the narrower register-width.
Does a hi-32 lo-32 approach.
*/
uint64_t sbox_4bit(uint64_t sbox, uint64_t in) {
    uint32_t sbox_h = sbox >> 32;                    // All arguments
    uint32_t sbox_l = sbox      ;                    // passed in a0-3
    uint32_t in_h   = in   >> 32;                    //
    uint32_t in_l   = in        ;                    //
    uint32_t msk    = 0x88888888;                    // +2 instructions.
    uint32_t rd_h   = xperm4(sbox_l, in_h      ) |  // +2 instructions
                      xperm4(sbox_h, in_h ^ msk);   // +2 instructions
    uint32_t rd_l   = xperm4(sbox_l, in_l      ) |  // +2 instructions
                      xperm4(sbox_h, in_l ^ msk);
    uint64_t rd     = (((uint64_t)rd_h) << 32)    |  // Return values in
                      rd_l;                          // a0, a1
    return   rd     ;                                // +1 instruciton
    // 9 instructions for entire function.
}

#else
#error Unknown XLEN
#endif


void     pack_8bit_sbox(sbox_8bit_t * out, uint8_t * in) {

    for(int i = 0 ; i < 256; i += 8) {
        
        uint64_t dw = 
            (((uint64_t)(in[i + 0])) <<  0) |
            (((uint64_t)(in[i + 1])) <<  8) |
            (((uint64_t)(in[i + 2])) << 16) |
            (((uint64_t)(in[i + 3])) << 24) |
            (((uint64_t)(in[i + 4])) << 32) |
            (((uint64_t)(in[i + 5])) << 40) |
            (((uint64_t)(in[i + 6])) << 48) |
            (((uint64_t)(in[i + 7])) << 56) ;

        out -> packed[i/8] = dw;

    }

}


//! Apply the given sbox to each byte in the supplied 64-bit word.
uint64_t sbox_8bit     (sbox_8bit_t * sbox, uint64_t in) {

    uint64_t        rd   = 0   ;
    uint64_t        mask = 0   ;

    for(int i = 0; i < 32; i ++) {
        uint64_t sb_i = sbox -> packed[i];
        rd   |= xperm8(sb_i, in ^ mask);
        mask += 0x0808080808080808LL;
    }

    return rd;
}


/*
@details
On RV64:
-  8 instructions per loop iteration.
- 32 loop iterations
- 32*8 = 256 instructions total.
- 16 bytes processed ->  256/16 = 16 instructions / byte.
*/
void     sbox_8bit_x4  (
    uint64_t        out[2]  ,
    sbox_8bit_t *   sbox    ,
    uint64_t        in [2]
){

    uint64_t        rd0  = 0   ;
    uint64_t        rd1  = 0   ;
    uint64_t        mask = 0   ;

    for(int i = 0; i < 32; i ++) {
        uint64_t sb_i = sbox -> packed[i];          // 1 instr
        rd0  |= xperm8(sb_i, in[0] ^ mask);        // 3 instr
        rd1  |= xperm8(sb_i, in[1] ^ mask);        // 3 instr
        mask += 0x0808080808080808LL;               // 1 instr
    }

    out[0] = rd0;
    out[1] = rd1;
}

