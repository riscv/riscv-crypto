
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "riscvcrypto/sm4/api_sm4.h"
#include "riscvcrypto/share/riscv-crypto-intrinsics.h"


const uint32_t FK [ 4] = {
    0xC6BAB1A3,
    0x5033AA56,
    0x97917D67,
    0xDC2270B2
};

const uint32_t CK [32] = {
    0x150E0700, 0x312A231C, 0x4D463F38, 0x69625B54, 0x857E7770, 0xA19A938C,
    0xBDB6AFA8, 0xD9D2CBC4, 0xF5EEE7E0, 0x110A03FC, 0x2D261F18, 0x49423B34,
    0x655E5750, 0x817A736C, 0x9D968F88, 0xB9B2ABA4, 0xD5CEC7C0, 0xF1EAE3DC,
    0x0D06FFF8, 0x29221B14, 0x453E3730, 0x615A534C, 0x7D766F68, 0x99928B84,
    0xB5AEA7A0, 0xD1CAC3BC, 0xEDE6DFD8, 0x0902FBF4, 0x251E1710, 0x413A332C,
    0x5D564F48, 0x79726B64
};

static inline uint32_t ssm4_ks4(uint32_t rs1, uint32_t rs2) {
    rs1 = _ssm4_ks(rs1, rs2, 0);
    rs1 = _ssm4_ks(rs1, rs2, 1);
    rs1 = _ssm4_ks(rs1, rs2, 2);
    rs1 = _ssm4_ks(rs1, rs2, 3);
    return rs1;
}

static inline uint32_t ssm4_ed4(uint32_t rs1, uint32_t rs2) {
    rs1 = _ssm4_ed(rs1, rs2, 0);
    rs1 = _ssm4_ed(rs1, rs2, 1);
    rs1 = _ssm4_ed(rs1, rs2, 2);
    rs1 = _ssm4_ed(rs1, rs2, 3);
    return rs1;
}

void    sm4_key_schedule_enc (
    uint32_t rk [32], //!< Output expanded round key
    uint8_t  mk [16]  //!< Input cipher key
) {
    uint32_t   t   ;

    uint32_t * mkp = (uint32_t*)mk;
    uint32_t * rkp = (uint32_t*)rk;
    uint32_t * ckp = (uint32_t*)CK;
    uint32_t * rke = (uint32_t*)rk + 32;

    uint32_t K0 = mkp[0] ^ FK[0];
    uint32_t K1 = mkp[1] ^ FK[1];
    uint32_t K2 = mkp[2] ^ FK[2];
    uint32_t K3 = mkp[3] ^ FK[3];

    while(rkp < rke) {
        
        t  = K1 ^ K2 ^ K3 ^ ckp[0];
        K0 = ssm4_ks4(K0, t);
        
        t  = K2 ^ K3 ^ K0 ^ ckp[1];
        K1 = ssm4_ks4(K1, t);

        t  = K3 ^ K0 ^ K1 ^ ckp[2];
        K2 = ssm4_ks4(K2, t);

        t  = K0 ^ K1 ^ K2 ^ ckp[3];
        K3 = ssm4_ks4(K3, t);

        rkp[0] = (K0);
        rkp[1] = (K1);
        rkp[2] = (K2);
        rkp[3] = (K3);

        rkp     += 4;
        ckp     += 4;
    }

}


void    sm4_key_schedule_dec (
    uint32_t rk [32], //!< Output expanded round key
    uint8_t  mk [16]  //!< Input cipher key
){

    uint32_t tmp;

    sm4_key_schedule_enc(rk, mk);

    for(int i = 0; i < 16; i ++) {
        tmp      = rk[   i];
        rk[   i] = rk[31-i];
        rk[31-i] = tmp     ;
    }

}


void    sm4_block_enc_dec (
    uint8_t  out [16], // Output block
    uint8_t  in  [16], // Input block
    uint32_t rk  [32]  // Round key (encrypt or decrypt)
){

    uint32_t * inp = (uint32_t*)in      ;
    uint32_t * op  = (uint32_t*)out     ;
    uint32_t * rkp = (uint32_t*)rk      ;
    uint32_t * rke = (uint32_t*)rk + 32 ;

    uint32_t   X0  = (inp[0]);
    uint32_t   X1  = (inp[1]);
    uint32_t   X2  = (inp[2]);
    uint32_t   X3  = (inp[3]);

    uint32_t   t   ;

    while(rkp < rke) {

        t  = X1 ^ X2 ^ X3 ^ rkp[0];
        X0 = ssm4_ed4(X0, t);
        
        t  = X2 ^ X3 ^ X0 ^ rkp[1];
        X1 = ssm4_ed4(X1, t);

        t  = X3 ^ X0 ^ X1 ^ rkp[2];
        X2 = ssm4_ed4(X2, t);

        t  = X0 ^ X1 ^ X2 ^ rkp[3];
        X3 = ssm4_ed4(X3, t);

        rkp += 4;
    }

    op[0] = (X3);
    op[1] = (X2);
    op[2] = (X1);
    op[3] = (X0);

}

