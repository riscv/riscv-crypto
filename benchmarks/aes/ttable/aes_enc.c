
/*!
@addtogroup crypto_block_aes_ttable AES TTable Reference
@brief Standard TTable implementation of AES w.out acceleration .
@ingroup crypto_block_aes
@{
*/

#include "riscvcrypto/share/util.h"

#include "riscvcrypto/crypto_block/aes/api_aes.h"

//! AES Round constants
static const uint8_t round_const[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

#define AES_ENC_TBOX_X { \
  TUPLE(63,C6,A5), TUPLE(7C,F8,84), TUPLE(77,EE,99), TUPLE(7B,F6,8D), \
  TUPLE(F2,FF,0D), TUPLE(6B,D6,BD), TUPLE(6F,DE,B1), TUPLE(C5,91,54), \
  TUPLE(30,60,50), TUPLE(01,02,03), TUPLE(67,CE,A9), TUPLE(2B,56,7D), \
  TUPLE(FE,E7,19), TUPLE(D7,B5,62), TUPLE(AB,4D,E6), TUPLE(76,EC,9A), \
  TUPLE(CA,8F,45), TUPLE(82,1F,9D), TUPLE(C9,89,40), TUPLE(7D,FA,87), \
  TUPLE(FA,EF,15), TUPLE(59,B2,EB), TUPLE(47,8E,C9), TUPLE(F0,FB,0B), \
  TUPLE(AD,41,EC), TUPLE(D4,B3,67), TUPLE(A2,5F,FD), TUPLE(AF,45,EA), \
  TUPLE(9C,23,BF), TUPLE(A4,53,F7), TUPLE(72,E4,96), TUPLE(C0,9B,5B), \
  TUPLE(B7,75,C2), TUPLE(FD,E1,1C), TUPLE(93,3D,AE), TUPLE(26,4C,6A), \
  TUPLE(36,6C,5A), TUPLE(3F,7E,41), TUPLE(F7,F5,02), TUPLE(CC,83,4F), \
  TUPLE(34,68,5C), TUPLE(A5,51,F4), TUPLE(E5,D1,34), TUPLE(F1,F9,08), \
  TUPLE(71,E2,93), TUPLE(D8,AB,73), TUPLE(31,62,53), TUPLE(15,2A,3F), \
  TUPLE(04,08,0C), TUPLE(C7,95,52), TUPLE(23,46,65), TUPLE(C3,9D,5E), \
  TUPLE(18,30,28), TUPLE(96,37,A1), TUPLE(05,0A,0F), TUPLE(9A,2F,B5), \
  TUPLE(07,0E,09), TUPLE(12,24,36), TUPLE(80,1B,9B), TUPLE(E2,DF,3D), \
  TUPLE(EB,CD,26), TUPLE(27,4E,69), TUPLE(B2,7F,CD), TUPLE(75,EA,9F), \
  TUPLE(09,12,1B), TUPLE(83,1D,9E), TUPLE(2C,58,74), TUPLE(1A,34,2E), \
  TUPLE(1B,36,2D), TUPLE(6E,DC,B2), TUPLE(5A,B4,EE), TUPLE(A0,5B,FB), \
  TUPLE(52,A4,F6), TUPLE(3B,76,4D), TUPLE(D6,B7,61), TUPLE(B3,7D,CE), \
  TUPLE(29,52,7B), TUPLE(E3,DD,3E), TUPLE(2F,5E,71), TUPLE(84,13,97), \
  TUPLE(53,A6,F5), TUPLE(D1,B9,68), TUPLE(00,00,00), TUPLE(ED,C1,2C), \
  TUPLE(20,40,60), TUPLE(FC,E3,1F), TUPLE(B1,79,C8), TUPLE(5B,B6,ED), \
  TUPLE(6A,D4,BE), TUPLE(CB,8D,46), TUPLE(BE,67,D9), TUPLE(39,72,4B), \
  TUPLE(4A,94,DE), TUPLE(4C,98,D4), TUPLE(58,B0,E8), TUPLE(CF,85,4A), \
  TUPLE(D0,BB,6B), TUPLE(EF,C5,2A), TUPLE(AA,4F,E5), TUPLE(FB,ED,16), \
  TUPLE(43,86,C5), TUPLE(4D,9A,D7), TUPLE(33,66,55), TUPLE(85,11,94), \
  TUPLE(45,8A,CF), TUPLE(F9,E9,10), TUPLE(02,04,06), TUPLE(7F,FE,81), \
  TUPLE(50,A0,F0), TUPLE(3C,78,44), TUPLE(9F,25,BA), TUPLE(A8,4B,E3), \
  TUPLE(51,A2,F3), TUPLE(A3,5D,FE), TUPLE(40,80,C0), TUPLE(8F,05,8A), \
  TUPLE(92,3F,AD), TUPLE(9D,21,BC), TUPLE(38,70,48), TUPLE(F5,F1,04), \
  TUPLE(BC,63,DF), TUPLE(B6,77,C1), TUPLE(DA,AF,75), TUPLE(21,42,63), \
  TUPLE(10,20,30), TUPLE(FF,E5,1A), TUPLE(F3,FD,0E), TUPLE(D2,BF,6D), \
  TUPLE(CD,81,4C), TUPLE(0C,18,14), TUPLE(13,26,35), TUPLE(EC,C3,2F), \
  TUPLE(5F,BE,E1), TUPLE(97,35,A2), TUPLE(44,88,CC), TUPLE(17,2E,39), \
  TUPLE(C4,93,57), TUPLE(A7,55,F2), TUPLE(7E,FC,82), TUPLE(3D,7A,47), \
  TUPLE(64,C8,AC), TUPLE(5D,BA,E7), TUPLE(19,32,2B), TUPLE(73,E6,95), \
  TUPLE(60,C0,A0), TUPLE(81,19,98), TUPLE(4F,9E,D1), TUPLE(DC,A3,7F), \
  TUPLE(22,44,66), TUPLE(2A,54,7E), TUPLE(90,3B,AB), TUPLE(88,0B,83), \
  TUPLE(46,8C,CA), TUPLE(EE,C7,29), TUPLE(B8,6B,D3), TUPLE(14,28,3C), \
  TUPLE(DE,A7,79), TUPLE(5E,BC,E2), TUPLE(0B,16,1D), TUPLE(DB,AD,76), \
  TUPLE(E0,DB,3B), TUPLE(32,64,56), TUPLE(3A,74,4E), TUPLE(0A,14,1E), \
  TUPLE(49,92,DB), TUPLE(06,0C,0A), TUPLE(24,48,6C), TUPLE(5C,B8,E4), \
  TUPLE(C2,9F,5D), TUPLE(D3,BD,6E), TUPLE(AC,43,EF), TUPLE(62,C4,A6), \
  TUPLE(91,39,A8), TUPLE(95,31,A4), TUPLE(E4,D3,37), TUPLE(79,F2,8B), \
  TUPLE(E7,D5,32), TUPLE(C8,8B,43), TUPLE(37,6E,59), TUPLE(6D,DA,B7), \
  TUPLE(8D,01,8C), TUPLE(D5,B1,64), TUPLE(4E,9C,D2), TUPLE(A9,49,E0), \
  TUPLE(6C,D8,B4), TUPLE(56,AC,FA), TUPLE(F4,F3,07), TUPLE(EA,CF,25), \
  TUPLE(65,CA,AF), TUPLE(7A,F4,8E), TUPLE(AE,47,E9), TUPLE(08,10,18), \
  TUPLE(BA,6F,D5), TUPLE(78,F0,88), TUPLE(25,4A,6F), TUPLE(2E,5C,72), \
  TUPLE(1C,38,24), TUPLE(A6,57,F1), TUPLE(B4,73,C7), TUPLE(C6,97,51), \
  TUPLE(E8,CB,23), TUPLE(DD,A1,7C), TUPLE(74,E8,9C), TUPLE(1F,3E,21), \
  TUPLE(4B,96,DD), TUPLE(BD,61,DC), TUPLE(8B,0D,86), TUPLE(8A,0F,85), \
  TUPLE(70,E0,90), TUPLE(3E,7C,42), TUPLE(B5,71,C4), TUPLE(66,CC,AA), \
  TUPLE(48,90,D8), TUPLE(03,06,05), TUPLE(F6,F7,01), TUPLE(0E,1C,12), \
  TUPLE(61,C2,A3), TUPLE(35,6A,5F), TUPLE(57,AE,F9), TUPLE(B9,69,D0), \
  TUPLE(86,17,91), TUPLE(C1,99,58), TUPLE(1D,3A,27), TUPLE(9E,27,B9), \
  TUPLE(E1,D9,38), TUPLE(F8,EB,13), TUPLE(98,2B,B3), TUPLE(11,22,33), \
  TUPLE(69,D2,BB), TUPLE(D9,A9,70), TUPLE(8E,07,89), TUPLE(94,33,A7), \
  TUPLE(9B,2D,B6), TUPLE(1E,3C,22), TUPLE(87,15,92), TUPLE(E9,C9,20), \
  TUPLE(CE,87,49), TUPLE(55,AA,FF), TUPLE(28,50,78), TUPLE(DF,A5,7A), \
  TUPLE(8C,03,8F), TUPLE(A1,59,F8), TUPLE(89,09,80), TUPLE(0D,1A,17), \
  TUPLE(BF,65,DA), TUPLE(E6,D7,31), TUPLE(42,84,C6), TUPLE(68,D0,B8), \
  TUPLE(41,82,C3), TUPLE(99,29,B0), TUPLE(2D,5A,77), TUPLE(0F,1E,11), \
  TUPLE(B0,7B,CB), TUPLE(54,A8,FC), TUPLE(BB,6D,D6), TUPLE(16,2C,3A)  \
}

#define TUPLE(a1,a2,a3)       0x##a3##a1##a1##a2
uint32_t AES_ENC_TBOX_0[] = AES_ENC_TBOX_X;
#undef TUPLE
#define TUPLE(a1,a2,a3)       0x##a1##a1##a2##a3
uint32_t AES_ENC_TBOX_1[] = AES_ENC_TBOX_X;
#undef TUPLE
#define TUPLE(a1,a2,a3)       0x##a1##a2##a3##a1
uint32_t AES_ENC_TBOX_2[] = AES_ENC_TBOX_X;
#undef TUPLE
#define TUPLE(a1,a2,a3)       0x##a2##a3##a1##a1
uint32_t AES_ENC_TBOX_3[] = AES_ENC_TBOX_X;
#undef TUPLE
#define TUPLE(a1,a2,a3)       0x##a1##a1##a1##a1
uint32_t AES_ENC_TBOX_4[] = AES_ENC_TBOX_X;
#undef TUPLE

#define AES_ENC_RND_INIT() {  \
  t_0 = rkp[ 0 ] ^ t_0;       \
  t_1 = rkp[ 1 ] ^ t_1;       \
  t_2 = rkp[ 2 ] ^ t_2;       \
  t_3 = rkp[ 3 ] ^ t_3;       \
                              \
  rkp += AES_128_NB;          \
}

#define AES_ENC_RND_ITER() {                                                 \
  t_4 = rkp[ 0 ] ^ ( AES_ENC_TBOX_0[ ( t_0 >>  0 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_1[ ( t_1 >>  8 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_2[ ( t_2 >> 16 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_3[ ( t_3 >> 24 ) & 0xFF ]              ) ; \
  t_5 = rkp[ 1 ] ^ ( AES_ENC_TBOX_0[ ( t_1 >>  0 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_1[ ( t_2 >>  8 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_2[ ( t_3 >> 16 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_3[ ( t_0 >> 24 ) & 0xFF ]              ) ; \
  t_6 = rkp[ 2 ] ^ ( AES_ENC_TBOX_0[ ( t_2 >>  0 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_1[ ( t_3 >>  8 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_2[ ( t_0 >> 16 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_3[ ( t_1 >> 24 ) & 0xFF ]              ) ; \
  t_7 = rkp[ 3 ] ^ ( AES_ENC_TBOX_0[ ( t_3 >>  0 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_1[ ( t_0 >>  8 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_2[ ( t_1 >> 16 ) & 0xFF ]              ) ^ \
                   ( AES_ENC_TBOX_3[ ( t_2 >> 24 ) & 0xFF ]              ) ; \
                                                                             \
  rkp += AES_128_NB; t_0 = t_4; t_1 = t_5; t_2 = t_6; t_3 = t_7;             \
}

#define AES_ENC_RND_FINI() {                                                 \
  t_4 = rkp[ 0 ] ^ ( AES_ENC_TBOX_4[ ( t_0 >>  0 ) & 0xFF ] & 0x000000FF ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_1 >>  8 ) & 0xFF ] & 0x0000FF00 ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_2 >> 16 ) & 0xFF ] & 0x00FF0000 ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_3 >> 24 ) & 0xFF ] & 0xFF000000 ) ; \
  t_5 = rkp[ 1 ] ^ ( AES_ENC_TBOX_4[ ( t_1 >>  0 ) & 0xFF ] & 0x000000FF ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_2 >>  8 ) & 0xFF ] & 0x0000FF00 ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_3 >> 16 ) & 0xFF ] & 0x00FF0000 ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_0 >> 24 ) & 0xFF ] & 0xFF000000 ) ; \
  t_6 = rkp[ 2 ] ^ ( AES_ENC_TBOX_4[ ( t_2 >>  0 ) & 0xFF ] & 0x000000FF ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_3 >>  8 ) & 0xFF ] & 0x0000FF00 ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_0 >> 16 ) & 0xFF ] & 0x00FF0000 ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_1 >> 24 ) & 0xFF ] & 0xFF000000 ) ; \
  t_7 = rkp[ 3 ] ^ ( AES_ENC_TBOX_4[ ( t_3 >>  0 ) & 0xFF ] & 0x000000FF ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_0 >>  8 ) & 0xFF ] & 0x0000FF00 ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_1 >> 16 ) & 0xFF ] & 0x00FF0000 ) ^ \
                   ( AES_ENC_TBOX_4[ ( t_2 >> 24 ) & 0xFF ] & 0xFF000000 ) ; \
                                                                             \
  rkp += AES_128_NB; t_0 = t_4; t_1 = t_5; t_2 = t_6; t_3 = t_7;             \
}


/*!
@brief A generic AES key schedule
*/
void    aes_key_schedule (
    uint32_t * rk , //!< Output Nk*(Nr+1) word cipher key.
    uint8_t  * ck , //!< Input Nk byte cipher key
    const int  Nk , //!< Number of words in the key.
    const int  Nr   //!< Number of rounds.
){
      
    for( int i =  0; i < ( Nk ); i++ ) {
        rk[i] = U8_TO_U32LE((ck+(4*i)));
    }

    for(int i = 4; i < Nk*(Nr+1); i += 1) {
        uint32_t t_0 = rk[ i - 1 ];
        uint32_t t_1 = rk[ i - 4 ];

        if( ( i % AES_128_NK ) == 0 ) {
          t_0 = round_const [ i / Nk] ^
              ( AES_ENC_TBOX_4[ ( t_0 >>  8 ) & 0xFF ] & 0x000000FF ) ^
              ( AES_ENC_TBOX_4[ ( t_0 >> 16 ) & 0xFF ] & 0x0000FF00 ) ^
              ( AES_ENC_TBOX_4[ ( t_0 >> 24 ) & 0xFF ] & 0x00FF0000 ) ^
              ( AES_ENC_TBOX_4[ ( t_0 >>  0 ) & 0xFF ] & 0xFF000000 ) ;
        }

        rk[ i ] = t_0 ^ t_1;
    }
}


/*!
*/
void    aes_128_enc_key_schedule (
    uint32_t    rk [AES_128_RK_BYTES ],
    uint8_t     ck [AES_128_KEY_BYTES]
){
    aes_key_schedule(rk, ck, 4, 10);
}


/*!
*/
void    aes_ecb_encrypt (
    uint8_t     ct [AES_BLOCK_BYTES],
    uint8_t     pt [AES_BLOCK_BYTES],
    uint32_t  * rk,
    int         nr
){
    uint32_t *rkp = ( uint32_t* )( rk ), t_0, t_1, t_2, t_3, t_4, t_5, t_6, t_7;

    t_0 = U8_TO_U32LE((pt +  0));
    t_1 = U8_TO_U32LE((pt +  4));
    t_2 = U8_TO_U32LE((pt +  8));
    t_3 = U8_TO_U32LE((pt + 12));

    //      1 initial   round
    AES_ENC_RND_INIT();
    
    for( int i = 1; i < AES_128_NR; i++ ) {
        AES_ENC_RND_ITER();
    }
    
    AES_ENC_RND_FINI(); 

    U32_TO_U8LE(ct, t_0,  0 );
    U32_TO_U8LE(ct, t_1,  4 );
    U32_TO_U8LE(ct, t_2,  8 );
    U32_TO_U8LE(ct, t_3, 12 );
}

//!@}
