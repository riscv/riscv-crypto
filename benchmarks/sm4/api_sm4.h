
#ifndef __API_SM4_H__
#define __API_SM4_H__

void    sm4_key_schedule_enc (
    uint32_t rk [32], //!< Output expanded round key
    uint8_t  mk [16]  //!< Input cipher key
);

void    sm4_key_schedule_dec (
    uint32_t rk [32], //!< Output expanded round key
    uint8_t  mk [16]  //!< Input cipher key
);

void    sm4_block_enc_dec (
    uint8_t  out [16], // Output block
    uint8_t  in  [16], // Input block
    uint32_t rk  [32]  // Round key (encrypt or decrypt)
);

#endif

