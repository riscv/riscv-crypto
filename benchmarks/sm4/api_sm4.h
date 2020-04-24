
#ifndef __API_SM4_H__
#define __API_SM4_H__

void    sm4_key_schedule_enc (
    uint32_t rk [32], //!< Output expanded round key
    uint8_t  mk [16]  //!< Input cipher key
);

#endif

