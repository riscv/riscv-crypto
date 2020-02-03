//  enc1s.h
//  2020-01-27  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Prototypes for ENC1S and ENC4S.

#ifndef _ENC1S_H_
#define _ENC1S_H_

#include <stdint.h>

//  Function codes -- see enc1s.c

#define AES_FN_ENC  (0)
#define AES_FN_FWD  (1)
#define AES_FN_DEC  (2)
#define AES_FN_REV  (3)

//  ENC1S: Instruction for a byte select, single S-box, and linear operation.

uint32_t enc1s(uint32_t rs1, uint32_t rs2, int fb, int fa);

#endif /* _ENC1S_H_ */


