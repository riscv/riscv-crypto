
#include <stdio.h>
#include <stdint.h>

#include "riscv-crypto-intrinsics.h"

#ifndef __KAT_GEN_H__
#define __KAT_GEN_H__

//! Generate a set of KAT tests for the current RV32/64 architecture.
void kat_generate(
    uint_xlen_t prng_seed , //!< Initial value for the internal PRNG.
    void (*put_char)(char)  //!< Put character function used for IO.
);


#endif

