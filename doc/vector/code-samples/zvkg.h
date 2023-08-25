// Copyright 2022 Rivos Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ZVKG_H_
#define ZVKG_H_

#include <stdint.h>

// Y, X, and H point to 128 bits values, 32b aligned if the processor
// does not support unaligned access.
//
//   Y <- (Y xor X) o H
// where 'o' is the Galois Field Multiplication in GF(2^128).
extern void
zvkg_vghsh(
    void* Y,
    const void* X,
    const void* H
);

// Y, X, and H point to arrays of 128 bits values, 32b aligned
// if the processor does not support unaligned access.
// 'n' is the number of 128b element groups.
//
//   Y[i]_out = (Y[i]_in ^ X[i]) o H[i]
// where 'o' is the Galois Field Multiplication in GF(2^128).
extern void
zvkg_vghsh_vv(
    void* Y,
    const void* X,
    const void* H,
    size_t n
);

// X and Y point to arrays of 128 bits values, 32b aligned
// if the processor does not support unaligned access.
// 'n' is the number of 128b element groups.
//
//   Y[i]_out = Y[i]_in o H[i]
// where 'o' is the Galois Field Multiplication in GF(2^128).
extern void
zvkg_vgmul_vv(
    void* Y,
    const void* H,
    size_t n
);

#endif  // ZVKG_H_
