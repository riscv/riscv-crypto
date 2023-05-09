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

#ifndef ZVKNH_H_
#define ZVKNH_H_

#include <stdint.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

// We arrange the initial hash value to remove the need for byte-swapping
// and re-arranging in the SHA logic.
// The logic wants H0 (a), ... H7 (h) in the following order (listed
// from most significant to least significant in each group of 4 32b values):
//  {a,b,e,f} {h,g,d,c}
//
// So we want the constant array content arranged as:
//   kHash[0] = f
//   kHash[1] = e
//   kHash[2] = b
//   kHash[3] = a
//
//   kHash[4] = h
//   kHash[5] = g
//   kHash[6] = d
//   kHash[7] = c
//
// Each constant is stored in the platform endianness, i.e., little endian.
// The final hash value (updated values of a...h) needs to be byteswapped
// (to big endian) and reordered to match the expected bit stream of SHA-2.
//
static const uint32_t kSha256InitialHash[8] = {
    0x9b05688c,  // [0]: H5 = f
    0x510e527f,  // [1]: H4 = e
    0xbb67ae85,  // [2]: H1 = b
    0x6a09e667,  // [3]: H0 = a

    0x5be0cd19,  // [4]: H7 = h
    0x1f83d9ab,  // [5]: H6 = g
    0xa54ff53a,  // [6]: H3 = d
    0x3c6ef372,  // [7]: H2 = c
};

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE 128

// We arrange the initial hash value to remove the need for byte-swapping
// and re-arranging in the SHA logic.
// The logic wants H0 (a), ... H7 (h) in the following order (listed
// from most significant to least significant in each group of 4 32b values):
//  {a,b,e,f} {h,g,d,c}
//
// So we want the constant array content arranged as:
//   kHash[0] = f
//   kHash[1] = e
//   kHash[2] = b
//   kHash[3] = a
//
//   kHash[4] = h
//   kHash[5] = g
//   kHash[6] = d
//   kHash[7] = c
//
// Each constant is stored in the platform endianness, i.e., little endian.
// The final hash value (updated values of a...h) needs to be byteswapped
// (to big endian) and reordered to match the expected bit stream of SHA-2.
//
static const uint64_t kSha512InitialHash[SHA512_DIGEST_SIZE / sizeof(uint64_t)] = {
    0x9b05688c2b3e6c1f,  // [0]: H5 = f
    0x510e527fade682d1,  // [1]: H4 = e
    0xbb67ae8584caa73b,  // [2]: H1 = b
    0x6a09e667f3bcc908,  // [3]: H0 = a

    0x5be0cd19137e2179,  // [4]: H7 = h
    0x1f83d9abfb41bd6b,  // [5]: H6 = g
    0xa54ff53a5f1d36f1,  // [6]: H3 = d
    0x3c6ef372fe94f82b,  // [7]: H2 = c
};

extern void
sha256_block_lmul1(
    uint8_t* hash,
    const void* block
);

extern void
sha256_block_vslide_lmul1(
    uint8_t* hash,
    const void* block
);

extern void
sha512_block_lmul1(
    uint8_t* hash,
    const void* block
);

extern void
sha512_block_lmul2(
    uint8_t* hash,
    const void* block
);

#endif  // ZVKNH_H_
