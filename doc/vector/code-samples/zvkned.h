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

#ifndef ZVKNED_H_
#define ZVKNED_H_

#include <stdint.h>


// Key scheduling / expansion.

extern void
zvkned_aes128_expand_key(
    uint32_t* dest,      // char[176], 32b aligned
    const void* key  // char[16], 32b aligned
);

extern void
zvkned_aes256_expand_key(
    uint32_t* dest,       // char[240], 32b aligned
    const void* key   // char[32], 32b aligned
);

// AES-128 Encoding

extern uint64_t
zvkned_aes128_encode_vs_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

extern uint64_t
zvkned_aes128_encode_vs_lmul2(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

extern uint64_t
zvkned_aes128_encode_vs_lmul4(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

extern uint64_t
zvkned_aes128_encode_vv_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);


// AES-128 Decoding

extern uint64_t
zvkned_aes128_decode_vs_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

extern uint64_t
zvkned_aes128_decode_vs_lmul2(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

extern uint64_t
zvkned_aes128_decode_vv_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);


// AES-256 Encoding

extern uint64_t
zvkned_aes256_encode_vs_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

extern uint64_t
zvkned_aes256_encode_vs_lmul2(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

extern uint64_t
zvkned_aes256_encode_vs_lmul4(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

extern uint64_t
zvkned_aes256_encode_vv_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

// AES-256 Decoding

extern uint64_t
zvkned_aes256_decode_vs_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

extern uint64_t
zvkned_aes256_decode_vs_lmul2(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

extern uint64_t
zvkned_aes256_decode_vv_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

#endif  // ZVKNED_H_
