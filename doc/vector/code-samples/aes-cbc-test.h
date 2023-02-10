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

#ifndef AES_CBC_TEST_H_
#define AES_CBC_TEST_H_

#include <stdint.h>

struct aes_cbc_test {
    uint8_t  key[32];
    uint8_t  iv[16];
    const uint8_t* plaintext;
    const uint8_t* ciphertext;
    int      plaintextlen;
    bool     encrypt;
    // Ensure alignment of the key in a well-aligned array.
    char     padding[15];
};

struct aes_cbc_test_suite {
    const char* name;
    int count;
    int keylen;
    const struct aes_cbc_test* tests;
};

#endif  // AES_CBC_TEST_H_
