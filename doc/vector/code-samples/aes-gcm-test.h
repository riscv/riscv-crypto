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

#ifndef AES_GCM_TESTS_H_
#define AES_GCM_TESTS_H_

#include <stdint.h>

struct aes_gcm_test {
    // Encryption/decryption Key
    uint8_t key[32];
    // Initialization Vector (IV)
    const uint8_t* iv;
    // Cipher Text
    const uint8_t* ct;
    // Additional Data
    const uint8_t* aad;
    // Expected tag
    const uint8_t* tag;
    // Plain Text
    const uint8_t* pt;
    // Lengths are in bytes.
    size_t ivlen;
    size_t ctlen;
    size_t aadlen;
    size_t taglen;
    bool encrypt;
    bool expect_fail;
    // Ensure alignment of the key in a well-aligned array.
    uint8_t padding[6];
};

struct aes_gcm_test_suite {
    const struct aes_gcm_test* tests;
    const char* name;
    size_t keylen;
    size_t count;
};

#endif  // AES_GCM_TESTS_H_
