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

#ifndef SHA_TEST_
#define SHA_TEST_

#include <stdint.h>

// Applies to both SHA-256 and SHA-512.
struct sha_test {
    uint8_t md[64];
    const uint8_t* msg;
    int msglen;
    uint8_t align[4];
};

// Applies to both SHA-256 and SHA-512.
struct sha_test_suite {
    const struct sha_test* tests;
    const char* name;
    int keylen;
    int count;
};

#endif  // SHA_TEST_
