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

#ifndef SM4_TEST_H_
#define SM4_TEST_H_

#include <stdint.h>
#include <stddef.h>

struct sm4_test_vector {
    uint32_t* message;
    uint32_t* output;
    uint32_t* master_key;
    size_t message_len;
    size_t iterations;
    bool encrypt;
    char foo[3];
};

struct sm4_test_suite {
    const char* name;
    struct sm4_test_vector* vectors;
    size_t tests_count;
};

#endif  // SM4_TEST_H_
