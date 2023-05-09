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

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zvksed.h"
#include "sm4-test.h"
#include "test-vectors/sm4-test-vectors.h"

__attribute__((aligned(16)))
uint32_t buf[128] = {0};

static void
sm4_encrypt_single(uint32_t *key, size_t len, uint32_t *input,
                   uint32_t *output, bool encrypt)
{
    if (encrypt) {
        zvksed_sm4_encode_vv(output, input, len, key);
    } else {
        zvksed_sm4_decode_vv(output, input, len, key);
    }
}

static int run_sm4_test(struct sm4_test_vector *vector)
{
    assert(vector->message_len % 16 == 0 &&
           vector->message_len < sizeof(buf));

    memcpy(buf, vector->message, vector->message_len);
    for (size_t i = 0; i < vector->iterations; i++) {
        sm4_encrypt_single(vector->master_key, vector->message_len,
                           buf, buf, vector->encrypt);
    }

    return memcmp(vector->output, buf, vector->message_len);
}

int main()
{
    int result;
    size_t suites_count;
    struct sm4_test_vector *test;

    suites_count = sizeof(sm4_suites) / sizeof(sm4_suites[0]);
    for (size_t i = 0; i < suites_count; ++i) {
        printf("Running %s test suite...", sm4_suites[i].name);
        for (size_t j = 0; j < sm4_suites[i].tests_count; ++j) {
            test = &sm4_suites[i].vectors[j];
            result = run_sm4_test(test);
            if (result != 0) {
                printf("test %zu failed\n", j);
                exit(1);
            }
        }
        printf("success, %zu tests were run.\n", sm4_suites[i].tests_count);
    }

    return 0;
}
