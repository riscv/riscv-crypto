# SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

.text

# vlen_bits
#
# Returns VLEN, i.e., the length of vector registers in bits.
#
# C/C++ Signature
#   extern "C" uint64_t
#   vlen_bits(void);
#
.balign 4
.global vlen_bits
vlen_bits:
    csrr a0, vlenb
    # Multiply vlenb (bytes) by 8 to return VLEN (bits).
    slli a0, a0, 3
    ret
