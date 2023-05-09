# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# ShangMi Block Cipher (SM4) routines using the proposed Zvksed instructions
# (vsm3me.vv, vsm3c.vv).
#
# This code was developed to validate the design of the Zvksed extension,
# understand and demonstrate expected usage patterns.
#
# DISCLAIMER OF WARRANTY:
#  This code is not intended for use in real cryptographic applications,
#  has not been reviewed, even less audited by cryptography or security
#  experts, etc.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY EXPRESS
#  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#  IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
#  OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
#  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

.data
# Function Key
# Used for generating -1 round of round key {rk[-4], rk[-3], rk[-2], rk[-1]}
FK: .word 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC

.text
# zvksed_sm4_encode_vv
#
# Encodes the plain text provided in 'src'.
# 'master_key' contains an unexpanded 128 bit master key.
# Result is placed in dst.
# The length provided in 'n' shall be a multiple of 16B block size.
#
# This variant uses LMUL=1, processing a single vector register of text
# during each iteration of the core encode loop. The round keys are kept
# in vector registers (8 of them, one per round).
#
# This routine performs an initial round of key expansion prior to
# key use in the core encoding loop. If the key is used for multiple
# invocations of the encode/decode routines, it might be more efficient
# to expand the key separately and pass in the address of the pre-expanded
# key.
#
# C/C++ Signature
#   extern "C" void
#   zvksh_sm4_encode_vv(
#       void* dst,         // a0
#       const void* src,    // a1
#       uint64_t n,    // a2
#       uint32_t master_key[4]
#   );
#  a0=dest, a1=src, a2=n, a3=&master_key[0]
#
.balign 4
.global zvksed_sm4_encode_vv
zvksed_sm4_encode_vv:
    vsetivli x0, 4, e32, m1, ta, ma

    # Load the master key.
    vle32.v v10, (a3)

    # Load the FK.
    # It's used during the key expansion phase.
    la t6, FK
    vle32.v v11, (t6)

    # Stage -1 of key expansion, round_key rk{-3:-1}
    vxor.vv v10, v10, v11

    # Generate round keys.
    vsm4k.vi v11, v10, 0
    vsm4k.vi v12, v11, 1
    vsm4k.vi v13, v12, 2
    vsm4k.vi v14, v13, 3
    vsm4k.vi v15, v14, 4
    vsm4k.vi v16, v15, 5
    vsm4k.vi v17, v16, 6
    vsm4k.vi v18, v17, 7

1:
    # Load a 16B block of data to process.
    vle32.v v1, (a1)

    vsm4r.vv v1, v11    # with round key rk[0:3]
    vsm4r.vv v1, v12    # with round key rk[4:7]
    vsm4r.vv v1, v13    # with round key rk[8:11]
    vsm4r.vv v1, v14    # with round key rk[12:15]
    vsm4r.vv v1, v15    # with round key rk[16:19]
    vsm4r.vv v1, v16    # with round key rk[20:23]
    vsm4r.vv v1, v17    # with round key rk[24:27]
    vsm4r.vv v1, v18    # with round key rk[28:31]

    # Generate vector of [3, 2, 1, 0] indices.
    # Use it to reverse the order of elements in the register.
    vid.v v3
    vxor.vi v3, v3, 3
    vrgather.vv v10, v1, v3

    # Save the ciphertext.
    vse32.v v10, (a0)

    add a2, a2, -16
    add a1, a1, 16
    bnez a2, 1b

    ret

# zvksed_sm4_decode_vv
#
# Decodes the cipher text provided in 'src'.
# 'master_key' contains an unexpanded 128 bit master key.
# Result is placed in dst.
# The length provided in 'n' shall be a multiple of 16B block size.
#
# This variant uses LMUL=1, processing a single vector register of text
# during each iteration of the core encode loop. The round keys are kept
# in vector registers (8 of them, one per round).
#
# This routine performs an initial round of key expansion prior to
# key use in the core encoding loop. If the key is used for multiple
# invocations of the encode/decode routines, it might be more efficient
# to expand the key separately and pass in the address of the pre-expanded
# key.
#
# The only difference between decode and encode is that the round keys are
# applied in the reversed order.
#
# C/C++ Signature
#   extern "C" void
#   zvksed_sm4_decode_vv(
#       void* dst,         // a0
#       const void* src,    // a1
#       uint64_t n,    // a2
#       uint32_t master_key[4]
#   );
#  a0=dest, a1=src, a2=n, a3=&master_key[0]
#
.balign 4
.global zvksed_sm4_decode_vv
zvksed_sm4_decode_vv:
    vsetivli x0, 4, e32, m1, ta, ma

    # Load the master key.
    vle32.v v10, (a3)

    # Load the FK.
    # It's used during key expansion phase.
    la t6, FK
    vle32.v v11, (t6)

    # Stage -1 of key expansion, round_key rk{-3:-1}
    vxor.vv v10, v10, v11

    # Generate round keys.
    vsm4k.vi v11, v10, 0
    vsm4k.vi v12, v11, 1
    vsm4k.vi v13, v12, 2
    vsm4k.vi v14, v13, 3
    vsm4k.vi v15, v14, 4
    vsm4k.vi v16, v15, 5
    vsm4k.vi v17, v16, 6
    vsm4k.vi v18, v17, 7

    # Generate vector of [3, 2, 1, 0] indices.
    # Use it to reverse the order of elements in the register.
    vid.v v3
    vxor.vi v3, v3, 3

    # Reverse the order of elements in register.
    vrgather.vv v4, v11, v3     # round_key[3:0]
    vrgather.vv v5, v12, v3     # round_key[7:4]
    vrgather.vv v6, v13, v3     # round_key[11:8]
    vrgather.vv v7, v14, v3     # round_key[15:12]
    vrgather.vv v8, v15, v3     # round_key[19:16]
    vrgather.vv v9, v16, v3     # round_key[23:20]
    vrgather.vv v10, v17, v3    # round_key[27:24]
    vrgather.vv v11, v18, v3    # round_key[31:28]

1:
    # Load encoded text from 'src', 4B * 4 at a time
    vle32.v v1, (a1)

    vsm4r.vv v1, v11    # with round key rk[31:28]
    vsm4r.vv v1, v10    # with round key rk[27:24]
    vsm4r.vv v1, v9     # with round key rk[23:20]
    vsm4r.vv v1, v8     # with round key rk[19:16]
    vsm4r.vv v1, v7     # with round key rk[15:11]
    vsm4r.vv v1, v6     # with round key rk[11:8]
    vsm4r.vv v1, v5     # with round key rk[7:4]
    vsm4r.vv v1, v4     # with round key rk[3:0]

    # Reverse the order of elements in register.
    vrgather.vv v10, v1, v3

    # Save the plaintext.
    vse32.v v10, (a0)

    add a2, a2, -16
    add a1, a1, 16
    bnez a2, 1b
    ret
