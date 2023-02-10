# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# ShangMi Hash (SM3) routines using the proposed Zvksh instructions (vsm3me.vv,
# vsm3c.vi).
#
# This code was developed to validate the design of the Zvksh extension,
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
.balign 4
# Initialization vector
# Used as a initial state of the context.
IV: .word 0x6f168073, 0xb9b21449, 0xd7422417, 0x68ada, 0xbc306fa9, 0xaa383116
    .word 0x4dee8de3, 0x4e0efbb0


.text

# zvksh_sm3_encode_lmul1
#
# Hash the provided input text content at 'src'.
# Data shall already be padded as defined in the specification.
# The output is placed in 'dst' with length of 32 bytes.
#
# 'n' should be multiple of 64 byte block size.
#
# Returns the number of bytes processed.
# This routine uses LMUL=1, processing 64 bytes in each iteration.
# It requires VLEN>=256.
#
# C/C++ Signature
#   extern "C" void
#   zvksh_sm3_encode_lmul1(
#       void* dst,         // a0
#       const void* src,   // a1
#       uint64_t n,        // a2
#   );
#  a0=dest, a1=src, a2=n
#
.balign 4
.global zvksh_sm3_encode_lmul1
zvksh_sm3_encode_lmul1:
    # - a1 points to the block bytes, gets a +=64 for each loop pass.
    # - a2 contains the number of remaining bytes, gets -=64 in each pass.

    # Vector register usage
    # - v0 contains the mask for the vmerge.
    # - v4 contains the evolving hash state {h,g,f,e,d,c,b,a} (256b as 8x32b)
    # - v8 contains the hash state H at the beginning of the block, used again
    #   at the end of each pass to create the new hash, H' = H xor {h,..,a}.
    # - v12, v16, v20, v24 contain the (expanded) message words (8 32b words each)
    #
    #  Note that we use multiples of 4, so that we can use the same code
    #  for LMUL=1, LMUL=2, and LMUL=4.

    # Load the IV and use it the an initial state of the hash context.
    vsetivli x0, 8, e32, m1, ta, ma

    la t6, IV
    vle32.v v4, (t6)

    # Set v0 to select the four least significant words (indices 0,1,2, and 3).
    # v0[i] <- i
    vid.v v0
    # v0.mask[i] <- (v0[i] <= 3), i.e., v0 <- {ffff...fffTTTT}
    vmsleu.vi v0, v0, 0x3

1:
    add a2, a2, -64  # a2 <- a2 - 64, remaining bytes after this loop pass.
    # Preserve the current hash state for the final XOR at the end of the block.
    vmv.v.v v8, v4

    # Load the 64B message block in 2x32B chunks.
    vle32.v v12, (a1)  # v12 <- {w7,w6,w5,w4,w3,w2,w1,w0}
    add a1, a1, 32
    vle32.v v16, (a1)  # v16 <- {w15,w14,w13,w12,w11,w10,w9,w8}
    add a1, a1, 32
    # As vsm3c consumes only elements at indices {0,2,4,5} in vs2, we need to
    # slide down he input by 2 elements down to use {w7,w6,w3,w2}.
    #   v20 <- {_, _, w7, w6, w5, w4, w3, w2}   (where _ may be random values)
    vslidedown.vi v20, v12, 2

    # SM3 rounds 2, 3, and 4, 5
    # rnds=0 means SM3 rounds 1 and 2, rnds=1 means SM3 rounds 4 and 5
    vsm3c.vi v4, v12, 0  # Consumes {w5,w4,w1,w0}
    vsm3c.vi v4, v20, 1  # Consumes {w7,w6,w3,w2}

    #  v20 <- {_, _, _, _, w7, w6, w5, w4}   (where _ may be random values)
    vslidedown.vi v20, v20, 2
    #  v24 <- {w11, w10, w9, w8, 0, 0, 0, 0}
    vslideup.vi v24, v16, 4
    # Merge the registers.
    #  v20 <- {w11, w10, w9, w8, w7, w6, w5, w4}
    vmerge.vvm v20, v24, v20, v0   # v20[i] = v0.mask[i] ? v20[i] : v24[i]

    # SM3 rounds 6, 7
    vsm3c.vi v4, v20, 2  # Consumes {w9,w8,w5,w4}
    # v20 <- {_, _, w11, w10, w9, w8, w7, w6}
    vslidedown.vi v20, v20, 2
    # SM3 rounds 8, 9
    vsm3c.vi v4, v20, 3  # Consumes {w11,w10,w7,w6}

    # SM3 rounds 10, 11, and 12,13
    vsm3c.vi v4, v16, 4  # Consumes {w13,w12,w9,w8}
    #  v20 <- {_,_, w15,w14,w13,w12,w11,w10}
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 5   # Consumes {w15,w14,w11,w10}

    # v12 <- {w23,w22,w21,w20,w19,w18,w17,w16}
    vsm3me.vv v12, v16, v12

    #  v20 <- {_,_, _,_,w15,w14,w13,w12}
    vslidedown.vi v20, v20, 2
    #  v24 <- {w19,w18,w17,w16,0,0,0,0}
    vslideup.vi v24, v12, 4
    # v20 <- {w19, w18, w17, w16, w15, w14, w13, w12}
    vmerge.vvm v20, v24, v20, v0  # Bottom 4 from v20, rest from v24

    # SM3 rounds 14,15, and 16,17
    vsm3c.vi v4, v20, 6  # Consumes {w17,w16,w13,w12}
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 7  # Consumes {w19,w18,w15,w14}

    # SM3 rounds 18,19, and 20,21
    vsm3c.vi v4, v12, 8  # Consumes {w21,w20,w17,w16}
    # v20 <- {_,_,w23,w22,w21,w20,w19,w18}
    vslidedown.vi v20, v12, 2
    vsm3c.vi v4, v20, 9  # Consumes {w23,w22,w19,w18}

    # v16 <- {w31,w30,w29,w28,w27,26,w25,w24}
    vsm3me.vv v16, v12, v16

    # Prepare a register with {w27, w26, w25, w24, w23, w22, w21, w20}
    # v20 <- {_,_,w23,w22,w21,w20}
    vslidedown.vi v20, v20, 2
    # v24 <- {w27,w26,w25,w24,0,0,0,0}
    vslideup.vi v24, v16, 4
    # v20 <- {w27,w26,w25,w24,w23,w22,w21,w20}
    vmerge.vvm v20, v24, v20, v0

    # SM3 rounds 22,23, and 24,25
    vsm3c.vi v4, v20, 10  # Consumes {w25,w24,w21,w20}
    # v20 <- {_,_,w27,w26,w25,w24,w23,w22}
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 11  # Consumes {w27,w26,w23,w22}

    # SM3 rounds 26,27, and 28,29
    vsm3c.vi v4, v16, 12  # Consumes {w29,w28,w25,w24}
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 13  # Consumes {w31,w30,w27,w26}

    # v12 <- {w39,w38,w37,w36,w35,w34,w33,w32}
    vsm3me.vv v12, v16, v12

    # Prepare a register with {w35, w34, w33, w32, w31, w30, w29, w28}
    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 14
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 15

    vsm3c.vi v4, v12, 16
    vslidedown.vi v20, v12, 2
    vsm3c.vi v4, v20, 17

    vsm3me.vv v16, v12, v16

    # Prepare a register with {w43, w42, w41, w40, w39, w38, w37, w36}
    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v16, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 18
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 19

    vsm3c.vi v4, v16, 20
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 21

    vsm3me.vv v12, v16, v12

    # Prepare a register with {w51, w50, w49, w48, w47, w46, w45, w44}
    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 22
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 23

    vsm3c.vi v4, v12, 24
    vslidedown.vi v20, v12, 2
    vsm3c.vi v4, v20, 25

    vsm3me.vv v16, v12, v16

    # Prepare a register with {w59, w58, w57, w56, w55, w54, w53, w52}
    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v16, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 26
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 27

    vsm3c.vi v4, v16, 28
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 29

    vsm3me.vv v12, v16, v12

    # Prepare a register with {w67, w66, w65, w64, w63, w62, w61, w60}
    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 30
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 31

    # H' = H xor {h,g,f,e,d,c,b,a}
    vxor.vv v4, v8, v4

    bnez a2, 1b     # Loop if there are more blocks.

    vse32.v v4, (a0)
    ret


# zvksh_sm3_encode_lmul2
#
# This routine is identical to the lmul1 version, except for the use of LMUL=2.
# It requires VLEN>=128.
#
.balign 4
.global zvksh_sm3_encode_lmul2
zvksh_sm3_encode_lmul2:
    # m2: LMUL=2
    vsetivli x0, 8, e32, m2, ta, ma

    la t6, IV
    vle32.v v4, (t6)

    vid.v v0
    vmsleu.vi v0, v0, 0x3

1:
    add a2, a2, -64
    vmv.v.v v8, v4

    vle32.v v12, (a1)
    add a1, a1, 32
    vle32.v v16, (a1)
    add a1, a1, 32
    vslidedown.vi v20, v12, 2

    vsm3c.vi v4, v12, 0
    vsm3c.vi v4, v20, 1

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v16, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 2
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 3

    vsm3c.vi v4, v16, 4
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 5

    vsm3me.vv v12, v16, v12

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 6
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 7

    vsm3c.vi v4, v12, 8
    vslidedown.vi v20, v12, 2
    vsm3c.vi v4, v20, 9

    vsm3me.vv v16, v12, v16

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v16, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 10
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 11

    vsm3c.vi v4, v16, 12
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 13

    vsm3me.vv v12, v16, v12

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 14
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 15

    vsm3c.vi v4, v12, 16
    vslidedown.vi v20, v12, 2
    vsm3c.vi v4, v20, 17

    vsm3me.vv v16, v12, v16

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v16, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 18
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 19

    vsm3c.vi v4, v16, 20
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 21

    vsm3me.vv v12, v16, v12

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 22
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 23

    vsm3c.vi v4, v12, 24
    vslidedown.vi v20, v12, 2
    vsm3c.vi v4, v20, 25

    vsm3me.vv v16, v12, v16

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v16, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 26
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 27

    vsm3c.vi v4, v16, 28
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 29

    vsm3me.vv v12, v16, v12

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 30
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 31

    vxor.vv v4, v8, v4

    bnez a2, 1b

    vse32.v v4, (a0)
    ret


# zvksh_sm3_encode_lmul4
#
# This routine is identical to the lmul1 version, except for the use of LMUL=4.
# It requires VLEN>=64.
#
.balign 4
.global zvksh_sm3_encode_lmul4
zvksh_sm3_encode_lmul4:
    # m4: LMUL=4
    vsetivli x0, 8, e32, m4, ta, ma

    la t6, IV
    vle32.v v4, (t6)

    vid.v v0
    vmsleu.vi v0, v0, 0x3

1:
    add a2, a2, -64
    vmv.v.v v8, v4

    vle32.v v12, (a1)
    add a1, a1, 32
    vle32.v v16, (a1)
    add a1, a1, 32
    vslidedown.vi v20, v12, 2

    vsm3c.vi v4, v12, 0
    vsm3c.vi v4, v20, 1

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v16, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 2
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 3

    vsm3c.vi v4, v16, 4
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 5

    vsm3me.vv v12, v16, v12

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 6
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 7

    vsm3c.vi v4, v12, 8
    vslidedown.vi v20, v12, 2
    vsm3c.vi v4, v20, 9

    vsm3me.vv v16, v12, v16

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v16, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 10
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 11

    vsm3c.vi v4, v16, 12
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 13

    vsm3me.vv v12, v16, v12

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 14
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 15

    vsm3c.vi v4, v12, 16
    vslidedown.vi v20, v12, 2
    vsm3c.vi v4, v20, 17

    vsm3me.vv v16, v12, v16

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v16, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 18
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 19

    vsm3c.vi v4, v16, 20
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 21

    vsm3me.vv v12, v16, v12

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 22
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 23

    vsm3c.vi v4, v12, 24
    vslidedown.vi v20, v12, 2
    vsm3c.vi v4, v20, 25

    vsm3me.vv v16, v12, v16

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v16, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 26
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 27

    vsm3c.vi v4, v16, 28
    vslidedown.vi v20, v16, 2
    vsm3c.vi v4, v20, 29

    vsm3me.vv v12, v16, v12

    vslidedown.vi v20, v20, 2
    vslideup.vi v24, v12, 4
    vmerge.vvm v20, v24, v20, v0

    vsm3c.vi v4, v20, 30
    vslidedown.vi v20, v20, 2
    vsm3c.vi v4, v20, 31

    vxor.vv v4, v8, v4

    bnez a2, 1b

    vse32.v v4, (a0)
    ret


# Note that we don't define a LMUL=8 variant. The core logic uses 7 register
# groups. We can easily save 1 register by storing the previous state in memory
# and reloading for the final XOR. This still leaves us two groups short
# to simply use LMUL=8 without significant logic changes.

