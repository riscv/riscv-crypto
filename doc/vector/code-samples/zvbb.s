# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# The Zvbb extension contains vectorized bit manipulation operations AND-NOT
# (vandn), rotate left (vrol), and rotate right (vror).
#
# Those routines are vector-length (VLEN) agnostic, only requiring
# that VLEN is a multiple of 64. Smaller VLENs should work when using
# LMUL>1, but this is not exercised here.
#
# This code was developed to validate the design of the Zvbb extension, and to
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

.text

######################################################################
# Vector AND-NOT routines (8 bits)
######################################################################

# zvbb_vandn8_vv
#
# Takes two byte vectors vs2, vs1, and their number of elements (bytes)
# 'n' as inputs, sets destination vector to (vs1 & (!vs2))
#
# The vectors are treated as vectors of bytes. Given the bitwise
# nature of vandn we could set them with other element widths.
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vandn8_vv(
#       uint8_t* dest,          // a0
#       const uint8_t* vs2,     // a1
#       const uint8_t* vs1,     // a2
#       uint64_t n              // a3
#   );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvbb_vandn8_vv
zvbb_vandn8_vv:
    mv t1, a3  # Save 'n' to return later.
    xor x0, x0, x0
1:
    vsetvli t0, a3, e8, m1, ta, ma # Set vector length based on 8-bit vectors
    vle8.v v2, (a1) # load vs2
    vle8.v v1, (a2) # load vs1

    vandn.vv v0, v2, v1   # v0 = vs1 &~ vs2
    vse8.v v0, (a0) # store in dest

    sub a3, a3, t0 # decrement number of elements done
    add a1, a1, t0 # bump pointer
    add a2, a2, t0 # bump pointer
    add a0, a0, t0 # bump pointer
    bnez a3, 1b

    mv a0, t1
    ret

# zvbb_vandn8_vx
#
# Takes one 'n' byte-length vectors vs2 and a register rs1 as input,
# sets destination vector to (rs1 & (!vs2))
#
# 'n' should be a multiple of 16 bytes (128b).
# The vectors are treated as 8-bit vectors here.
# In later implementations, this will change
#
# Returns the number of bytes processed, which is 'n' when 'n'
# is a multiple of 16, and  floor(n/16)*16 otherwise.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vandn8_vx(
#       uint8_t* dest,        // a0
#       const uint64_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#   );
#  a0=dest, a1=vs2, a2 = rs1, a3 = n
#
.balign 4
.global zvbb_vandn8_vx
zvbb_vandn8_vx:
    mv t1, a3  # Save 'n' to return later.
1:
    vsetvli t0, a3, e8, m1,ta,ma # Set vector length based on 8-bit vectors
    vle8.v v2, (a1) # load vs2

    vandn.vx v0, v2, a2   # v0 = rs1 &~ v2
    vse8.v v0, (a0) # store in dest

    sub a3, a3, t0 # decrement number of elements done
    add a1, a1, t0 # bump pointer
    add a0, a0, t0 # bump pointer
    bnez a3, 1b

    mv a0, t1
    ret

######################################################################
# Vector Rotate Left routines
######################################################################

# zvbb_vrol_vv
#
# Takes two vectors of uint64_t elements vs2, vs1 as input,
# a number of (64 bit) elements 'n', sets destination vector
# to vrol(vs1, vs2)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vrol_vv(
#       void* dest,          // a0
#       const void* vs2,     // a1
#       const void* vs1,     // a2
#       size_t n             // a3
#   );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvbb_vrol_vv
zvbb_vrol_vv:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vle64.v v1, (a2) # get vs1
    vrol.vv v0, v2, v1  # vd vs2 vs1
    vse64.v v0, (a0)

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a3, a3, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a2, a2, t0
    add a0, a0, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvbb_vrol_vx
#
# Takes a vector of uint64_t elements vs2, a scalar rs1,
# and a number of (64 bit) elements 'n' as inputs,
# sets destination vector to vrol(vs2, rs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vrol_vx(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#   );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvbb_vrol_vx
zvbb_vrol_vx:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vrol.vx v0, v2, a2  # vd vs2 rs1
    vse64.v v0, (a0)

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a3, a3, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a3, 1b

    mv a0, t1
    ret

######################################################################
# Vector Rotate Right routines
######################################################################

# zvbb_vror_vv
#
# Takes two vectors of uint64_t elements vs2, vs1 as input,
# a number of (64 bit) elements 'n', sets destination vector
# to vror(vs1, vs2)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vror_vv(
#       void* dest,          // a0
#       const void* vs2,     // a1
#       const void* vs1,     // a2
#       size_t n             // a3
#   );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvbb_vror_vv
zvbb_vror_vv:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vle64.v v1, (a2) # get vs1
    vror.vv v0, v2, v1  # vd vs2 vs1
    vse64.v v0, (a0)

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a3, a3, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a2, a2, t0
    add a0, a0, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvbb_vror_vx
#
# Takes a vector of uint64_t elements vs2, a scalar rs1,
# and a number of (64 bit) elements 'n' as inputs,
# sets destination vector to vror(vs2, rs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vror_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#   );
#  a0=dest, a1=vs2, a2 = rs1, a3 = n
#
.balign 4
.global zvbb_vror_vx
zvbb_vror_vx:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vror.vx v0, v2, a2  # vd vs2 rs1
    vse64.v v0, (a0)

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a3, a3, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvbb_vror_vi56
#
# Takes a vector of uint64_t elements vs2, and a number of (64 bit)
# elements 'n' as inputs, sets destination vector to vror(vs2, 56).
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vror_vi56(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       size_t n              // a2
#   );
#  a0=dest, a1=vs2, a2 = n
#
.balign 4
.global zvbb_vror_vi56
zvbb_vror_vi56:
    mv t1, a2
1:
    vsetvli t0, a2, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vror.vi v0, v2, 56  # vd vs2 56
    vse64.v v0, (a0)

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a2, a2, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret

######################################################################
# Vector Bits/Bytes Reversal routines
######################################################################

# zvbb_vbrev_v
#
# Takes a vector of uint64_t elements vs2, and a number of (64 bit)
# elements 'n' as inputs, sets destination vector to vbrev(vs2)
# The last parameter sets the SEW to use.
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vbrev_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       size_t n              // a2
#       size_t sew            // a3
#   );
#  a0=dest, a1=vs2, a2 = n, a3 = sew
#
.balign 4
.global zvbb_vbrev_v
zvbb_vbrev_v:
    mv t1, a2
    li t2, 64
    div t2, t2, a3 # Determine SEW element scaler
    mul a2, a2, t2 # Scale number of elements according to SEW
1:
.vbrev_sew8:
    li t2, 8
    bne a3, t2, .vbrev_sew16
    vsetvli t0, a2, e8, m1, ta, ma
    vle8.v v2, (a1) # get vs2
    vbrev.v v0, v2  # vd vs2
    vse8.v v0, (a0) # put vs2
    li t3, 1 # bump size is 1 byte
    j .vbrev_do_loop
.vbrev_sew16:
    li t2, 16
    bne a3, t2, .vbrev_sew32
    vsetvli t0, a2, e16, m1, ta, ma
    vle16.v v2, (a1) # get vs2
    vbrev.v v0, v2  # vd vs2
    vse16.v v0, (a0) # put vs2
    li t3, 2 # bump size is 2 bytes
    j .vbrev_do_loop
.vbrev_sew32:
    li t2, 32
    bne a3, t2, .vbrev_sew64
    vsetvli t0, a2, e32, m1, ta, ma
    vle32.v v2, (a1) # get vs2
    vbrev.v v0, v2  # vd vs2
    vse32.v v0, (a0) # put vs2
    li t3, 4 # bump size is 4 bytes
    j .vbrev_do_loop
.vbrev_sew64:
    vsetvli t0, a2, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vbrev.v v0, v2  # vd vs2
    vse64.v v0, (a0) # put vs2
    li t3, 8 # bump size is 8 bytes

.vbrev_do_loop:
    # Bump the addresses by the number of bytes (#elts*sew/8) processed.
    sub a2, a2, t0
    mul t0, t0, t3
    add a1, a1, t0
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret

# zvbb_vrev8_v
#
# Takes a vector of uint64_t elements vs2, and a number of (64 bit)
# elements 'n' as inputs, sets destination vector to vrev8(vs2)
# The last parameter sets the SEW to use.
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vror_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       size_t n              // a2
#       size_t sew            // a3
#   );
#  a0=dest, a1=vs2, a2 = n, a3 = sew
#
.balign 4
.global zvbb_vrev8_v
zvbb_vrev8_v:
    mv t1, a2
    li t2, 64
    div t2, t2, a3 # Determine SEW element scaler
    mul a2, a2, t2 # Scale number of elements according to SEW
1:
.sew8:
    li t2, 8
    bne a3, t2, .sew16
    vsetvli t0, a2, e8, m1, ta, ma
    vle8.v v2, (a1) # get vs2
    vrev8.v v0, v2  # vd vs2
    vse8.v v0, (a0) # put vs2
    li t3, 1 # bump size is 1 byte
    j .do_loop
.sew16:
    li t2, 16
    bne a3, t2, .sew32
    vsetvli t0, a2, e16, m1, ta, ma
    vle16.v v2, (a1) # get vs2
    vrev8.v v0, v2  # vd vs2
    vse16.v v0, (a0) # put vs2
    li t3, 2 # bump size is 2 bytes
    j .do_loop
.sew32:
    li t2, 32
    bne a3, t2, .sew64
    vsetvli t0, a2, e32, m1, ta, ma
    vle32.v v2, (a1) # get vs2
    vrev8.v v0, v2  # vd vs2
    vse32.v v0, (a0) # put vs2
    li t3, 4 # bump size is 4 bytes
    j .do_loop
.sew64:
    vsetvli t0, a2, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vrev8.v v0, v2  # vd vs2
    vse64.v v0, (a0) # put vs2
    li t3, 8 # bump size is 8 bytes

.do_loop:
    # Bump the addresses by the number of bytes (#elts*sew/8) processed.
    sub a2, a2, t0
    mul t0, t0, t3
    add a1, a1, t0
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret

# zvbb_vbrev8_v
#
# Takes a vector of uint64_t elements vs2, and a number of (64 bit)
# elements 'n' as inputs, sets destination vector to vbrev8(vs2).
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vror_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       size_t n              // a2
#   );
#  a0=dest, a1=vs2, a2 = n
#
.balign 4
.global zvbb_vbrev8_v
zvbb_vbrev8_v:
    mv t1, a2
1:
    vsetvli t0, a2, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vbrev8.v v0, v2  # vd vs2
    vse64.v v0, (a0) # put vs2

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a2, a2, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret

######################################################################
# Vector Leading/Trailing Zeros routines
######################################################################

# zvbb_vclz_v
#
# Takes a vector of uint64_t elements vs2, and a number of (64 bit)
# elements 'n' as inputs, sets destination vector to clz(vs2).
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vclz_v(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       size_t n              // a2
#   );
#  a0=dest, a1=vs2, a2 = n
#
.balign 4
.global zvbb_vclz_v
zvbb_vclz_v:
    mv t1, a2
1:
    vsetvli t0, a2, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vclz.v v0, v2  # vd vs2
    vse64.v v0, (a0) # put vs2

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a2, a2, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret

# zvbb_vctz_v
#
# Takes a vector of uint64_t elements vs2, and a number of (64 bit)
# elements 'n' as inputs, sets destination vector to ctz(vs2).
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vctz_v(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       size_t n              // a2
#   );
#  a0=dest, a1=vs2, a2 = n
#
.balign 4
.global zvbb_vctz_v
zvbb_vctz_v:
    mv t1, a2
1:
    vsetvli t0, a2, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vctz.v v0, v2  # vd vs2
    vse64.v v0, (a0) # put vs2

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a2, a2, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret

# zvbb_vcpop_v
#
# Takes a vector of uint64_t elements vs2, and a number of (64 bit)
# elements 'n' as inputs, sets destination vector to cpop(vs2).
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vcpop_v(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       size_t n              // a2
#   );
#  a0=dest, a1=vs2, a2 = n
#
.balign 4
.global zvbb_vcpop_v
zvbb_vcpop_v:
    mv t1, a2
1:
    vsetvli t0, a2, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vcpop.v v0, v2  # vd vs2
    vse64.v v0, (a0) # put vs2

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a2, a2, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret


# zvbb_vwsll32_vv
#
# Takes two input vectors of uint32_t elements 'vs2', and 'vs1',
# a destination vector of uint64_t elements 'dest' and computes
#   dest[i] = (uint64_t)vs2[i] << (vs1[i] & 0b1_1111)
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vwsll32_vv(
#       uint64_t* dest,       // a0
#       const uint32_t* vs2,  // a1
#       const uint32_t* vs1,  // a2
#       size_t n              // a3
#   );
#  a0=dest, a1=vs2, a2=vs1, a3 = n
#
.balign 4
.global zvbb_vwsll32_vv
zvbb_vwsll32_vv:
    mv t1, a3
1:
    vsetvli t0, a3, e32, m1, ta, ma
    vle32.v v2, (a1) # get vs2
    vle32.v v4, (a2) # get vs1
    vwsll.vv v8, v2, v4  # vd vs2 vs1
    vse64.v v8, (a0) # put vs2

    # Bump the input addresses by the number of bytes (#elts*4) processed.
    sub a3, a3, t0
    slli t0, t0, 2
    add a1, a1, t0
    add a2, a2, t0
    # Destination address is bumped by (#elts*8)
    slli t0, t0, 1
    add a0, a0, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvbb_vwsll32_vx
#
# Takes an input vectors of uint32_t elements 'vs2', a uint64_t scalar 'rs1',
# a destination vector of uint64_t elements 'dest' and computes
#   dest[i] = (uint64_t)vs2[i] << (rs1 & 0b1_1111))
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vwsll32_vx(
#       uint64_t* dest,       // a0
#       const uint32_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#   );
#  a0=dest, a1=vs2, a2=rs1, a3=n
#
.balign 4
.global zvbb_vwsll32_vx
zvbb_vwsll32_vx:
    mv t1, a3
1:
    vsetvli t0, a3, e32, m1, ta, ma
    vle32.v v2, (a1) # get vs2
    vwsll.vx v8, v2, a2  # vd vs2 rs1
    vse64.v v8, (a0) # put vs2

    # Bump the input addresses by the number of bytes (#elts*4) processed.
    sub a3, a3, t0
    slli t0, t0, 2
    add a1, a1, t0
    # Destination address is bumped by (#elts*8)
    slli t0, t0, 1
    add a0, a0, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvbb_vwsll32_vi15
#
# Takes an input vectors of uint32_t elements 'vs2',
# a destination vector of uint64_t elements 'dest' and computes
#   dest[i] = (uint64_t)vs2[i] << 15
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbb_vwsll32_vi15(
#       uint64_t* dest,       // a0
#       const uint32_t* vs2,  // a1
#       size_t n              // a2
#   );
#  a0=dest, a1=vs2, a2 = n
#
.balign 4
.global zvbb_vwsll32_vi15
zvbb_vwsll32_vi15:
    mv t1, a2
1:
    vsetvli t0, a2, e32, m1, ta, ma
    vle32.v v2, (a1) # get vs2
    vwsll.vi v8, v2, 15  # vd vs2 zimm5
    vse64.v v8, (a0) # put vs2

    # Bump the input addresses by the number of bytes (#elts*4) processed.
    sub a2, a2, t0
    slli t0, t0, 2
    add a1, a1, t0
    # Destination address is bumped by (#elts*8)
    slli t0, t0, 1
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret
