
#ifndef __AES_COMMON_S__
#define __AES_COMMON_S__

//
// Rotate value in RS1 right by IMM. Use TMP as scratch regiser.
// RD may equal RS1. TMP may not equal RD or RS1.
.macro ROR32I RD, TMP, RS1, IMM
    srli    \TMP, \RS1, \IMM
    slli    \RD , \RS1, (32-\IMM)
    or      \RD , \RD , \TMP
.endm

//
// Load the byte-aligned AES state from pointer in CK
// - Each column is loaded into the T* registers.
// - The X* registers are temps.
//
.macro AES_LOAD_STATE T0, T1, CK, X0, X1

#if ((AES_BYTE_ALIGNED == 1) || (defined(AES_BYTE_ALIGNED)))

    lbu     \T0,  7(\CK)
    lbu     \T1, 15(\CK)
    lbu     \X0,  6(\CK)
    lbu     \X1, 14(\CK)
    slli    \T0, \T0, 8
    slli    \T1, \T1, 8
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    lbu     \X0,  5(\CK)
    lbu     \X1, 13(\CK)
    slli    \T0, \T0, 8
    slli    \T1, \T1, 8
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    lbu     \X0,  4(\CK)
    lbu     \X1, 12(\CK)
    slli    \T0, \T0, 8
    slli    \T1, \T1, 8
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    lbu     \X0,  3(\CK)
    lbu     \X1, 11(\CK)
    slli    \T0, \T0, 8
    slli    \T1, \T1, 8
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    lbu     \X0,  2(\CK)
    lbu     \X1, 10(\CK)
    slli    \T0, \T0, 8
    slli    \T1, \T1, 8
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    lbu     \X0,  1(\CK)
    lbu     \X1,  9(\CK)
    slli    \T0, \T0, 8
    slli    \T1, \T1, 8
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    lbu     \X0,  0(\CK)
    lbu     \X1,  8(\CK)
    slli    \T0, \T0, 8
    slli    \T1, \T1, 8
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1

#else

    ld      \T0, 0(\CK)
    ld      \T1, 8(\CK)

#endif

.endm

//
// Dump the AES state from column-wise registers into a byte-aligned array.
//
.macro AES_DUMP_STATE T0, T1, CT, X0, X1, OFFSET

#if ((AES_BYTE_ALIGNED == 1) || (defined(AES_BYTE_ALIGNED)))

    sw      \T0, (\OFFSET + 0)(\CT)
    sw      \T1, (\OFFSET + 8)(\CT)
    srli    \X0, \T0, 32
    srli    \X1, \T1, 32
    sw      \X0, (\OFFSET + 4)(\CT)
    sw      \X1, (\OFFSET +12)(\CT)

#else

    sd      \T0, (\OFFSET + 0)(\CT)
    sd      \T1, (\OFFSET + 8)(\CT)
    
#endif

.endm

#endif // __AES_COMMON_S__
