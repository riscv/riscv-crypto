
#ifndef __AES_COMMON_S__
#define __AES_COMMON_S__

//
// Rotate value in RS1 right by IMM. Use TMP as scratch register.
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
.macro AES_LOAD_STATE T0, T1, T2, T3, CK, X0, X1, X2, X3

#if ((AES_BYTE_ALIGNED == 1) || (defined(AES_BYTE_ALIGNED)))

    lbu     \T0,  3(\CK)
    lbu     \T1,  7(\CK)
    lbu     \T2, 11(\CK)
    lbu     \T3, 15(\CK)
    slli    \T0,\T0, 8
    slli    \T1,\T1, 8
    slli    \T2,\T2, 8
    slli    \T3,\T3, 8
    lbu     \X0,  2(\CK)
    lbu     \X1,  6(\CK)
    lbu     \X2, 10(\CK)
    lbu     \X3, 14(\CK)
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    or      \T2, \T2, \X2
    or      \T3, \T3, \X3
    slli    \T0,\T0, 8
    slli    \T1,\T1, 8
    slli    \T2,\T2, 8
    slli    \T3,\T3, 8
    lbu     \X0,  1(\CK)
    lbu     \X1,  5(\CK)
    lbu     \X2,  9(\CK)
    lbu     \X3, 13(\CK)
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    or      \T2, \T2, \X2
    or      \T3, \T3, \X3
    slli    \T0,\T0, 8
    slli    \T1,\T1, 8
    slli    \T2,\T2, 8
    slli    \T3,\T3, 8
    lbu     \X0,  0(\CK)
    lbu     \X1,  4(\CK)
    lbu     \X2,  8(\CK)
    lbu     \X3, 12(\CK)
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    or      \T2, \T2, \X2
    or      \T3, \T3, \X3

#else

    lw      \T0, 0(\CK)
    lw      \T1, 4(\CK)
    lw      \T2, 8(\CK)
    lw      \T3,12(\CK)

#endif

.endm

//
// Dump the AES state from column-wise registers into a byte-aligned array.
//
.macro AES_DUMP_STATE T0, T1, T2, T3, CT

#if ((AES_BYTE_ALIGNED == 1) || (defined(AES_BYTE_ALIGNED)))

    sb      \T0,  0(\CT)
    sb      \T1,  4(\CT)
    sb      \T2,  8(\CT)
    sb      \T3, 12(\CT)
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    sb      \T0,  1(\CT)
    sb      \T1,  5(\CT)
    sb      \T2,  9(\CT)
    sb      \T3, 13(\CT)
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    sb      \T0,  2(\CT)
    sb      \T1,  6(\CT)
    sb      \T2, 10(\CT)
    sb      \T3, 14(\CT)
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    sb      \T0,  3(\CT)
    sb      \T1,  7(\CT)
    sb      \T2, 11(\CT)
    sb      \T3, 15(\CT)

#else

    sw      \T0, 0(\CT)
    sw      \T1, 4(\CT)
    sw      \T2, 8(\CT)
    sw      \T3,12(\CT)
    
#endif

.endm

#endif // __AES_COMMON_S__
