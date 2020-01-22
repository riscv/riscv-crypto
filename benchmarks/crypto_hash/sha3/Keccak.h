/*
Implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
hereby denoted as "the implementer".

For more information, feedback or questions, please refer to our website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <stdint.h>
#include <string.h>

#ifndef __KECCAK_H__


/*!
@brief Function to compute the Keccak[r, c] sponge function over a given input.
@param  rate            The value of the rate r.
@param  capacity        The value of the capacity c.
@param  input           Pointer to the input message.
@param  inputByteLen    The number of input bytes provided in the input message.
@param  delimitedSuffix Bits that will be automatically appended to the end
                        of the input message, as in domain separation.
                        This is a byte containing from 0 to 7 bits
                        These <i>n</i> bits must be in the least significant bit positions
                        and must be delimited with a bit 1 at position <i>n</i>
                        (counting from 0=LSB to 7=MSB) and followed by bits 0
                        from position <i>n</i>+1 to position 7.
                        Some examples:
                            - If no bits are to be appended, then @a delimitedSuffix must be 0x01.
                            - If the 2-bit sequence 0,1 is to be appended (as for SHA3-*), @a delimitedSuffix must be 0x06.
                            - If the 4-bit sequence 1,1,1,1 is to be appended (as for SHAKE*), @a delimitedSuffix must be 0x1F.
                            - If the 7-bit sequence 1,1,0,1,0,0,0 is to be absorbed, @a delimitedSuffix must be 0x8B.
@param  output          Pointer to the buffer where to store the output.
@param  outputByteLen   The number of output bytes desired.
@pre    One must have r+c=1600 and the rate a multiple of 8 bits in this implementation.
  */
void Keccak(
    unsigned int rate,
    unsigned int capacity,
    const unsigned char *input,
    unsigned long long int inputByteLen,
    unsigned char delimitedSuffix,
    unsigned char *output,
    unsigned long long int outputByteLen
);

#endif
