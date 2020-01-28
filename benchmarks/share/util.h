
#ifndef __UTIL_H
#define __UTIL_H

#define STR(S) XSTR(S)
#define XSTR(S) #S

#define SHR(x,c) ((x) >> (c))
#define ROTR32(x,c) (((x) >> (c)) | ((x) << (32 - (c))))
#define ROTR64(x,c) (((x) >> (c)) | ((x) << (64 - (c))))

#define U8_TO_U32LE(x) (((uint32_t)(x[3]) << 24) | \
                        ((uint32_t)(x[2]) << 16) | \
                        ((uint32_t)(x[1]) <<  8) | \
                        ((uint32_t)(x[0]) <<  0) )

#endif

