//
// Created by Ghost on 2019/9/23.
//

#ifndef CRYPTO_FRAMEWORK_ERR_H
#define CRYPTO_FRAMEWORK_ERR_H

#include <stdint.h>

typedef uint32_t ERRNO;

//====== Basic error codes
#define ERRNO_OK                0x00000000 // ok
#define ERRNO_UNKNOWN           0x00000001 // unknown error
#define ERRNO_NULLPTR           0x00000002
#define ERRNO_INVALID_BLOCK     0x00000003
#define ERRNO_MALLOC_ERROR      0x00000004
#define ERRNO_ALG_NOTSUPPORT    0x00000005

// other error codes offset
#define ERRNO_WRP_MASK          0x01000000
#define ERRNO_WRPIO_MASK        0x04000000


#endif //CRYPTO_FRAMEWORK_ERR_H
