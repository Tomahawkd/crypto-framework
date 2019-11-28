//
// Created by Ghost on 2019/10/18.
//

#ifndef CRYPTO_FRAMEWORK_SYS_RANDOM_H
#define CRYPTO_FRAMEWORK_SYS_RANDOM_H

#include <stdint.h>
#include "cryptoconf.h"

#ifdef  __cplusplus
extern "C" {
#endif

LIB_API void randseed(uint32_t seed);

LIB_API void getrandombits(uint8_t *result, uint32_t length);

#ifdef  __cplusplus
}
#endif

#endif //CRYPTO_FRAMEWORK_SYS_RANDOM_H
