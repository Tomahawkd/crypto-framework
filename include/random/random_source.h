//
// Created by Ghost on 2019/9/11.
//

#ifndef CRYPTO_FRAMEWORK_RANDOM_SOURCE_H
#define CRYPTO_FRAMEWORK_RANDOM_SOURCE_H

#include <stdint.h>
#include "cryptoconf.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Get random resource from external DRBGs/NRBGs/physical sources
 *  (in our implementation we use system call to get entropy,
 *  so that we need to use fixed length and ignore the prediction resistance flag)
 *  Be advised that the syscall limit the length the user get at once, you need to
 *  read the system doc about this. (For MacOS use getentropy, for Linux use syscall
 *  with flag SYS_getrandom)
 *
 * @param length bytes of result
 * @param result
 * @return result code
 */
LIB_API int get_entropy(uint8_t *result, uint32_t length);

#ifdef  __cplusplus
}
#endif

#endif //CRYPTO_FRAMEWORK_RANDOM_SOURCE_H
