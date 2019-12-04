//
// Created by Ghost on 2019/10/21.
//

#ifndef CRYPTO_FRAMEWORK_WRPIO_H
#define CRYPTO_FRAMEWORK_WRPIO_H

#include "typedef.h"
#include "err.h"
#include "cryptoconf.h"
#include <stdint.h>

//#define ERRNO_WRPIO_MASK                  0x04000000
#define ERRNO_WRPIO_NULLPTR                 (ERRNO_WRPIO_MASK + 0x01)
#define ERRNO_WRPIO_ACTION_NOT_SUPPORT      (ERRNO_WRPIO_MASK + 0x02)
#define ERRNO_WRPIO_READ_ERR                (ERRNO_WRPIO_MASK + 0x03)
#define ERRNO_WRPIO_EOF_REACHED             (ERRNO_WRPIO_MASK + 0x04)
#define ERRNO_WRPIO_WRITE_ERR               (ERRNO_WRPIO_MASK + 0x05)
#define ERRNO_WRPIO_FILE_NULLPTR            (ERRNO_WRPIO_MASK + 0x06)
#define ERRNO_WRPIO_FILE_ERR                (ERRNO_WRPIO_MASK + 0x07)
#define ERRNO_WRPIO_UNKNOWN_MODE            (ERRNO_WRPIO_MASK + 0x08)
#define ERRNO_WRPIO_FILE_SEEK_ERR           (ERRNO_WRPIO_MASK + 0x09)
#define ERRNO_WRPIO_MAX_LENGTH_REACHED      (ERRNO_WRPIO_MASK + 0x0A)
#define ERRNO_WRPIO_ALGORITHM_NOT_SUPPORT   (ERRNO_WRPIO_MASK + 0x0B)

#define WRPIO_MODE_READ             0x01u
#define WRPIO_MODE_WRITE            0x02u
#define WRPIO_MODE_APPEND           0x04u
#define WRPIO_MODE_OVERWRITE        0x08u

#define WRPIO_CTRL_SET_TARGET       0x0001
#define WRPIO_CTRL_SET_OFFSET       0x0002
#define WRPIO_CTRL_REOPEN_FILE      0x0003
#define WRPIO_CTRL_SET_MODE         0x0004
#define WRPIO_CTRL_SET_PATH         0x0005
#define WRPIO_CTRL_SET_NAME         0x0006

#define WRPIO_MAX_TARGET_LENGTH     511
#define MODE_STR_MAX_LEN			5

#ifdef  __cplusplus
extern "C" {
#endif

LIB_API WRPIO *WRPIO_new();
LIB_API ERRNO WRPIO_init(WRPIO *io, const WRPIO_METH *method, const char *target, uint8_t mode);
LIB_API ERRNO WRPIO_write(WRPIO *io, uint8_t *data, uint32_t datalen);
LIB_API ERRNO WRPIO_read(WRPIO *io, uint8_t *buff, uint32_t *len);
LIB_API ERRNO WRPIO_flush(WRPIO *io);
LIB_API ERRNO WRPIO_ctrl(WRPIO *io, uint32_t flag, void *ptr, uint32_t len);
LIB_API void WRPIO_free(WRPIO *io);


// Basic implementation
LIB_API const WRPIO_METH *WRPIO_file(void);
LIB_API const WRPIO_METH *WRPIO_std(void);

// NOT implement yet
LIB_API const WRPIO_METH *WRPIO_socket();


#ifdef  __cplusplus
}
#endif

#endif //CRYPTO_FRAMEWORK_WRPIO_H
