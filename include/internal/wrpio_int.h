//
// Created by Ghost on 2019/10/21.
//

#ifndef CRYPTO_FRAMEWORK_WRPIO_INT_H
#define CRYPTO_FRAMEWORK_WRPIO_INT_H

#include "wrpio.h"
#include "typedef.h"
#include "err.h"

struct wrpio_meth_st {
    uint32_t ctx_size;
    ERRNO (*init)(WRPIO *);
    ERRNO (*write)(WRPIO *, uint8_t *buf, uint32_t len);
    ERRNO (*read)(WRPIO *, uint8_t *buf, uint32_t *len);
    ERRNO (*flush)(WRPIO *);
    ERRNO (*ctrl)(WRPIO *, uint32_t flag, void *ptr, uint32_t len);
    void (*cleanup)(WRPIO *);
};

struct wrpio_st {
    const WRPIO_METH *meth;
    uint8_t mode;
    char target[WRPIO_MAX_TARGET_LENGTH + 1];
    void *meth_data;
};

#endif //CRYPTO_FRAMEWORK_WRPIO_INT_H
