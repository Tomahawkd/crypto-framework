//
// Created by Ghost on 2019/10/21.
//

#include "wrpio.h"
#include "internal/wrpio_int.h"
#include <stdlib.h>
#include <string.h>

WRPIO *WRPIO_new() {
    WRPIO *io;
    io = malloc(sizeof(WRPIO));
    io->meth = NULL;
    io->meth_data = NULL;
    memset(io->target, 0, WRPIO_MAX_TARGET_LENGTH);

    return io;
}

ERRNO WRPIO_init(WRPIO *io, const WRPIO_METH *method, const char *target, uint8_t mode) {

    if (io == NULL || method == NULL) return ERRNO_WRPIO_NULLPTR;
    if (strlen(target) > WRPIO_MAX_TARGET_LENGTH) return ERRNO_WRPIO_MAX_LENGTH_REACHED;
    io->meth = method;
    if(target != NULL) strncpy(io->target, target, WRPIO_MAX_TARGET_LENGTH - 1);
    io->mode = mode;
    if (io->meth_data) free(io->meth_data);
    if (method->ctx_size > 0) io->meth_data = malloc(method->ctx_size);
    return method->init(io);
}

ERRNO WRPIO_write(WRPIO *io, uint8_t *data, uint32_t datalen) {
    if (io == NULL || io->meth == NULL) return ERRNO_WRPIO_NULLPTR;
    if (io->meth->write == NULL) return ERRNO_WRPIO_ACTION_NOT_SUPPORT;
    if (io->target[0] == 0) return ERRNO_WRPIO_FILE_ERR;
    return io->meth->write(io, data, datalen);
}

ERRNO WRPIO_read(WRPIO *io, uint8_t *buff, uint32_t *len) {
    if (io == NULL || io->meth == NULL) return ERRNO_WRPIO_NULLPTR;
    if (io->meth->read == NULL) return ERRNO_WRPIO_ACTION_NOT_SUPPORT;
    if (io->target[0] == 0) return ERRNO_WRPIO_FILE_ERR;
    return io->meth->read(io, buff, len);
}

ERRNO WRPIO_flush(WRPIO *io) {
    if (io == NULL || io->meth == NULL) return ERRNO_WRPIO_NULLPTR;
    if (io->meth->flush == NULL) return ERRNO_WRPIO_ACTION_NOT_SUPPORT;
    if (io->target[0] == 0) return ERRNO_WRPIO_FILE_ERR;
    return io->meth->flush(io);
}

ERRNO WRPIO_ctrl(WRPIO *io, uint32_t flag, void *ptr, uint32_t len) {
    if (io == NULL) return ERRNO_WRPIO_NULLPTR;
    if (io->meth->ctrl == NULL) return ERRNO_WRPIO_ACTION_NOT_SUPPORT;
    else return io->meth->ctrl(io, flag, ptr, len);
}

void WRPIO_free(WRPIO *io) {
    if (io == NULL || io->meth == NULL) return;

    if (io->meth->cleanup) io->meth->cleanup(io);
    if (io->meth->ctx_size > 0) free(io->meth_data);
    free(io);
}
