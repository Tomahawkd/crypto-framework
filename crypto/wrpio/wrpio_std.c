//
// Created by Ghost on 2019/10/21.
//

#include "wrpio.h"
#include "internal/wrpio_int.h"
#include <stdio.h>

static ERRNO init(WRPIO *io) {
    // Due to test the target[0] whether is 0 in wrpio to detect err, we need to
    // set a non-0 here to avoid it
    io->target[0] = 1;
    return ERRNO_OK;
}

static ERRNO write(WRPIO *io, uint8_t *buf, uint32_t len) {
    if (len > fwrite(buf, 1, len, stdout)) return ERRNO_WRPIO_WRITE_ERR;
    return ERRNO_OK;
}

static ERRNO read(WRPIO *io, uint8_t *buf, uint32_t *len) {
    uint32_t real_len = fread(buf, 1, *len, stdin);

    if (*len > real_len) {
        if (feof(stdin)) {
            *len = real_len;
            return ERRNO_WRPIO_EOF_REACHED;
        } else return ERRNO_WRPIO_READ_ERR;
    } else return ERRNO_OK;
}

static ERRNO flush(WRPIO *io) {
    fflush(stdin);
    fflush(stdout);

    return ERRNO_OK;
}

static const WRPIO_METH std = {
        0,
        init,
        write,
        read,
        flush,
        NULL,
        NULL
};
const WRPIO_METH *WRPIO_std() {
    return &std;
}
