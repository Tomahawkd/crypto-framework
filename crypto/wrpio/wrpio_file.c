//
// Created by Ghost on 2019/10/21.
//

#include "wrpio.h"
#include "internal/wrpio_int.h"
#include <stdio.h>
#include <string.h>

typedef struct wrpio_file_st {

    FILE *file;
    char mode_str[MODE_STR_MAX_LEN];

} WRPIO_FILE;

static ERRNO ctrl(WRPIO *io, uint32_t flag, void *ptr, uint32_t len);

static ERRNO init(WRPIO *io) {
    WRPIO_FILE *data = (WRPIO_FILE *) io->meth_data;

    memset(io->meth_data, 0, sizeof(WRPIO_FILE));

    // do not use fopen because the ctrl always reopen the file
    ctrl(io, WRPIO_CTRL_SET_MODE, NULL, io->mode);
    ctrl(io, WRPIO_CTRL_REOPEN_FILE, NULL, 0);
    if (data->file == NULL) return ERRNO_WRPIO_FILE_ERR;
    else return ERRNO_OK;
}

static ERRNO write(WRPIO *io, uint8_t *buf, uint32_t len) {

    WRPIO_FILE *data = (WRPIO_FILE *) io->meth_data;
    if (data->file == NULL) return ERRNO_WRPIO_FILE_NULLPTR;
    if (!(io->mode & WRPIO_MODE_WRITE)) return ERRNO_WRPIO_ACTION_NOT_SUPPORT;

    if (len > fwrite(buf, 1, len, data->file)) return ERRNO_WRPIO_WRITE_ERR;
    return ERRNO_OK;
}

static ERRNO read(WRPIO *io, uint8_t *buf, uint32_t *len) {

    WRPIO_FILE *data = (WRPIO_FILE *) io->meth_data;
    uint32_t real_len = 0;

    if (data->file == NULL) return ERRNO_WRPIO_FILE_NULLPTR;
    if (!(io->mode & WRPIO_MODE_READ)) return ERRNO_WRPIO_ACTION_NOT_SUPPORT;

    real_len = fread(buf, 1, *len, data->file);
    if (*len <= real_len) return ERRNO_OK;
    if (!feof(data->file)) return ERRNO_WRPIO_READ_ERR;
    *len = real_len;
    return ERRNO_WRPIO_EOF_REACHED;
}

static ERRNO flush(WRPIO *io) {
    WRPIO_FILE *data = (WRPIO_FILE *) io->meth_data;

    if (fflush(data->file) != 0) return ERRNO_WRPIO_FILE_ERR;
    else return ERRNO_OK;
}

static ERRNO ctrl(WRPIO *io, uint32_t flag, void *ptr, uint32_t len) {

    WRPIO_FILE *data = (WRPIO_FILE *) io->meth_data;
    uint32_t offset = 0;

    switch (flag) {

        case WRPIO_CTRL_SET_OFFSET: {
            if (ptr == NULL || len == 0) return ERRNO_WRPIO_NULLPTR;
            if (data->file == NULL) return ERRNO_WRPIO_FILE_NULLPTR;
            offset = *((uint32_t *)ptr);
            if (fseek(data->file, offset, SEEK_SET)) return ERRNO_WRPIO_FILE_SEEK_ERR;
            else return ERRNO_OK;
        }

        case WRPIO_CTRL_SET_TARGET: {
            if (ptr == NULL || len == 0) return ERRNO_WRPIO_NULLPTR;
            if (len > WRPIO_MAX_TARGET_LENGTH) return ERRNO_WRPIO_MAX_LENGTH_REACHED;

            memset(io->target, 0, WRPIO_MAX_TARGET_LENGTH);
            memcpy(io->target, ptr, len);

            return ERRNO_OK;
        }


        case WRPIO_CTRL_SET_MODE: {

            char mode_str[MODE_STR_MAX_LEN] = {0};
            uint8_t mode = (uint8_t) len;

            if (mode & WRPIO_MODE_APPEND) {
                mode_str[offset] = 'a';
                offset++;
                mode_str[offset] = 'b';
                offset++;
                if (mode & WRPIO_MODE_READ) {
                    mode_str[offset] = '+';
                }
            } else if ((mode & WRPIO_MODE_READ) && (mode & WRPIO_MODE_WRITE)) {
                if (mode & WRPIO_MODE_OVERWRITE) mode_str[offset] = 'w';
                else mode_str[offset] = 'r';
                offset++;
                mode_str[offset] = 'b';
                offset++;
                mode_str[offset] = '+';
            } else if (mode & WRPIO_MODE_WRITE) {
                mode_str[offset] = 'w';
                offset++;
                mode_str[offset] = 'b';
            } else if (mode & WRPIO_MODE_READ) {
                mode_str[offset] = 'r';
                offset++;
                mode_str[offset] = 'b';
            } else return ERRNO_WRPIO_UNKNOWN_MODE;

            io->mode = mode;
            memcpy(data->mode_str, mode_str, MODE_STR_MAX_LEN);
            return ERRNO_OK;
        }

        case WRPIO_CTRL_SET_PATH: {
            char tmp[WRPIO_MAX_TARGET_LENGTH] = {0};
            uint8_t need_slash;

            if (ptr == NULL || len == 0) return ERRNO_WRPIO_NULLPTR;

            need_slash = (((char *)ptr)[len - 1] == '/' ? 0 : 1);
            offset = strnlen(io->target, WRPIO_MAX_TARGET_LENGTH);
            while (offset > 0 && io->target[offset - 1] != '/') offset--;

            if (len + need_slash + strnlen(io->target + offset, WRPIO_MAX_TARGET_LENGTH) > WRPIO_MAX_TARGET_LENGTH) {
                return ERRNO_WRPIO_MAX_LENGTH_REACHED;
            }

            memcpy(tmp, ptr, len);
            if (need_slash) tmp[len] = '/';
            memcpy(tmp + need_slash + len, io->target + offset, strlen(io->target + offset));
            memcpy(io->target, tmp, WRPIO_MAX_TARGET_LENGTH);

            return ERRNO_OK;
        }

        case WRPIO_CTRL_SET_NAME: {
            char tmp[WRPIO_MAX_TARGET_LENGTH] = {0};

            if (ptr == NULL || len == 0) return ERRNO_WRPIO_NULLPTR;

            offset = strnlen(io->target, WRPIO_MAX_TARGET_LENGTH);
            while (offset > 0 && io->target[offset - 1] != '/') offset--;

            if (offset + len > WRPIO_MAX_TARGET_LENGTH) return ERRNO_WRPIO_MAX_LENGTH_REACHED;

            if(offset) memcpy(tmp, io->target, offset);
            memcpy(tmp + offset, ptr, len);
            memcpy(io->target, tmp, WRPIO_MAX_TARGET_LENGTH);

            return ERRNO_OK;
        }

        case WRPIO_CTRL_REOPEN_FILE: {
            if (data->file != NULL) fclose(data->file);
            data->file = fopen(io->target, data->mode_str);
            if (data->file == NULL) return ERRNO_WRPIO_FILE_ERR;
            else return ERRNO_OK;
        }

        default:
            return ERRNO_WRPIO_ACTION_NOT_SUPPORT;
    }
}

static void cleanup(WRPIO *io) {

    WRPIO_FILE *data = (WRPIO_FILE *) io->meth_data;
    if (data->file != NULL) fclose(data->file);
}

static const WRPIO_METH file = {
        sizeof(WRPIO_FILE),
        init,
        write,
        read,
        flush,
        ctrl,
        cleanup
};

const WRPIO_METH *WRPIO_file() {
    return &file;
}
