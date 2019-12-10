//
// Created by Ghost on 2019/10/25.
//

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "wrp.h"
#include "internal/wrp_int.h"
#include "random/sys_random.h"

WRP_KEY_CTX *WRP_KEY_CTX_new() {

    WRP_KEY_CTX *ctx = malloc(sizeof(WRP_KEY_CTX));
    ctx->key = NULL;
    ctx->bits = 0;
    ctx->key_data = NULL;
    ctx->flag = 0;
    ctx->use_count = 0;
    memset(ctx->random_pool, 0, WRP_MAX_RANDPOOL_LENGTH);
    memset(ctx->seed, 0, WRP_MAX_KEY_LENGTH);
    return ctx;
}

ERRNO WRP_KEY_init(WRP_KEY_CTX *ctx, const WRP_KEY *key, uint32_t bits) {
    if (ctx == NULL || key == NULL) return ERRNO_WRP_NULL_CTX;
    if (key->genkey == NULL || key->rng == NULL || key->getkey == NULL) return ERRNO_WRP_KEY_INVALID;
    if (ctx->key != NULL && ctx->key_data != NULL && ctx->key->cleanup != NULL) ctx->key->cleanup(ctx);
    ctx->key = key;
    ctx->bits = bits;
    ctx->key->rng(ctx, ctx->random_pool, WRP_MAX_RANDPOOL_LENGTH);
    if (ctx->key_data) free(ctx->key_data);
    if (ctx->key->ctx_size > 0) ctx->key_data = malloc(ctx->key->ctx_size);
    memset(ctx->key_data, 0, ctx->key->ctx_size);
    return key->init(ctx);
}

ERRNO WRP_KEY_genkey(WRP_KEY_CTX *ctx) {
    
    ERRNO ret;
    if (ctx == NULL || ctx->key == NULL) return ERRNO_WRP_NULL_CTX;
    ret = ctx->key->genkey(ctx);
    if(ctx->key->rng(ctx, ctx->random_pool, WRP_MAX_RANDPOOL_LENGTH) != 0) return ERRNO_WRP_KEY_RANDOM_GENERATOR_ERR;
    return ret;
}

ERRNO WRP_KEY_set_key(WRP_KEY_CTX *ctx, uint8_t *data, uint32_t data_len, uint32_t mode) {
    ERRNO ret;
    if (ctx == NULL || ctx->key == NULL) return ERRNO_WRP_NULL_CTX;
    ret = ctx->key->setkey(ctx, data, data_len, mode);
    return ret;
}


ERRNO WRP_KEY_get_key(WRP_KEY_CTX *ctx, uint8_t *data, uint32_t *data_len, uint32_t mode) {
    ERRNO ret;
    if (ctx == NULL || ctx->key == NULL) return ERRNO_WRP_NULL_CTX;
    ret = ctx->key->getkey(ctx, data, data_len, mode);
    return ret;
}

ERRNO WRP_KEY_key_len(WRP_KEY_CTX *ctx, uint32_t mode) {
    if (ctx == NULL || ctx->key == NULL || ctx->key->getlen) return ERRNO_WRP_NULL_CTX;
    return ctx->key->getlen(ctx, mode);
}

#ifndef CRYPTOLIB_NO_WRPIO
LIB_API ERRNO WRP_KEY_import(WRP_KEY_CTX *ctx, const char *target, uint32_t mode) {
    WRPIO *io;
    ERRNO ret;
    if (ctx == NULL) return ERRNO_WRP_NULL_CTX;

    io = WRPIO_new();
    ret = ctx->key->import(ctx, io, target, mode);
    WRPIO_free(io);
    return ret;
}


ERRNO WRP_KEY_export(WRP_KEY_CTX *ctx, const char *target, uint32_t mode) {
    WRPIO *io;
    ERRNO ret;
    if (ctx == NULL || ctx->key == NULL) return ERRNO_WRP_NULL_CTX;

    io = WRPIO_new();
    ret = ctx->key->export(ctx, io, target, mode);
    WRPIO_free(io);
    return ret;
}
#endif

uint32_t WRP_KEY_get_uid(WRP_KEY_CTX *ctx) {
    return ctx == NULL || ctx->key == NULL ? 0 : ctx->key->uid;
}

ERRNO WRP_KEY_ctrl(WRP_KEY_CTX *ctx, uint32_t ctrl_flag, void *data, uint32_t data_len) {
    if (ctx == NULL || ctx->key == NULL) return ERRNO_WRP_NULL_CTX;

    switch (ctrl_flag) {

        case WRP_KEY_CTRL_TYPE_set_seed: {
            if (data == NULL || data_len == 0) return ERRNO_NULLPTR;
            if (data_len > WRP_MAX_KEY_LENGTH)
                return ERRNO_WRP_KEY_MAX_SEED_REACH;
			if (data_len < ctx->bits/8)
				return ERRNO_WRP_BUF_TOO_SMALL;
            memcpy(ctx->seed, data, data_len);
            WRP_KEY_set_flag(ctx, WRP_KEY_FLAG_HAS_SEED, 1);
            return ERRNO_OK;    
        }

        case WRP_KEY_CTRL_INCREASE_USE_COUNT: {
            ctx->use_count++;
            return ERRNO_OK;
        }

        case WRP_KEY_CTRL_DECREASE_USE_COUNT: {
            if (ctx->use_count != 0) ctx->use_count--;
            if (WRP_KEY_get_flag(ctx, WRP_KEY_FLAG_FREE_AFTER_USE) && ctx->use_count == 0)
                WRP_KEY_CTX_free(ctx);
            return ERRNO_OK;
        }

        default:
            if (ctx->key->ctrl) return ctx->key->ctrl(ctx, ctrl_flag, data_len, data);
            else return ERRNO_WRP_CTRL_NOT_SUPPORT;
    }
}

uint8_t WRP_KEY_get_flag(WRP_KEY_CTX *ctx, uint32_t flag) {
    if (ctx == NULL) return 0;
    return ctx->flag & flag;
}

void WRP_KEY_set_flag(WRP_KEY_CTX *ctx, uint32_t flag, uint32_t val) {
    if (ctx == NULL) return;
    if (val == 0) ctx->flag &= ~flag;
    else ctx->flag |= flag;
}

void WRP_KEY_CTX_free(WRP_KEY_CTX *ctx) {
    if (ctx == NULL) return;

    WRP_KEY_set_flag(ctx, WRP_KEY_FLAG_FREE_AFTER_USE, 1);
    if (ctx->use_count > 0) return;

    if (ctx->key && ctx->key->cleanup) {
        ctx->key->cleanup(ctx);
    }

    memset(ctx->random_pool, 0, WRP_MAX_RANDPOOL_LENGTH);
    memset(ctx->seed, 0, WRP_MAX_KEY_LENGTH);
    if (ctx->key->ctx_size > 0) free(ctx->key_data);
    free(ctx);
}