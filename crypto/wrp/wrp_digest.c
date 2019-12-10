//
// Created by Ghost on 2019/10/11.
//

#include <stdlib.h>
#include <string.h>
#include "wrp.h"
#include "internal/wrp_int.h"

WRP_DIGEST_CTX *WRP_DIGEST_CTX_new() {

    WRP_DIGEST_CTX *ctx = malloc(sizeof(WRP_DIGEST_CTX));
    ctx->digest = NULL;
    ctx->flag = 0;
    ctx->md_data = NULL;

    return ctx;
}

static void reset(WRP_DIGEST_CTX *ctx) {

    if (ctx == NULL || ctx->digest == NULL) return;

    if (!WRP_DIGEST_get_flag(ctx, WRP_FLAG_CLEANED) && ctx->digest->cleanup) ctx->digest->cleanup(ctx);
    if (ctx->digest->ctx_size > 0 && ctx->md_data) free(ctx->md_data);

    ctx->flag = 0;
    WRP_DIGEST_set_flag(ctx, WRP_FLAG_CLEANED, 1);
    ctx->md_data = NULL;
}

uint32_t WRP_DIGEST_get_len(const WRP_DIGEST_CTX *digest) {
    if (!digest || !digest->digest) return 0;
    return digest->digest->md_size;
}

ERRNO WRP_DIGEST_init(WRP_DIGEST_CTX *ctx, const WRP_DIGEST *digest) {

    if (ctx == NULL || digest == NULL) return ERRNO_WRP_NULL_CTX;
    if (!digest->init || !digest->update || !digest->final) return ERRNO_WRP_DIGEST_INVALID;
    reset(ctx);
    ctx->digest = digest;
    ctx->flag = 0;
    if (ctx->digest->ctx_size > 0) ctx->md_data = malloc(ctx->digest->ctx_size);
    WRP_DIGEST_set_flag(ctx, WRP_FLAG_CLEANED, 0);
    return digest->init(ctx);
}

ERRNO WRP_DIGEST_update(WRP_DIGEST_CTX *ctx, const void *data, uint32_t data_len) {
    if (ctx == NULL || ctx->digest == NULL) return ERRNO_WRP_NULL_CTX;
    return ctx->digest->update(ctx, data, data_len);
}

ERRNO WRP_DIGEST_doFinal(WRP_DIGEST_CTX *ctx, uint8_t *md, uint32_t *md_size) {

    ERRNO ret;

    if (ctx == NULL || ctx->digest == NULL) return ERRNO_WRP_NULL_CTX;

    ret = ctx->digest->final(ctx, md);
    *md_size = ctx->digest->md_size;
    return ret;
}

#define CHK_RET(func) \
    if ((ret = func) != ERRNO_OK) goto cleanup;

ERRNO WRP_DIGEST_doDigest(WRP_DIGEST_CTX *ctx, const WRP_DIGEST *digest, void *data, uint32_t data_len, uint8_t *md,
                          uint32_t *md_size) {

    ERRNO ret;

    if (ctx == NULL || digest == NULL) return ERRNO_WRP_NULL_CTX;
    CHK_RET(WRP_DIGEST_init(ctx, digest));
    CHK_RET(WRP_DIGEST_update(ctx, data, data_len));
    CHK_RET(WRP_DIGEST_doFinal(ctx, md, md_size));

    cleanup:
    reset(ctx);
    return ret;
}

#undef CHK_RET

uint8_t WRP_DIGEST_get_flag(WRP_DIGEST_CTX *ctx, uint32_t flag) {
    if (ctx == NULL) return -1;
    return ctx->flag & flag;
}

void WRP_DIGEST_set_flag(WRP_DIGEST_CTX *ctx, uint32_t flag, uint32_t val) {
    if (ctx == NULL) return;
    if (val == 0) ctx->flag &= ~flag;
    else ctx->flag |= flag;
}

ERRNO WRP_DIGEST_ctrl(WRP_DIGEST_CTX *ctx, uint32_t ctrl_flag, void *data, uint32_t datalen) {

    if (ctx == NULL || ctx->digest == NULL) return ERRNO_WRP_NULL_CTX;

    switch (ctrl_flag) {

        default: {
            if (ctx->digest->ctrl) return ctx->digest->ctrl(ctx, ctrl_flag, datalen, data);
            else return ERRNO_WRP_CTRL_NOT_SUPPORT;
        }
    }

    return ERRNO_OK;
}

void WRP_DIGEST_CTX_free(WRP_DIGEST_CTX *ctx) {

    if (ctx == NULL) return;
    reset(ctx);
    free(ctx);
}