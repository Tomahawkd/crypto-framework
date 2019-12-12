//
// Created by Ghost on 2019/11/15.
//

#include <stdlib.h>
#include <string.h>
#include "wrp.h"
#include "internal/wrp_int.h"
#include "random/sys_random.h"

WRP_PUBCIPH_CTX *WRP_PUBCIPH_CTX_new() {

    WRP_PUBCIPH_CTX *ctx = malloc(sizeof(WRP_PUBCIPH_CTX));
    memset(ctx, 0, sizeof(WRP_PUBCIPH_CTX));
    return ctx;
}

ERRNO WRP_PUBCIPH_init(WRP_PUBCIPH_CTX *ctx, const WRP_PUBCIPH *meth, WRP_KEY_CTX *key) {

    if (!ctx || !meth || !key) return ERRNO_WRP_NULL_CTX;
    if (meth->uid != key->key->uid) return ERRNO_WRP_PUBCIPH_INVALID;

    ctx->meth = meth;
    ctx->key = key;
    WRP_KEY_ctrl(key, WRP_KEY_CTRL_INCREASE_USE_COUNT, NULL, 0);
    if (meth->init) return meth->init(ctx, key);
    return ERRNO_OK;
}

ERRNO WRP_PUBCIPH_DIGEST_init(WRP_PUBCIPH_CTX *ctx, const WRP_DIGEST *digest) {

    if (!ctx || !digest) return ERRNO_WRP_NULL_CTX;

    if (ctx->digest) WRP_DIGEST_CTX_free(ctx->digest);
    ctx->digest = WRP_DIGEST_CTX_new();
    return WRP_DIGEST_init(ctx->digest, digest);
}

ERRNO WRP_PUBCIPH_DIGEST_update(WRP_PUBCIPH_CTX *ctx, uint8_t *msg, uint32_t msglen) {
    if (!ctx) return ERRNO_WRP_NULL_CTX;
    if (!ctx->digest) return ERRNO_WRP_PUBCIPH_ALGORITHM_NOT_SUPPORT;
    return WRP_DIGEST_update(ctx->digest, msg, msglen);
}

ERRNO WRP_PUBCIPH_DIGEST_final_sign(WRP_PUBCIPH_CTX *ctx, uint8_t *sign, uint32_t *siglen) {
    uint8_t buf[WRP_MAX_DIGEST_LEN];
    uint32_t mdlen = WRP_MAX_DIGEST_LEN;
    ERRNO ret;

    if (!ctx) return ERRNO_WRP_NULL_CTX;
    if (!ctx->meth || !ctx->meth->sign) return ERRNO_WRP_PUBCIPH_ALGORITHM_NOT_SUPPORT;
    if ((ret = WRP_PUBCIPH_DIGEST_get_digest(ctx, buf, &mdlen)) != ERRNO_OK) return ret;
    return ctx->meth->sign(ctx, buf, mdlen, sign, siglen);
}

ERRNO WRP_PUBCIPH_DIGEST_final_verify(WRP_PUBCIPH_CTX *ctx, uint8_t *sign, uint32_t siglen) {
    uint8_t buf[WRP_MAX_DIGEST_LEN];
    uint32_t mdlen = WRP_MAX_DIGEST_LEN;
    ERRNO ret;

    if (!ctx) return ERRNO_WRP_NULL_CTX;
    if (!ctx->meth || !ctx->meth->verify) return ERRNO_WRP_PUBCIPH_ALGORITHM_NOT_SUPPORT;
    if ((ret = WRP_PUBCIPH_DIGEST_get_digest(ctx, buf, &mdlen)) != ERRNO_OK) return ret;
    return ctx->meth->verify(ctx, buf, mdlen, sign, siglen);
}

ERRNO WRP_PUBCIPH_DIGEST_get_digest(WRP_PUBCIPH_CTX *ctx, uint8_t *md, uint32_t *mdlen) {
    if (!ctx) return ERRNO_WRP_NULL_CTX;
    if (!ctx->digest) return ERRNO_WRP_PUBCIPH_ALGORITHM_NOT_SUPPORT;
    return WRP_DIGEST_doFinal(ctx->digest, md, mdlen);
}

ERRNO WRP_PUBCIPH_sign(WRP_PUBCIPH_CTX *ctx, uint8_t *md, uint32_t mdlen, uint8_t *sign, uint32_t *signlen) {
    if (!ctx) return ERRNO_WRP_NULL_CTX;
    if (!ctx->meth || !ctx->meth->sign) return ERRNO_WRP_PUBCIPH_ALGORITHM_NOT_SUPPORT;
    return ctx->meth->sign(ctx, md, mdlen, sign, signlen);
}

ERRNO WRP_PUBCIPH_verify(WRP_PUBCIPH_CTX *ctx, uint8_t *md, uint32_t mdlen, uint8_t *sign, uint32_t signlen) {
    if (!ctx) return ERRNO_WRP_NULL_CTX;
    if (!ctx->meth || !ctx->meth->verify) return ERRNO_WRP_PUBCIPH_ALGORITHM_NOT_SUPPORT;
    return ctx->meth->verify(ctx, md, mdlen, sign, signlen);
}

ERRNO WRP_PUBCIPH_encrypt(WRP_PUBCIPH_CTX *ctx, uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen) {
    if (!ctx) return ERRNO_WRP_NULL_CTX;
    if (!ctx->meth || !ctx->meth->enc) return ERRNO_WRP_PUBCIPH_ALGORITHM_NOT_SUPPORT;
    return ctx->meth->enc(ctx, in, inlen, out, outlen);
}

ERRNO WRP_PUBCIPH_decrypt(WRP_PUBCIPH_CTX *ctx, uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen) {
    if (!ctx) return ERRNO_WRP_NULL_CTX;
    if (!ctx->meth || !ctx->meth->dec) return ERRNO_WRP_PUBCIPH_ALGORITHM_NOT_SUPPORT;
    return ctx->meth->dec(ctx, in, inlen, out, outlen);
}

ERRNO WRP_PUBCIPH_ctrl(WRP_PUBCIPH_CTX *ctx, uint32_t ctrl_flag, void *data, uint32_t datalen) {
    if (ctx->meth->ctrl) return ctx->meth->ctrl(ctx, ctrl_flag, datalen, data);
    else return ERRNO_WRP_CTRL_NOT_SUPPORT;
}

uint8_t WRP_PUBCIPH_get_flag(WRP_PUBCIPH_CTX *ctx, uint32_t flag) {
    if (ctx == NULL) return -1;
    return ctx->flag & flag;
}

void WRP_PUBCIPH_set_flag(WRP_PUBCIPH_CTX *ctx, uint32_t flag, uint32_t val) {
    if (ctx == NULL) return;
    if (val == 0) ctx->flag &= ~flag;
    else ctx->flag |= flag;
}

void WRP_PUBCIPH_CTX_free(WRP_PUBCIPH_CTX *ctx) {

    WRP_KEY_ctrl(ctx->key, WRP_KEY_CTRL_DECREASE_USE_COUNT, NULL, 0);
    ctx->key = NULL;
    if (ctx->digest) WRP_DIGEST_CTX_free(ctx->digest);
    if (ctx->meth && ctx->meth->cleanup) ctx->meth->cleanup(ctx);
    free(ctx);
}