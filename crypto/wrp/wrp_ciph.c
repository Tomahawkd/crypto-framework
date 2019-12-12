//
// Created by Ghost on 2019/9/29.
//

#include <stdlib.h>
#include <string.h>
#include "wrp.h"
#include "internal/wrp_int.h"

WRP_CIPHER_CTX *WRP_CIPHER_CTX_new() {

    WRP_CIPHER_CTX *ctx = malloc(sizeof(WRP_CIPHER_CTX));
    ctx->cipher = NULL;
    ctx->encrypt = WRP_ENCRYPT;
    ctx->num = 0;
    ctx->buf_used = 0;
    ctx->last_used = 0;
    ctx->flag = 0;
    ctx->cipher_data = NULL;
    memset(ctx->origiv, 0, WRP_MAX_IV_LENGTH);
    memset(ctx->ivec, 0, WRP_MAX_IV_LENGTH);
    memset(ctx->buffer, 0, WRP_MAX_BLOCK_LENGTH);
    memset(ctx->last, 0, WRP_MAX_BLOCK_LENGTH);

    return ctx;
}

static void reset(WRP_CIPHER_CTX *ctx) {

    if (ctx == NULL) return;

    ctx->buf_used = 0;
    ctx->num = 0;
    ctx->last_used = 0;

    if (ctx->cipher != NULL) {
        if (WRP_CIPHER_get_flag(ctx, WRP_FLAG_CLEANED) == 0 && ctx->cipher->cleanup) ctx->cipher->cleanup(ctx);
        if (ctx->cipher->ctx_size > 0 && ctx->cipher_data) free(ctx->cipher_data);
    }

    ctx->flag = 0 + WRP_CIPHER_FLAG_IS_PAD; // default: add pad
    ctx->cipher_data = NULL;

    WRP_CIPHER_set_flag(ctx, WRP_FLAG_CLEANED, 1);
}

ERRNO
WRP_CIPHER_Encrypt_init(WRP_CIPHER_CTX *ctx, const WRP_CIPHER *cipher, const WRP_KEY_CTX *key, const uint8_t *iv) {

    ERRNO ret;
    if (ctx == NULL || cipher == NULL || key == NULL) return ERRNO_WRP_NULL_CTX;
    if (!cipher->init || !cipher->do_cipher || !key->key) return ERRNO_WRP_CIPHER_INVALID;
    if (cipher->uid != key->key->uid) return ERRNO_WRP_KEY_MISMATCH;
    reset(ctx);
    ctx->encrypt = WRP_ENCRYPT;
    ctx->cipher = cipher;
    if (ctx->cipher->ctx_size > 0) ctx->cipher_data = malloc(ctx->cipher->ctx_size);
    memset(ctx->cipher_data, 0, ctx->cipher->ctx_size);
    memset(ctx->last, 0, ctx->cipher->block_size);
    ret = cipher->init(ctx, key, iv, WRP_ENCRYPT);
    WRP_CIPHER_set_flag(ctx, WRP_FLAG_CLEANED, 0);
    return ret;
}

ERRNO
WRP_CIPHER_Decrypt_init(WRP_CIPHER_CTX *ctx, const WRP_CIPHER *cipher, const WRP_KEY_CTX *key, const uint8_t *iv) {

    ERRNO ret;
    if (ctx == NULL || cipher == NULL || key == NULL) return ERRNO_WRP_NULL_CTX;
    if (!cipher->init || !cipher->do_cipher || !key->key) return ERRNO_WRP_CIPHER_INVALID;
    if (cipher->uid != key->key->uid) return ERRNO_WRP_KEY_MISMATCH;
    reset(ctx);
    ctx->encrypt = WRP_DECRYPT;
    ctx->cipher = cipher;
    if (ctx->cipher->ctx_size > 0) ctx->cipher_data = malloc(ctx->cipher->ctx_size);
    memset(ctx->cipher_data, 0, ctx->cipher->ctx_size);
    memset(ctx->last, 0, ctx->cipher->block_size);
    ret = cipher->init(ctx, key, iv, WRP_DECRYPT);
    WRP_CIPHER_set_flag(ctx, WRP_FLAG_CLEANED, 0);
    return ret;
}

ERRNO
WRP_CIPHER_Encrypt_Update(WRP_CIPHER_CTX *ctx, const uint8_t *intext, uint32_t inlen, uint8_t *outtext,
                          uint32_t *outlen) {
    uint32_t to_use = 0;
    uint32_t remain = inlen;
    uint32_t bl;
    uint32_t blm;
    ERRNO ret;

    if (ctx == NULL || ctx->cipher == NULL) return ERRNO_WRP_NULL_CTX;

    bl = ctx->cipher->block_size;
    // the whole block encryption
    if (ctx->last_used == 0 && ((remain & (bl - 1)) == 0)) {
        ret = ctx->cipher->do_cipher(ctx, outtext, intext, inlen);
        if (ret != ERRNO_OK) return ret;
        *outlen = inlen;
        return ERRNO_OK;
    }

    // we got some data left in previous update
    if (ctx->last_used != 0) {

        // the last block is large enough for the input
        if (ctx->last_used + inlen < bl) {
            memcpy(ctx->last + ctx->last_used, intext, inlen);
            ctx->last_used += inlen;
            *outlen = 0;
            return ERRNO_OK;
        } else {
            to_use = bl - ctx->last_used;
            memcpy(ctx->last + ctx->last_used, intext, to_use);
            intext += to_use;
            remain -= to_use;
            ret = ctx->cipher->do_cipher(ctx, outtext, ctx->last, bl);
            if (ret != ERRNO_OK) return ret;
            *outlen = bl;
        }
    } else *outlen = 0;

    blm = remain & (bl - 1);
    remain -= blm;
    if (remain > 0) {
        ret = ctx->cipher->do_cipher(ctx, outtext + *outlen, intext, remain);
        if (ret != ERRNO_OK) return ret;
        *outlen += remain;
    }

    if (blm != 0) memcpy(ctx->last, intext + remain, blm);
    ctx->last_used = blm;
    return ERRNO_OK;
}

ERRNO
WRP_CIPHER_Decrypt_Update(WRP_CIPHER_CTX *ctx, const uint8_t *intext, uint32_t inlen, uint8_t *outtext,
                          uint32_t *outlen) {
    uint32_t bl;
    ERRNO ret = ERRNO_OK;
    uint32_t offset = 0;

    if (ctx == NULL || ctx->cipher == NULL) return ERRNO_WRP_NULL_CTX;

    *outlen = 0;
    bl = ctx->cipher->block_size;
    // if no padding, the decryption act the same as encryption
    if ((ctx->flag & WRP_CIPHER_FLAG_IS_PAD) == 0) {
        return WRP_CIPHER_Encrypt_Update(ctx, intext, inlen, outtext, outlen);
    }

    // the last stores DECRYPTED block if it is block len, otherwise it stores the segment of the intext
    // in this case, we need to copy the last to out if it is the DECRYPTED block.
    if (ctx->last_used == bl) {
        memcpy(outtext, ctx->last, bl);
        offset += bl;
        ctx->last_used = 0;
    }

    ret = WRP_CIPHER_Encrypt_Update(ctx, intext, inlen, outtext + offset, outlen);
    if (ret != ERRNO_OK) return ret;
    offset += *outlen;

    // here we have decrypt multiple blocks and we reserve the last block for final to check pad
    // otherwise the decryption is not complete, the last stores partial of the input.
    if (ctx->last_used == 0) {
        offset -= bl;
        memcpy(ctx->last, outtext + offset, bl);
        ctx->last_used = bl;
    }
    *outlen = offset;
    return ERRNO_OK;
}

ERRNO WRP_CIPHER_Encrypt_doFinal(WRP_CIPHER_CTX *ctx, uint8_t *remain_text, uint32_t *remain_textlen) {
    uint32_t i, n, bl, cur = 0;
    ERRNO ret;
    *remain_textlen = 0;

    if (ctx == NULL || ctx->cipher == NULL) return ERRNO_WRP_NULL_CTX;
    if (ctx->encrypt != WRP_ENCRYPT) return ERRNO_WRP_CIPHER_INVALID;

    // check len for no pad, align indicates that if it is strictly aligned
    if (WRP_CIPHER_get_flag(ctx, WRP_CIPHER_FLAG_IS_PAD) == 0) {
        if (ctx->last_used && ctx->cipher->align) return ERRNO_WRP_BAD_PADDING;
        else return ERRNO_OK;
    }

    bl = ctx->cipher->block_size;
    cur = ctx->last_used;
    // this should not happen
    if (cur > bl) return ERRNO_UNKNOWN;

    n = bl - cur;
    for (i = cur; i < bl; i++)
        ctx->last[i] = n;

    ret = ctx->cipher->do_cipher(ctx, remain_text, ctx->last, bl);
    if (ret != ERRNO_OK) return ret;
    *remain_textlen = bl;

    return ERRNO_OK;
}

ERRNO WRP_CIPHER_Decrypt_doFinal(WRP_CIPHER_CTX *ctx, uint8_t *remain_text, uint32_t *remain_textlen) {
    uint32_t i, n, bl, r = 0;
    *remain_textlen = 0;

    if (ctx == NULL || ctx->cipher == NULL) return ERRNO_WRP_NULL_CTX;
    if (ctx->encrypt != WRP_DECRYPT) return ERRNO_WRP_CIPHER_INVALID;

    if (WRP_CIPHER_get_flag(ctx, WRP_CIPHER_FLAG_IS_PAD) == 0) {
        if (ctx->last_used == 0) return ERRNO_OK;
        else return ERRNO_WRP_NOT_MULTI_OF_BLOCK;
    }

    bl = ctx->cipher->block_size;
    // the final one must be exactly block size
    if (ctx->last_used != bl) return ERRNO_WRP_NOT_MULTI_OF_BLOCK;

    i = ctx->last_used;
    n = ctx->last[bl - 1];

    if (n == 0 || n > bl) return ERRNO_WRP_BAD_PADDING;

    while (r < n) {
        if (ctx->last[--i] != n) return ERRNO_WRP_BAD_PADDING;
        r++;
    }

    // i is the offset of the padding start
    // reset n to count
    for (n = 0; n < i; ++n)
        remain_text[n] = ctx->last[n];
    *remain_textlen = i;

    return ERRNO_OK;
}

uint8_t WRP_CIPHER_get_flag(WRP_CIPHER_CTX *ctx, uint32_t flag) {
    if (ctx == NULL) return -1;
    return ctx->flag & flag;
}

void WRP_CIPHER_set_flag(WRP_CIPHER_CTX *ctx, uint32_t flag, uint32_t val) {
    if (ctx == NULL) return;
    if (val == 0) ctx->flag &= ~flag;
    else ctx->flag |= flag;
}

uint32_t WRP_CIPHER_get_uid(WRP_CIPHER_CTX *ctx) {
    return ctx == NULL || ctx->cipher == NULL ? -1 : ctx->cipher->uid;
}


ERRNO WRP_CIPHER_ctrl(WRP_CIPHER_CTX *ctx, uint32_t ctrl_flag, void *data, uint32_t datalen) {
    if (ctx == NULL || ctx->cipher == NULL) return ERRNO_WRP_NULL_CTX;

    switch (ctrl_flag) {
        case WRP_CTRL_TYPE_setiv: {
            if (data == NULL) return ERRNO_WRP_NULL_CTX;
            if (datalen < ctx->cipher->iv_size) return ERRNO_WRP_IV_TOO_SMALL;
            memcpy(ctx->origiv, data, ctx->cipher->iv_size);
            memcpy(ctx->ivec, data, ctx->cipher->iv_size);
            // gcm need this
            ctx->cipher->ctrl(ctx, ctrl_flag, datalen, data);
            break;
        }

        default:
            if (ctx->cipher->ctrl)
                return ctx->cipher->ctrl(ctx, ctrl_flag, datalen, data);
            else return ERRNO_WRP_CTRL_NOT_SUPPORT;

    }
    return ERRNO_OK;
}


void WRP_CIPHER_CTX_free(WRP_CIPHER_CTX *ctx) {

    if (ctx == NULL) return;
    reset(ctx);
    free(ctx);
}