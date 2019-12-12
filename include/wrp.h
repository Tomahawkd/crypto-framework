//
// Created by Ghost on 2019/9/29.
//

#ifndef CRYPTO_FRAMEWORK_WRP_H
#define CRYPTO_FRAMEWORK_WRP_H

#include "err.h"
#include "typedef.h"
#include "wrp_items.h"
#include "cryptoconf.h"
#include "wrpio.h"

#ifdef  __cplusplus
extern "C" {
#endif

//#define ERRNO_WRP_MASK                        0x01000000
#define ERRNO_WRP_NULL_CTX                      (ERRNO_WRP_MASK + 0x01)
#define ERRNO_WRP_CIPHER_INVALID                (ERRNO_WRP_MASK + 0x02)
#define ERRNO_WRP_DIGEST_INVALID                (ERRNO_WRP_MASK + 0x03)
#define ERRNO_WRP_KEY_INVALID                   (ERRNO_WRP_MASK + 0x04)
#define ERRNO_WRP_PUBCIPH_INVALID               (ERRNO_WRP_MASK + 0x05)
#define ERRNO_WRP_NOT_MULTI_OF_BLOCK            (ERRNO_WRP_MASK + 0x06)
#define ERRNO_WRP_BUF_TOO_SMALL                 (ERRNO_WRP_MASK + 0x07)
#define ERRNO_WRP_CTRL_NOT_SUPPORT              (ERRNO_WRP_MASK + 0x08)
#define ERRNO_WRP_BAD_PADDING                   (ERRNO_WRP_MASK + 0x09)
#define ERRNO_WRP_IV_TOO_SMALL                  (ERRNO_WRP_MASK + 0x0A)
#define ERRNO_WRP_REQUEST_TAG_TOO_BIG           (ERRNO_WRP_MASK + 0x0B)
#define ERRNO_WRP_GCM_TAG_CHECK_FAILED          (ERRNO_WRP_MASK + 0x0C)
#define ERRNO_WRP_KEY_BITS_NOT_SUPPORT          (ERRNO_WRP_MASK + 0x0D)
#define ERRNO_WRP_KEY_IMPORT_NOT_SUPPORT        (ERRNO_WRP_MASK + 0x0E)
#define ERRNO_WRP_KEY_EXPORT_NOT_SUPPORT        (ERRNO_WRP_MASK + 0x0F)
#define ERRNO_WRP_KEY_MAX_SEED_REACH            (ERRNO_WRP_MASK + 0x10)
#define ERRNO_WRP_KEY_RANDOM_GENERATOR_ERR      (ERRNO_WRP_MASK + 0x11)
#define ERRNO_WRP_KEY_INVALID_KEY               (ERRNO_WRP_MASK + 0x12)
#define ERRNO_WRP_KEY_MISMATCH                  (ERRNO_WRP_MASK + 0x13)
#define ERRNO_WRP_KEY_FILE_EXIST                (ERRNO_WRP_MASK + 0x14)
#define ERRNO_WRP_PUBCIPH_ALGORITHM_NOT_SUPPORT (ERRNO_WRP_MASK + 0x15)

#define WRP_MAX_IV_LENGTH      16
#define WRP_MAX_BLOCK_LENGTH   32
#define WRP_MAX_KEY_LENGTH     64
#define WRP_MAX_DIGEST_LEN     32

#define WRP_CTRL_TYPE_setiv                 0x0001
#define WRP_CTRL_TYPE_gcm_setaad            0x0002
#define WRP_CTRL_TYPE_gcm_gettag            0x0003
#define WRP_CTRL_TYPE_gcm_checktag          0x0004

#define WRP_CIPHER_FLAG_IS_PAD              (1u << 0u)
#define WRP_FLAG_CLEANED                    (1u << 1u)
#define WRP_KEY_FLAG_HAS_SEED               (1u << 0u)

#define WRP_ENCRYPT 1
#define WRP_DECRYPT 0

LIB_API WRP_CIPHER_CTX *WRP_CIPHER_CTX_new();
LIB_API ERRNO WRP_CIPHER_Encrypt_init(WRP_CIPHER_CTX *ctx, const WRP_CIPHER *cipher, const WRP_KEY_CTX *key, const uint8_t *iv);
LIB_API ERRNO WRP_CIPHER_Decrypt_init(WRP_CIPHER_CTX *ctx, const WRP_CIPHER *cipher, const WRP_KEY_CTX *key, const uint8_t *iv);
LIB_API ERRNO WRP_CIPHER_Encrypt_Update(WRP_CIPHER_CTX *ctx, const uint8_t *intext, uint32_t inlen, uint8_t *outtext, uint32_t *outlen);
LIB_API ERRNO WRP_CIPHER_Decrypt_Update(WRP_CIPHER_CTX *ctx, const uint8_t *intext, uint32_t inlen, uint8_t *outtext, uint32_t *outlen);
LIB_API ERRNO WRP_CIPHER_Encrypt_doFinal(WRP_CIPHER_CTX *ctx, uint8_t *remain_text, uint32_t *remain_textlen);
LIB_API ERRNO WRP_CIPHER_Decrypt_doFinal(WRP_CIPHER_CTX *ctx, uint8_t *remain_text, uint32_t *remain_textlen);
LIB_API uint32_t WRP_CIPHER_get_uid(WRP_CIPHER_CTX *ctx);
LIB_API uint8_t WRP_CIPHER_get_flag(WRP_CIPHER_CTX *ctx, uint32_t flag);
LIB_API void WRP_CIPHER_set_flag(WRP_CIPHER_CTX *ctx, uint32_t flag, uint32_t val);
LIB_API ERRNO WRP_CIPHER_ctrl(WRP_CIPHER_CTX *ctx, uint32_t ctrl_flag, void *data, uint32_t datalen);
LIB_API void WRP_CIPHER_CTX_free(WRP_CIPHER_CTX *ctx);

LIB_API uint32_t WRP_DIGEST_get_len(const WRP_DIGEST_CTX *digest);
LIB_API WRP_DIGEST_CTX *WRP_DIGEST_CTX_new();
LIB_API ERRNO WRP_DIGEST_init(WRP_DIGEST_CTX *ctx, const WRP_DIGEST *digest);
LIB_API ERRNO WRP_DIGEST_update(WRP_DIGEST_CTX *ctx, const void *data, uint32_t data_len);
LIB_API ERRNO WRP_DIGEST_doFinal(WRP_DIGEST_CTX *ctx, uint8_t *md, uint32_t *md_size);
LIB_API ERRNO WRP_DIGEST_doDigest(WRP_DIGEST_CTX *ctx, const WRP_DIGEST *digest, void *data, uint32_t data_len, uint8_t *md, uint32_t *md_size);
LIB_API uint8_t WRP_DIGEST_get_flag(WRP_DIGEST_CTX *ctx, uint32_t flag);
LIB_API void WRP_DIGEST_set_flag(WRP_DIGEST_CTX *ctx, uint32_t flag, uint32_t val);
LIB_API ERRNO WRP_DIGEST_ctrl(WRP_DIGEST_CTX *ctx, uint32_t ctrl_flag, void *data, uint32_t datalen);
LIB_API void WRP_DIGEST_CTX_free(WRP_DIGEST_CTX *ctx);

#define WRP_MAX_RANDPOOL_LENGTH     128
#define KEYMODE_GENERIC             1 // both
#define KEYMODE_ENCRYPT             2
#define KEYMODE_DECRYPT             4
#define KEYMODE_PUBKEY              8
#define KEYMODE_PRIVKEY             KEYMODE_GENERIC

#define WRP_KEY_FLAG_FREE_AFTER_USE     (1u << 0u)

#define WRP_KEY_CTRL_TYPE_set_seed          0x0001
#define WRP_KEY_CTRL_INCREASE_USE_COUNT     0x0002
#define WRP_KEY_CTRL_DECREASE_USE_COUNT     0x0003

LIB_API WRP_KEY_CTX *WRP_KEY_CTX_new();
LIB_API ERRNO WRP_KEY_init(WRP_KEY_CTX *ctx, const WRP_KEY *key, uint32_t bits);
LIB_API ERRNO WRP_KEY_genkey(WRP_KEY_CTX *ctx);
LIB_API ERRNO WRP_KEY_set_key(WRP_KEY_CTX *ctx, uint8_t *data, uint32_t data_len, uint32_t mode);
LIB_API ERRNO WRP_KEY_get_key(WRP_KEY_CTX *ctx, uint8_t *data, uint32_t *data_len, uint32_t mode);
LIB_API ERRNO WRP_KEY_key_len(WRP_KEY_CTX *ctx, uint32_t mode);
#ifndef CRYPTOLIB_NO_WRPIO
LIB_API ERRNO WRP_KEY_import(WRP_KEY_CTX *ctx, const char *target, uint32_t mode);
LIB_API ERRNO WRP_KEY_export(WRP_KEY_CTX *ctx, const char *target, uint32_t mode);
#endif
LIB_API uint32_t WRP_KEY_get_uid(WRP_KEY_CTX *ctx);
LIB_API ERRNO WRP_KEY_ctrl(WRP_KEY_CTX *ctx, uint32_t ctrl_flag, void *data, uint32_t datalen);
LIB_API uint8_t WRP_KEY_get_flag(WRP_KEY_CTX *ctx, uint32_t flag);
LIB_API void WRP_KEY_set_flag(WRP_KEY_CTX *ctx, uint32_t flag, uint32_t val);
LIB_API void WRP_KEY_CTX_free(WRP_KEY_CTX *ctx);


#define WRP_PUBCIPH_FLAG_NO_PADDING          (1u << 0u)

LIB_API WRP_PUBCIPH_CTX *WRP_PUBCIPH_CTX_new();
LIB_API ERRNO WRP_PUBCIPH_init(WRP_PUBCIPH_CTX *ctx, const WRP_PUBCIPH *meth, WRP_KEY_CTX *key);
LIB_API ERRNO WRP_PUBCIPH_DIGEST_init(WRP_PUBCIPH_CTX *ctx, const WRP_DIGEST *digest);
LIB_API ERRNO WRP_PUBCIPH_DIGEST_update(WRP_PUBCIPH_CTX *ctx, uint8_t *msg, uint32_t msglen);
LIB_API ERRNO WRP_PUBCIPH_DIGEST_final_sign(WRP_PUBCIPH_CTX *ctx, uint8_t *sign, uint32_t *siglen);
LIB_API ERRNO WRP_PUBCIPH_DIGEST_final_verify(WRP_PUBCIPH_CTX *ctx, uint8_t *sign, uint32_t siglen);
LIB_API ERRNO WRP_PUBCIPH_DIGEST_get_digest(WRP_PUBCIPH_CTX *ctx, uint8_t *md, uint32_t *mdlen);
LIB_API ERRNO WRP_PUBCIPH_sign(WRP_PUBCIPH_CTX *ctx, uint8_t *md, uint32_t mdlen, uint8_t *sign, uint32_t *signlen);
LIB_API ERRNO WRP_PUBCIPH_verify(WRP_PUBCIPH_CTX *ctx, uint8_t *md, uint32_t mdlen, uint8_t *sign, uint32_t signlen);
LIB_API ERRNO WRP_PUBCIPH_encrypt(WRP_PUBCIPH_CTX *ctx, uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen);
LIB_API ERRNO WRP_PUBCIPH_decrypt(WRP_PUBCIPH_CTX *ctx, uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen);
LIB_API ERRNO WRP_PUBCIPH_ctrl(WRP_PUBCIPH_CTX *ctx, uint32_t ctrl_flag, void *data, uint32_t datalen);
LIB_API uint8_t WRP_PUBCIPH_get_flag(WRP_PUBCIPH_CTX *ctx, uint32_t flag);
LIB_API void WRP_PUBCIPH_set_flag(WRP_PUBCIPH_CTX *ctx, uint32_t flag, uint32_t val);
LIB_API void WRP_PUBCIPH_CTX_free(WRP_PUBCIPH_CTX *ctx);

#ifdef  __cplusplus
}
#endif

#endif //CRYPTO_FRAMEWORK_WRP_H
