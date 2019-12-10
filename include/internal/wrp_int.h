//
// Created by Ghost on 2019/9/29.
//

#ifndef CRYPTO_FRAMEWORK_WRP_INT_H
#define CRYPTO_FRAMEWORK_WRP_INT_H

#include "typedef.h"
#include "err.h"
#include "wrp.h"
#include "random/sys_random.h"

struct wrp_cipher_st {
    uint32_t uid;
    uint8_t align; // need to check pad?
    uint32_t block_size;
    uint32_t key_size;
    uint32_t iv_size;
    uint32_t mode; // defined in modes.h
    uint32_t ctx_size; // WRP_CIPHER_CTX->cipher_data size
    void *custom_data; // other data need pass to cipher, only for custom ciphers

    ERRNO (*init)(WRP_CIPHER_CTX *ctx, const WRP_KEY_CTX *key,
                  const uint8_t *iv, int enc);

    ERRNO (*do_cipher)(WRP_CIPHER_CTX *ctx, uint8_t *out,
                       const uint8_t *in, uint32_t inlen);

    ERRNO (*cleanup)(WRP_CIPHER_CTX *);
    // cleanup procedure for custom ciphers, typically this should not be defined because these cipher definition are static in internal file

    /* Miscellaneous operations */
    ERRNO (*ctrl)(WRP_CIPHER_CTX *, uint32_t type, uint32_t len, void *ptr);
};

struct wrp_cipher_ctx_st {
    const WRP_CIPHER *cipher;
    uint32_t encrypt;
    uint32_t flag;

    uint8_t origiv[WRP_MAX_IV_LENGTH]; // original iv
    uint8_t ivec[WRP_MAX_IV_LENGTH]; // temp iv
    uint32_t buf_used;
    uint8_t buffer[WRP_MAX_BLOCK_LENGTH];
    uint32_t num; // contains that is from ctr mode
    uint32_t last_used; // data used in last block
    uint8_t last[WRP_MAX_BLOCK_LENGTH]; // last unfilled block

    void *cipher_data; // typically stores cipher ctx data(like key struct and block cipher function pointer)
};

struct wrp_digest_st {
    uint32_t uid;
    uint32_t md_size;
    uint32_t block_size; // char block(cblock) size
    uint32_t ctx_size; // WRP_DIGEST_CTX->md_data size
    ERRNO (*init)(WRP_DIGEST_CTX *ctx);

    ERRNO (*update)(WRP_DIGEST_CTX *ctx, const void *data, uint32_t len);

    ERRNO (*final)(WRP_DIGEST_CTX *ctx, uint8_t *md);

    void (*cleanup)(WRP_DIGEST_CTX *ctx);

    // typically this is not used
    ERRNO (*ctrl)(WRP_DIGEST_CTX *ctx, uint32_t flag, uint32_t len, void *ptr);
};

// the cache area stores in md_data which is internal ctx for specific md method
struct wrp_digest_ctx_st {
    const WRP_DIGEST *digest;
    uint32_t flag;

    void *md_data; // used by digest internal context, eg: SM3_CTX
};

#ifndef CRYPTOLIB_NO_RANDOM
static int default_rng(WRP_KEY_CTX *ctx, uint8_t *random, uint32_t len) {
    getrandombits(random, len);
    return 0;
}
#else
# ifndef DEFAULT_RNG_IMPLEMENTED
# error "default rng must be implemented for generate keys"
# endif
#endif

struct wrp_key_st {
    uint32_t uid;
    uint32_t ctx_size;

    ERRNO (*init)(WRP_KEY_CTX *ctx);
    ERRNO (*genkey)(WRP_KEY_CTX *ctx);
    ERRNO (*setkey)(WRP_KEY_CTX *ctx, void *data, uint32_t len, uint32_t mode);
    ERRNO (*getkey)(WRP_KEY_CTX *ctx, void *data, uint32_t *len, uint32_t mode);
    void (*cleanup)(WRP_KEY_CTX *ctx);
    int (*rng) (WRP_KEY_CTX *ctx, uint8_t *random, uint32_t len); // put here to use drbg which needs loads of initialization
    ERRNO (*ctrl)(WRP_KEY_CTX *ctx, uint32_t flag, uint32_t len, void *ptr);
    uint32_t (*getlen)(WRP_KEY_CTX *ctx, uint32_t mode);
#ifndef CRYPTOLIB_NO_WRPIO
    ERRNO (*import)(WRP_KEY_CTX *ctx, WRPIO *io, const char *target, uint32_t mode);
    ERRNO (*export)(WRP_KEY_CTX *ctx, WRPIO *io, const char *target, uint32_t mode);
#endif

};

struct wrp_key_ctx_st {

    const WRP_KEY *key;
    uint32_t mode;
    uint8_t random_pool[WRP_MAX_RANDPOOL_LENGTH];
    uint8_t seed[WRP_MAX_KEY_LENGTH];
    uint32_t bits;
    uint32_t flag;
    void *key_data;
    uint32_t use_count;
};

struct wrp_pubciph_st {

    uint32_t uid;

    ERRNO (*init)(WRP_PUBCIPH_CTX *ctx, WRP_KEY_CTX *key);
    ERRNO (*sign)(WRP_PUBCIPH_CTX *ctx, uint8_t *md, uint32_t mdlen, uint8_t *sign, uint32_t *signlen);
    ERRNO (*verify)(WRP_PUBCIPH_CTX *ctx, uint8_t *md, uint32_t mdlen, uint8_t *sign, uint32_t signlen);
    ERRNO (*enc)(WRP_PUBCIPH_CTX *ctx, const uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen);
    ERRNO (*dec)(WRP_PUBCIPH_CTX *ctx, const uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t *outlen);
    ERRNO (*ctrl)(WRP_PUBCIPH_CTX *ctx, uint32_t flag, uint32_t len, void *ptr);
    void (*cleanup)(WRP_PUBCIPH_CTX *ctx);
};

struct wrp_pubciph_ctx_st {
    const WRP_PUBCIPH *meth;
    WRP_DIGEST_CTX *digest;
    uint32_t flag;
    WRP_KEY_CTX *key;
};

#endif //CRYPTO_FRAMEWORK_WRP_INT_H
