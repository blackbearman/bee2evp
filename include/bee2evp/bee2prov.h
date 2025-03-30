
#ifndef __BEE2PROV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/types.h>

const OSSL_PARAM *md_gettable_params(void *provctx);

int provBeltHash_init(void *vctx);
int provBeltHash_update(void *vctx, const unsigned char *data, size_t datalen);
int provBeltHash_final(void *vctx, unsigned char *out, size_t *outlen, size_t outsize);
void provBeltHash_free(void *vctx);
void *provBeltHash_newctx(void *provctx);
int provBeltHash_get_params(OSSL_PARAM params[]);

int provBash256_init(void *vctx);
int provBash256_update(void *vctx, const unsigned char *data, size_t datalen);
int provBash256_final(void *vctx, unsigned char *out, size_t *outlen, size_t outsize);
void provBash256_free(void *vctx);
void *provBash256_newctx(void *provctx);
int provBash256_get_params(OSSL_PARAM params[]);

int provBash384_init(void *vctx);
int provBash384_update(void *vctx, const unsigned char *data, size_t datalen);
int provBash384_final(void *vctx, unsigned char *out, size_t *outlen, size_t outsize);
void provBash384_free(void *vctx);
void *provBash384_newctx(void *provctx);
int provBash384_get_params(OSSL_PARAM params[]);

int provBash512_init(void *vctx);
int provBash512_update(void *vctx, const unsigned char *data, size_t datalen);
int provBash512_final(void *vctx, unsigned char *out, size_t *outlen, size_t outsize);
void provBash512_free(void *vctx);
void *provBash512_newctx(void *provctx);
int provBash512_get_params(OSSL_PARAM params[]);

void provBeltECB_freectx(void *vctx);
void *provBeltECB_newctx(void *provctx);
int provBeltECB_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
    const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[]);
int provBeltECB_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
    const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[]);
int provBeltECB_update(void *vctx, unsigned char *out, size_t *outlen,
    size_t outsize, const unsigned char *in, size_t inlen);
int provBeltECB_final(void *vctx, unsigned char *out, size_t *outlen, size_t outsize);
int provBeltECB_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
const OSSL_PARAM *provBeltECB_gettable_ctx_params(void *provctx);
int provBeltECB_get_ctx_params(void *vctx, OSSL_PARAM *params);
int provBeltECB_get_params(OSSL_PARAM params[]);

void provBign_freectx(void *vctx);
void *provBign_newctx(void *provctx, const char *propquery);
int provBign_sign_init(void *vctx, void *provkey, const OSSL_PARAM params[]);
int provBign_verify_init(void *vctx, void *provkey, const OSSL_PARAM params[]);
int provBign_sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize,
    const unsigned char *tbs, size_t tbslen);
int provBign_verify(void *vctx, const unsigned char *sig, size_t siglen,
    const unsigned char *tbs, size_t tbslen);
const OSSL_PARAM *provBign_gettable_params(void *vctx);

#endif // OPENSSL_VERSION_MAJOR >= 3

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2PROV_H */
