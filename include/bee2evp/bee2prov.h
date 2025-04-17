
#ifndef __BEE2PROV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/types.h>

// Common functions for all digests
const OSSL_PARAM *md_gettable_params(void *provctx);
int md_get_params(
	OSSL_PARAM params[], 
	unsigned int blocksize, 
	unsigned int size, 
	unsigned int flags
);

extern const OSSL_DISPATCH provBeltHash_functions[];
extern const OSSL_DISPATCH provBash256_functions[];
extern const OSSL_DISPATCH provBash384_functions[];
extern const OSSL_DISPATCH provBash512_functions[];


extern const OSSL_DISPATCH provBeltECB_functions[];

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
