
#ifndef __BEE2PROV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/types.h>

#include "bee2/crypto/bign.h"

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

extern const OSSL_DISPATCH provBeltPBKDF_functions[];

extern const OSSL_DISPATCH bign_key_functions[];

void print_params(const OSSL_PARAM params[]);

extern const OSSL_DISPATCH bign_params_encoder_functions[];

extern const OSSL_DISPATCH bign_params_decoder_functions[];

extern const OSSL_DISPATCH bign_key_encoder_functions[];

extern const OSSL_DISPATCH bign_key_decoder_functions[];

extern const OSSL_DISPATCH bign_signature_functions[];

OSSL_CORE_BIO *ossl_prov_bio_new_file(const char *filename, const char *mode);
OSSL_CORE_BIO *ossl_prov_bio_new_membuf(const char *filename, int len);
int ossl_prov_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read);
int ossl_prov_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                           size_t *written);
int ossl_prov_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size);
int ossl_prov_bio_puts(OSSL_CORE_BIO *bio, const char *str);
int ossl_prov_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr);
int ossl_prov_bio_up_ref(OSSL_CORE_BIO *bio);
int ossl_prov_bio_free(OSSL_CORE_BIO *bio);
int ossl_prov_bio_vprintf(OSSL_CORE_BIO *bio, const char *format, va_list ap);
int ossl_prov_bio_printf(OSSL_CORE_BIO *bio, const char *format, ...);

int ossl_core_obj_create(const OSSL_CORE_HANDLE *prov, const char *oid, const char *sn, const char *ln);

err_t bignParamsPrint(
	const bign_params* params	/*!< [in] долговременные параметры */
);
#endif // OPENSSL_VERSION_MAJOR >= 3

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2PROV_H */
