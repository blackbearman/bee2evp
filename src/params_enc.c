
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3

/*
The encoder doesn't need to know more about the B<OSSL_CORE_BIO>
pointer than being able to pass it to the appropriate BIO upcalls (see
L<provider-base(7)/Core functions>: <openssl/core_dispatch.h>).

*/

#include <string.h>
#include <stdlib.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>

#include "bee2/core/b64.h"
#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/hex.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bign.h"

#include "bee2evp/bee2prov.h"
#include "bee2evp_lcl.h"



#define PARAM_BUF_SIZE 2048

/*!	\brief Печать параметров BIGN

	На экран выводятся параметры в виде структуры YAML
*/
err_t bignParamsPrint(
	const bign_params* params	/*!< [in] долговременные параметры */
)
{
	char hex[PARAM_BUF_SIZE];
	err_t code = ERR_OK;
	// pre
	ASSERT(memIsValid(params, sizeof(bign_params)));
	printf("params:\n");
	// печатать l
	code = printf("  l: %u\n", (unsigned)params->l) > 0
		? ERR_OK : ERR_FILE_WRITE;
	ERR_CALL_CHECK(code);
	// печатать p
	hexFrom(hex, params->p, params->l / 4);
	code = printf("  p: 0x%s\n", hex) > 0
		? ERR_OK : ERR_FILE_WRITE;
	ERR_CALL_CHECK(code);
	// печатать a
	hexFrom(hex, params->a, params->l / 4);
	code = printf("  a: 0x%s\n", hex) > 0
		? ERR_OK : ERR_FILE_WRITE;
	ERR_CALL_CHECK(code);
	// печатать b
	hexFrom(hex, params->b, params->l / 4);
	code = printf("  b: 0x%s\n", hex) > 0
		? ERR_OK : ERR_FILE_WRITE;
	ERR_CALL_CHECK(code);
	// печатать seed
	hexFrom(hex, params->seed, 8);
	code = printf("  seed: 0x%s\n", hex) > 0
		? ERR_OK : ERR_FILE_WRITE;
	ERR_CALL_CHECK(code);
	// печатать yG
	hexFrom(hex, params->yG, params->l / 4);
	code = printf("  yG: 0x%s\n", hex) > 0
		? ERR_OK : ERR_FILE_WRITE;
	ERR_CALL_CHECK(code);
	// печатать q
	hexFrom(hex, params->q, params->l / 4);
	code = printf("  q: 0x%s\n", hex) > 0
		? ERR_OK : ERR_FILE_WRITE;
	return code;
}

/*
При генерации параметров опция outform игнорируется, параметры выводятся 
только в PEM, поэтому необходим их кодер только в формат PEM.
*/

static OSSL_FUNC_encoder_newctx_fn bign_params_encoder_newctx;
static OSSL_FUNC_encoder_freectx_fn bign_params_encoder_freectx;
//static OSSL_FUNC_encoder_get_params_fn 
//static OSSL_FUNC_encoder_gettable_params_fn bign_params_encoder_gettable_params;
static OSSL_FUNC_encoder_set_ctx_params_fn bign_params_encoder_set_ctx_params;
static OSSL_FUNC_encoder_settable_ctx_params_fn bign_params_encoder_settable_ctx_params;
static OSSL_FUNC_encoder_does_selection_fn bign_params_encoder_does_selection;
static OSSL_FUNC_encoder_encode_fn bign_params_encoder_encode;

//static OSSL_FUNC_encoder_import_object_fn bign_to_EncryptedPrivateKeyInfo_pem_import_object; 
//static OSSL_FUNC_encoder_free_object_fn bign_params_encoder_freectx; 


/* Encoder-specific context */
typedef struct {
    const EVP_PKEY *pkey; /* The private key to encode */
	//OSSL_LIB_CTX *libctx;
	int save_parameters;
} MY_KEY_ENCODER_CTX;

/* Create a new encoder context */
static void *bign_params_encoder_newctx(void *provctx) {
    //PROV_CTX *pctx = (PROV_CTX *)provctx;
    MY_KEY_ENCODER_CTX *ctx = OPENSSL_zalloc(sizeof(MY_KEY_ENCODER_CTX));
	printf("81-params-encoder newctx\n");
    if (ctx == NULL) {
        return NULL;
    }
    ctx->pkey = NULL;
	//ctx->libctx = pctx->libctx;
    return ctx;
}

/* Free the encoder context */
static void bign_params_encoder_freectx(void *vctx) {
    MY_KEY_ENCODER_CTX *ctx = (MY_KEY_ENCODER_CTX *)vctx;
	printf("81-params-encoder freectx\n");
    if (ctx) {
        OPENSSL_free(ctx);
    }
}

/* Check if the encoder supports the given selection and key type */
static int bign_params_encoder_does_selection(void *vctx, int selection) {
    /* This encoder supports private key encoding */
	printf("82-params-encoder does_selection %d\n", selection);
    printf("82-params-encoder does_selection %d\n", selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
    printf("82-params-encoder does_selection %d\n", selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS);
    
	return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY
		|| selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) ? 1 : 0;
}

/* Encode the key into PEM PrivateKeyInfo */
static int bign_params_encoder_encode(void *vctx, OSSL_CORE_BIO *out, const void *key, 
                                  const OSSL_PARAM params[], int selection, 
                                  OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    const bign_key *pkey = (const bign_key *)key;
	octet der[1000];
	char buf[1000];
	size_t len = 1000;
	size_t written = 0;
    char* walker = buf;
+//bool_t specified = TRUE;
	printf("85-params-encoder encode %d\n", selection);

    if (pkey == NULL || !(selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (out == NULL) {
        return 0;
    }
	printf("85-params-encoder check key\n");
	bignParamsPrint(pkey->params);
    if (bignParamsEnc(der, &len, pkey->params) != ERR_OK)
	    return 0;
	//if(!evpBign_asn1_i2d_params(&der, &specified, pkey))
	//	return 0;
	printf("85-params-encoder write to buf\n");
    strCopy(buf, "-----BEGIN bign PARAMETERS-----\n");
    walker = buf + strlen(buf);
    b64From(walker, der, len);
    walker = buf + strlen(buf);
    strCopy(walker, "\n-----END bign PARAMETERS-----\n");
    
	printf("85-params-encoder write to output\n");
	if(!ossl_prov_bio_write_ex(out, buf, strlen(buf), &written))
		return 0;
	printf("85-bign-encoder finish\n");
    return 1;
}

// /* Gettable parameters for the encoder context */
// static const OSSL_PARAM *bign_params_encoder_gettable_params(void *provctx) {
//     static const OSSL_PARAM params[] = {
//         OSSL_PARAM_utf8_string("output", NULL, 0), /* PEM or DER */
//         OSSL_PARAM_END
//     };
// 	printf("83-bign-encoder gettable\n");
//     return params;
// }

/* Settable parameters for the encoder context */
static const OSSL_PARAM *bign_params_encoder_settable_ctx_params(void *provctx) {
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("output", NULL, 0), /* PEM or DER */
        OSSL_PARAM_int("save-parameters", NULL), 
        OSSL_PARAM_END
    };
	printf("83-bign-encoder settable\n");
    return params;
}

/* Set encoder parameters */
static int bign_params_encoder_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    const OSSL_PARAM *p;

    MY_KEY_ENCODER_CTX *ctx = (MY_KEY_ENCODER_CTX *)vctx;
	print_params(params);
    if ((p = OSSL_PARAM_locate_const(params, "output")) != NULL) {
        /* This template only supports PEM encoding */
        if (strcmp(p->data, "PEM") != 0) {
            ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
            return 0;
        }
    }
	//const OSSL_PARAM *cipherp =
    //    OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_CIPHER);
   	// p = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_PROPERTIES);
	p = OSSL_PARAM_locate_const(params, "save-parameters");
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &ctx->save_parameters))
            return 0;
    }
	printf("84-params-encoder set_ctx_params\n");
    return 1;
}

/* Dispatch table for the encoder functions */
const OSSL_DISPATCH bign_params_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))bign_params_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))bign_params_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))bign_params_encoder_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))bign_params_encoder_encode },
//    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, (void (*)(void))bign_params_encoder_gettable_params },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))bign_params_encoder_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))bign_params_encoder_set_ctx_params },
    { 0, NULL }
};

#endif // OPENSSL_VERSION_MAJOR >= 3
