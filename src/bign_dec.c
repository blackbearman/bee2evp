
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3

/*
The decoder doesn't need to know more about the B<OSSL_CORE_BIO>
pointer than being able to pass it to the appropriate BIO upcalls (see
L<provider-base(7)/Core functions>: <openssl/core_dispatch.h>).

*/

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <openssl/core.h>
#include <openssl/core_object.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/x509.h>

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
#include "bee2evp/bee2evp.h"


/*
При генерации параметров опция outform игнорируется, параметры выводятся 
только в PEM, поэтому необходим их декодер только из формата PEM.
*/

static OSSL_FUNC_decoder_newctx_fn bign_key_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn bign_key_decoder_freectx;
//static OSSL_FUNC_decoder_get_params_fn *bign_key_decoder_get_params;
//static OSSL_FUNC_decoder_gettable_params_fn *bign_key_decoder_gettable_params;
static OSSL_FUNC_decoder_set_ctx_params_fn bign_key_decoder_set_ctx_params;
static OSSL_FUNC_decoder_settable_ctx_params_fn bign_key_decoder_settable_ctx_params;
static OSSL_FUNC_decoder_does_selection_fn bign_key_decoder_does_selection;
static OSSL_FUNC_decoder_decode_fn bign_key_decoder_decode;
//static OSSL_FUNC_decoder_export_object_fn export_object;


/* Encoder-specific context */
typedef struct {
    const EVP_PKEY *pkey; /* The private key to encode */
	//OSSL_LIB_CTX *libctx;
	int save_parameters;
} MY_KEY_ENCODER_CTX;

/* Create a new decoder context */
static void *bign_key_decoder_newctx(void *provctx) {
    //PROV_CTX *pctx = (PROV_CTX *)provctx;
    MY_KEY_ENCODER_CTX *ctx = OPENSSL_zalloc(sizeof(MY_KEY_ENCODER_CTX));
	printf("91-bign-decoder newctx\n");
    if (ctx == NULL) {
        return NULL;
    }
    ctx->pkey = NULL;
	//ctx->libctx = pctx->libctx;
    return ctx;
}

/* Free the decoder context */
static void bign_key_decoder_freectx(void *vctx) {
    MY_KEY_ENCODER_CTX *ctx = (MY_KEY_ENCODER_CTX *)vctx;
	printf("91-bign-decoder freectx\n");
    if (ctx) {
        OPENSSL_free(ctx);
    }
}

/* Check if the decoder supports the given selection and key type */
static int bign_key_decoder_does_selection(void *vctx, int selection) {
    /* This decoder supports private key encoding */
	printf("92-bign-decoder does_selection %d\n", selection);
    printf("92-bign-decoder does_selection %d\n", selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
    printf("92-bign-decoder does_selection %d\n", selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS);
    
	return (selection & OSSL_KEYMGMT_SELECT_KEYPAIR
		|| selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) ? 1 : 0;
}


static int evpBign_pub_decode0(bign_key* key, int params_type, 
	const void* params)
{
	// параметры заданы явно?
	if (params_type == V_ASN1_SEQUENCE)
	{
		const ASN1_STRING* str = (const ASN1_STRING*)params;
		const octet* in = str->data;
		int in_len = str->length;
		bool_t specified;
		return evpBign_asn1_d2i_params(key, &specified, &in, in_len) &&
			specified;
	}
	// параметры заданы неявно?
	if (params_type == V_ASN1_OBJECT)
	{
		int nid = OBJ_obj2nid((const ASN1_OBJECT*)params);
		return evpBign_nid2params(key->params, nid);
	}
	return 0;
}

static int evpBign_pub_decode(bign_key* key, CONST3 X509_PUBKEY* pk)
{
	const octet* pubkey;
	int pubkey_len;
	const void* params;
	X509_ALGOR* palg;
	int params_type;
	// разобрать SubjectPublicKeyInfo
	if (!X509_PUBKEY_get0_param(0, &pubkey, &pubkey_len, &palg, pk))
		return 0;
	X509_ALGOR_get0(0, &params_type, &params, palg);
	// декодировать параметры открытого ключа
	if (!evpBign_pub_decode0(key, params_type, params))
		goto err;
	// декодировать открытый ключ
	if (!evpBign_asn1_o2i_pubkey(key, &pubkey, pubkey_len))
		goto err;
	return 1;
err:
	if (key)
		blobClose(key);
	return 0;
}

static int evpBign_priv_decode(bign_key* key, const PKCS8_PRIV_KEY_INFO* p8)
{
	const octet* privkey;
	int privkey_len;
	const void* params;
	const X509_ALGOR* palg;
	int params_type;
	// разобрать PrivateKeyInfo
	if (!PKCS8_pkey_get0(0, &privkey, &privkey_len, &palg, p8))
		return 0;
	X509_ALGOR_get0(0, &params_type, &params, palg);
	// декодировать параметры открытого ключа
	if (!evpBign_pub_decode0(key, params_type, params))
		goto err;
	// проверить длину личного ключа
	if (privkey_len * 4 != (int)key->params->l)
		goto err;
	// сохранить личный ключ
	memCopy(key->privkey, privkey, privkey_len);
	// вычислить открытый ключ
	if (bignPubkeyCalc(key->pubkey, key->params, key->privkey) != ERR_OK)
		goto err;
	return 1;
err:
	if (key)
		blobClose(key);
	return 0;
}


/* Encode the key into PEM PrivateKeyInfo */
static int bign_key_decoder_decode(void *vctx, OSSL_CORE_BIO *in, 
    int selection, OSSL_CALLBACK *data_cb, void *data_cbarg, 
    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    int ok = 0;
	unsigned char buf[1000];
	size_t read = 0;
    const unsigned char* walker;
    int ret = 0;
    PKCS8_PRIV_KEY_INFO* p8;
    bign_key* key = 0;
    X509_PUBKEY* pubkey;
	//bool_t specified = TRUE;
    printf("45-bign-decoder decode %d\n", selection);
    printf("45-bign-decoder data_cbarg %p\n", data_cbarg);
    printf("45-bign-decoder in %p\n", in);
    
    if (in == NULL) {
        return 0;
    }
    if(!ossl_prov_bio_read_ex(in, buf, 1000, &read))
        return 0;

    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR)) {
        return 0;
    }
    // создать ключ
	key = (bign_key*)blobCreate(sizeof(bign_key));
	if (!key)
		return 0;
	memSetZero(key, sizeof(bign_key));
    printf("45-bign-decoder read (%lu) %.*s\n", read, (int)read, buf);
    walker = buf;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) 
    {
        p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &walker, read);
        if (!p8)
            goto err;
        printf("45-bign-decoder p8 decoded\n");
        // декодировать параметры личного ключа
        if (!evpBign_priv_decode(key, p8))
            goto err;
    }  
    else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)   
    {
        pubkey = d2i_X509_PUBKEY(NULL, &walker, read);
        if (!pubkey)
            goto err;
        // декодировать параметры открытого ключа
        printf("45-bign-decoder convert from x509 pk\n");
        if(!evpBign_pub_decode(key, pubkey))
            goto err;
    }
 
	printf("45-bign-decoder write to output\n");
    if (key != NULL) {
        OSSL_PARAM params[4];
        int object_type = OSSL_OBJECT_UNKNOWN;

        params[0] =
            OSSL_PARAM_construct_int("type", &object_type);
        params[1] =
            OSSL_PARAM_construct_utf8_string("data-type",
                                             (char *)"bign",
                                             0);
        
        /* The address of the key becomes the octet string */
        params[2] =
            OSSL_PARAM_construct_octet_string("reference",
                                              &key, sizeof(bign_key));
        params[3] = OSSL_PARAM_construct_end();

    /*
     * For stuff that should end up in an EVP_PKEY, we only accept an object
     * reference for the moment.  This enforces that the key data itself
     * remains with the provider.
     */

     // Load function is used in the decoding process
        ok = data_cb(params, data_cbarg);
    }
    //ret = data_cb(NULL, pkey);
	printf("45-bign-decoder finish %d\n", ok);
    return 1;
err:
    if (key)
 		blobClose(key);
    return ret;
}

/* Settable parameters for the decoder context */
static const OSSL_PARAM *bign_key_decoder_settable_ctx_params(void *provctx) {
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("output", NULL, 0), /* PEM or DER */
        OSSL_PARAM_int("save-parameters", NULL), 
        OSSL_PARAM_END
    };
	printf("93-bign-decoder settable\n");
    return params;
}

/* Set decoder parameters */
static int bign_key_decoder_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    const OSSL_PARAM *p;

    MY_KEY_ENCODER_CTX *ctx = (MY_KEY_ENCODER_CTX *)vctx;
	print_params(params);
    if ((p = OSSL_PARAM_locate_const(params, "output")) != NULL) {
        /* This template only supports PEM encoding */
        if (strcmp(p->data, "DER") != 0) {
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
	printf("94-bign-decoder set_ctx_params\n");
    return 1;
}

const OSSL_DISPATCH bign_key_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))bign_key_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))bign_key_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))bign_key_decoder_decode },
    { OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
      (void (*)(void))bign_key_decoder_settable_ctx_params },
    { OSSL_FUNC_DECODER_SET_CTX_PARAMS,
      (void (*)(void))bign_key_decoder_set_ctx_params },
    { OSSL_FUNC_DECODER_DOES_SELECTION, 
        (void (*)(void)) bign_key_decoder_does_selection},
    { 0, NULL }
};

#endif // OPENSSL_VERSION_MAJOR >= 3
