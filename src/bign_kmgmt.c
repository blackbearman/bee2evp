#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdlib.h>

#include <bee2/core/blob.h>
#include <bee2/core/der.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bign.h>
#include "bee2evp_lcl.h"
#include "bee2evp/bee2evp.h"
#include "bee2evp/bee2prov.h"

/*
At least one constructor and the destructor are MANDATORY
     * The functions 'has' is MANDATORY
*/

/* Key-specific context */
typedef struct {
    EVP_PKEY *pkey; /* Private key */
} MY_KEY_CTX;

typedef struct bign_pkey_ctx
{
	int params_nid;		/*< идентификатор параметров */	
	int hash_nid;		/*< рекомендуемый хэш-алгоритм для ЭЦП */
	u8 flags;			/*< флаги */
	const EVP_MD* md;	/*< алгоритм хэширования для ЭЦП */
	blob_t kdf_ukm;		/*< данные для bake-kdf: ukm */
	int kdf_num;		/*< данные для bake-kdf: номер ключа */
} bign_pkey_ctx;

typedef struct bign_gen_ctx
{
	int params_nid;		/*< идентификатор параметров */	
	u8 flags;			/*< флаги */
    char curve[16];
	bign_params params;
    int selection;
    int decoded;
} bign_gen_ctx;

#define BIGN_POSSIBLE_SELECTIONS                                                \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

static OSSL_FUNC_keymgmt_new_fn provBign_key_newctx;
static OSSL_FUNC_keymgmt_gen_init_fn provBign_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn provBign_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn provBign_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn provBign_key_generate;
static OSSL_FUNC_keymgmt_gen_cleanup_fn provBign_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn provBign_key_load;
static OSSL_FUNC_keymgmt_free_fn provBign_key_freectx;
static OSSL_FUNC_keymgmt_get_params_fn provBign_key_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn provBign_key_gettable_params;
static OSSL_FUNC_keymgmt_has_fn provBign_key_has;
// static OSSL_FUNC_keymgmt_match_fn rsa_match;
// static OSSL_FUNC_keymgmt_validate_fn rsa_validate;
static OSSL_FUNC_keymgmt_import_fn provBign_import;
// static OSSL_FUNC_keymgmt_import_types_fn rsa_import_types;
static OSSL_FUNC_keymgmt_export_fn provBign_key_export;
// static OSSL_FUNC_keymgmt_export_types_fn rsa_export_types;
// static OSSL_FUNC_keymgmt_query_operation_name_fn rsa_query_operation_name;
// static OSSL_FUNC_keymgmt_dup_fn rsa_dup;


// OSSL_FUNC_keymgmt_has() should check whether the given I<keydata> contains the subsets
// of data indicated by the I<selector>.  A combination of several
// selector bits must consider all those subsets, not just one.  An
// implementation is, however, free to consider an empty subset of data
// to still be a valid subset. For algorithms where some selection is
// not meaningful such as B<OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS> for
// RSA keys the function should just return 1 as the selected subset
// is not really missing in the key.
/*
OSSL_FUNC_KEYMGMT_FREE is mandatory
OSSL_FUNC_KEYMGMT_NEW || OSSL_FUNC_KEYMGMT_LOAD || OSSL_FUNC_KEYMGMT_IMPORT
is mandatory
OSSL_FUNC_KEYMGMT_HAS is mandatory
OSSL_FUNC_KEYMGMT_GET_PARAMS requires OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS
OSSL_FUNC_KEYMGMT_SET_PARAMS requires OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS
OSSL_FUNC_KEYMGMT_GEN requires OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_CLEANUP
OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS requires OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS
OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS requires OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS
OSSL_FUNC_KEYMGMT_EXPORT requires OSSL_FUNC_KEYMGMT_EXPORT_TYPES
OSSL_FUNC_KEYMGMT_IMPORT requires OSSL_FUNC_KEYMGMT_IMPORT_TYPES
*/
static
int provBign_key_has(const void *keydata, int selection)
{
    const bign_key *key = keydata;
    int ok = 1;
    printf("42-bign-key-has\n");
    if (key == NULL)
        return 0;
    if ((selection & BIGN_POSSIBLE_SELECTIONS) == 0)
        return 0; /* the selection is not matching */

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && !memIsZero(key->pubkey, sizeof(key->pubkey));
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && !memIsZero(key->privkey, sizeof(key->privkey));
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && !memIsZero(key->params, sizeof(key->params));
    /*
     * We consider OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS to always be
     * available, so no extra check is needed other than the previous one
     * against EC_POSSIBLE_SELECTIONS.
     */
    return ok;
}

/* Create a new key context */
static void *provBign_key_newctx(void *provctx) {
    bign_key *ctx = blobCreate(sizeof(bign_key));
    printf("41-bign-key-newctx\n");
    if (ctx == NULL) {
        return NULL;
    }
    memSetZero(ctx, sizeof(bign_key));
    return ctx;
}

/* Free the key context */
static void provBign_key_freectx(void *vctx) {
    bign_key *ctx = (bign_key *)vctx;
    if (ctx) {
        blobClose(ctx);
    }
}

 /* Key loading by object reference, also a constructor */
 void *provBign_key_load(const void *reference, size_t size) {
    bign_key *ctx;
    printf("111-bign-kmgmt Load to BIGN key %lu bytes from %lu\n", size, sizeof(bign_key));

    if (size == sizeof(bign_key)) {
        /* The contents of the reference is the address to our object */
        ctx = *(bign_key **)reference;

        /* We grabbed, so we detach it */
        *(bign_key **)reference = NULL;
        bignParamsPrint(ctx->params);
        return ctx;
    }
    return NULL;
}

////////// GEN ///////////////////////////


static void *provBign_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    //OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct bign_gen_ctx *gctx = NULL;
    printf("71-bign_gen-init %d\n", selection);
    print_params(params);

    if ((selection & BIGN_POSSIBLE_SELECTIONS) == 0)
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->selection = selection;
        //gctx->libctx = libctx;
    }
    printf("71-bign_gen-init params not initialized\n");
    // if (!provBign_gen_set_params(gctx, params)) {
    //     provBign_gen_cleanup(gctx);
    //     gctx = NULL;
    // }
    return gctx;
}

static int bn_param(const OSSL_PARAM* params, const char* name, octet* value) {
    const OSSL_PARAM *p;
    BIGNUM *b = NULL;
    p = OSSL_PARAM_locate_const(params, name);
    if (p != NULL) {
        b = BN_new();
        if (!b || !OSSL_PARAM_get_BN(p, &b)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
    }
    return 1;
}

void print_params(const OSSL_PARAM params[]) {
    int i = 0;
    int int_val;
    if (params) {
        while (params[i].key) {
            printf("Param %s: type %u : size %lu : value ", params[i].key, params[i].data_type, params[i].data_size);
            switch (params[i].data_type) {
            case OSSL_PARAM_INTEGER:
                OSSL_PARAM_get_int(&params[i], &int_val);
                printf("%d \n", int_val);
                break;
            case OSSL_PARAM_UTF8_STRING:
                printf("%.*s \n", (int)params[i].data_size, (char*)params[i].data);
                break;
            default:
                for(size_t j = 0; j < params[i].data_size; j++)
                    printf("%02x:", *((unsigned char*)params[i].data + j));
                printf("\n");
                break;
            }
            i++;
        }
    }
}


static int provBign_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct bign_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;
    size_t size = 0;

    printf("73-bign_gen-set_params %p %p\n", genctx, params);
    print_params(params);

    if (gctx == NULL)
        return 0;

    printf("73-bign_gen-set_params extract parameters\n");
    
    p = OSSL_PARAM_locate_const(params, "params");
    if (p != NULL) {
        // if (OSSL_PARAM_get_utf8_string(p, &gctx->curve, 15) ) {
        //     printf("String extracted %s", gctx->curve);
        // } else {
        //     printf("String is not extracted %p", p->data);
        // }
        if (p->data_type != OSSL_PARAM_UTF8_STRING || p->data_size > 15) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
        memCopy(gctx->curve, p->data, p->data_size);
        gctx->curve[p->data_size] = 0;
    }
    printf("73-bign_gen-set_params String extracted %s\n", gctx->curve);
    if (!bn_param(params, "p", gctx->params.p) ||
        !bn_param(params, "a", gctx->params.a) ||
        !bn_param(params, "b", gctx->params.b) ||
        !bn_param(params, "order", gctx->params.q)) 
    {
        return 0;
    }
    printf("73-bign_gen-set_params All domain parameters are processed\n");
    p = OSSL_PARAM_locate_const(params, "seed");
    if (p != NULL
        && !OSSL_PARAM_get_octet_string(p, (void**) &gctx->params.seed, 8, &size))
        return 0;
    p = OSSL_PARAM_locate_const(params, "decoded-from-explicit");
    if (p != NULL
        && !OSSL_PARAM_get_int(p, &gctx->decoded))
        return 0;
    printf("73-bign_gen-set_params All parameters are processed\n");
    return 1;
}

static const OSSL_PARAM *provBign_gen_settable_params(ossl_unused void *genctx,
                                                 ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string("params", NULL, 0),                         
        OSSL_PARAM_BN("p", NULL, 0),                              
        OSSL_PARAM_BN("a", NULL, 0),                              
        OSSL_PARAM_BN("b", NULL, 0),                                        
        OSSL_PARAM_BN("order", NULL, 0),                                           
        OSSL_PARAM_octet_string("seed", NULL, 0),                 
        OSSL_PARAM_int("decoded-from-explicit", NULL),
        OSSL_PARAM_END
    };
    printf("72-bign_gen-settable\n");
    return settable;
}



/* Generate a private key */
static void* provBign_key_generate(void *vctx, OSSL_CALLBACK *cb, void *cbarg) {
    bign_gen_ctx *ctx = (bign_gen_ctx *)vctx;
    bign_key* key;
    printf("74-bign_gen Start\n");
	// разобрать указатели
	ASSERT(memIsValid(ctx, sizeof(bign_gen_ctx)));
	// генератор не работает? 
	if (!rngIsValid())
		return 0;
    printf("74-bign_gen Generator checked.\n");
	// создать ключ
    key = (bign_key*)blobCreate(sizeof(bign_key));
	if (!key)
		return 0;
	printf("74-bign_gen Key created.\n");
	// ключ уже есть в контексте
	if (!ctx->curve[0])
	{
		// переписать параметры
		memCopy(&key->params, &ctx->params, sizeof(bign_params));
	}
	// ключа нет в контексте
	else
	{
        
		// загрузить параметры
		if (bignParamsStd(&key->params[0], "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK)
		{
			blobClose(key);
			return 0;
		}
	}
    printf("74-bign_gen Last step\n");
    key->flags = EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED 
        || EVP_BIGN_PKEY_ENC_PARAMS_COFACTOR;
	// сгенерировать пару ключей
	if(bignKeypairGen(key->privkey, key->pubkey, key->params, 
		rngStepR, 0) == ERR_OK) 
    {
        printf("74-bign_gen Key is generated\n");
		return key;
    }
    printf("74-bign_gen Key is not generated\n");
    blobClose(key);
    return 0;
}

static void provBign_gen_cleanup(void *genctx)
{
    struct bign_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return;
    OPENSSL_free(gctx);
}

////////////////////// PARAMS /////////////////////////////////////////

// static const OSSL_PARAM rsa_params[] = {
//     OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
//     OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
//     OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
//     OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
//     RSA_KEY_TYPES()
//     OSSL_PARAM_END
// };

// static const OSSL_PARAM *rsa_gettable_params(void *provctx)
// {
//     return rsa_params;
// }

/* Gettable parameters for the key context */
static const OSSL_PARAM *provBign_key_gettable_params(void *provctx) {
    static const OSSL_PARAM params[] = {
        // OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        // OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        // OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string("mandatory-digest", NULL, 0),
        // OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0), 
        // OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0), 
        // OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0), 
        // OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, NULL, 0), 
        // OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, NULL, 0), 
        // OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, NULL, 0), 
        // OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, NULL, 0), 
        // OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, NULL, 0), 
        // OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, NULL, 0), 
        // OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, NULL, 0), 
        // OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, NULL, 0), 
        // OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, NULL),
        // OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        // OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        // OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL), 
        // OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
        // OSSL_PARAM_octet_string("privkey", NULL, 0), /* DER-encoded private key */
        OSSL_PARAM_END
    };
    return params;
}


/* Set parameters for loading a private key */
static int provBign_key_get_params(void *keydata, OSSL_PARAM params[]) {
    bign_key *key = (bign_key *)keydata;
    const OSSL_PARAM *p;
    printf("74-bign_mgmt get params\n");
    print_params(params);

    if ((p = OSSL_PARAM_locate_const(params, "mandatory-digest")) != NULL) {
        if (key) {
            if ((key->params->l == 128) && !OSSL_PARAM_set_utf8_string(p, "belt-hash"))
                return 0;
            if ((key->params->l == 192) && !OSSL_PARAM_set_utf8_string(p, "bash386"))
                return 0; 
            if ((key->params->l == 256) && !OSSL_PARAM_set_utf8_string(p, "bash512"))
                return 0;       
        }
    }
    return 1;
}

/* Public key extraction */
static int provBign_export(void *vctx, int selection, OSSL_CALLBACK *export_cb, void *cbarg) {
    MY_KEY_CTX *ctx = (MY_KEY_CTX *)vctx;
    OSSL_PARAM params[1];
    EVP_PKEY *pubkey;
    unsigned char *der = NULL;
    int der_len;
    int result;
    printf("74-bign_mgmt Call export function\n");

    if (ctx->pkey == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0; /* No private key loaded */
    }

    /* Extract the public key from the private key */
    pubkey = EVP_PKEY_new();
    if (pubkey == NULL) {
        return 0;
    }

    /* Duplicate the key and set it to the public key */
    if (!EVP_PKEY_copy_parameters(pubkey, ctx->pkey)) {
        EVP_PKEY_free(pubkey);
        return 0;
    }

    /* Export the public key in DER format */
    der_len = i2d_PUBKEY(pubkey, &der);
    if (der_len <= 0) {
        EVP_PKEY_free(pubkey);
        return 0;
    }

    /* Callback to export the public key */
    params[0] = OSSL_PARAM_construct_octet_string("pubkey", der, der_len);
    result = export_cb(params, cbarg);

    /* Cleanup */
    EVP_PKEY_free(pubkey);
    OPENSSL_free(der);

    return result;

//     RSA *rsa = keydata;
//     const RSA_PSS_PARAMS_30 *pss_params = ossl_rsa_get0_pss_params_30(rsa);
//     OSSL_PARAM_BLD *tmpl;
//     OSSL_PARAM *params = NULL;
//     int ok = 1;

//     if (!ossl_prov_is_running() || rsa == NULL)
//         return 0;

//     if ((selection & RSA_POSSIBLE_SELECTIONS) == 0)
//         return 0;

//     tmpl = OSSL_PARAM_BLD_new();
//     if (tmpl == NULL)
//         return 0;

//     if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
//         ok = ok && (ossl_rsa_pss_params_30_is_unrestricted(pss_params)
//                     || ossl_rsa_pss_params_30_todata(pss_params, tmpl, NULL));
//     if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
//         int include_private =
//             selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

//         ok = ok && ossl_rsa_todata(rsa, tmpl, NULL, include_private);
//     }

//     if (!ok || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
//         ok = 0;
//         goto err;
//     }

//     ok = param_callback(params, cbarg);
//     OSSL_PARAM_free(params);
// err:
//     OSSL_PARAM_BLD_free(tmpl);
//     return ok;
}


# define EC_IMEXPORTABLE_DOM_PARAMETERS                                        \
    OSSL_PARAM_utf8_string("params", NULL, 0),               \
    OSSL_PARAM_BN("p", NULL, 0),                              \
    OSSL_PARAM_BN("a", NULL, 0),                              \
    OSSL_PARAM_BN("b", NULL, 0),                              \
    OSSL_PARAM_BN("order", NULL, 0),                          \
    OSSL_PARAM_BN("cofactor", NULL, 0),                       \
    OSSL_PARAM_octet_string("seed", NULL, 0),                 \
    OSSL_PARAM_int("decoded-from-explicit", NULL)

# define EC_IMEXPORTABLE_PUBLIC_KEY                                            \
    OSSL_PARAM_octet_string("pub", NULL, 0)
# define EC_IMEXPORTABLE_PRIVATE_KEY                                           \
    OSSL_PARAM_BN("priv", NULL, 0)


static const OSSL_PARAM ec_private_key_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_public_key_types[] = {
    EC_IMEXPORTABLE_PUBLIC_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_key_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_PUBLIC_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_dom_parameters_types[] = {
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_5_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_6_types[] = {
    EC_IMEXPORTABLE_PUBLIC_KEY,
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_key_domp_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_PUBLIC_KEY,
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    OSSL_PARAM_END
};

static const OSSL_PARAM *ec_types[] = {
    NULL,
    ec_private_key_types,
    ec_public_key_types,
    ec_key_types,
    ec_dom_parameters_types,
    ec_5_types,
    ec_6_types,
    ec_key_domp_types
};


static const OSSL_PARAM *provBign_export_types(int selection)
{
    int type_select = 0;
    printf("98-bign_export_types %d", selection);
    
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        type_select += 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        type_select += 2;
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        type_select += 4;
    return ec_types[type_select];
}

static int provBign_gen_set_template(void *genctx, void *templ)
{
    struct bign_gen_ctx *gctx = genctx;
    bign_key *key = templ;

    if (gctx == NULL || key == NULL)
        return 0;
    printf("99-gen_set_template params init");
    gctx->params = *(key->params);
    bignParamsPrint(key->params);
    return 1;
}


// /*
//  * Callers of ossl_ec_key_fromdata MUST make sure that ec_key_params_fromdata has
//  * been called before!
//  *
//  * This function only gets the bare keypair, domain parameters and other
//  * parameters are treated separately, and domain parameters are required to
//  * define a keypair.
//  */
// int ossl_ec_key_fromdata(EC_KEY *ec, const OSSL_PARAM params[], int include_private)
// {
//     const OSSL_PARAM *param_priv_key = NULL, *param_pub_key = NULL;
//     BN_CTX *ctx = NULL;
//     BIGNUM *priv_key = NULL;
//     unsigned char *pub_key = NULL;
//     size_t pub_key_len;
//     const EC_GROUP *ecg = NULL;
//     EC_POINT *pub_point = NULL;
//     int ok = 0;

//     ecg = EC_KEY_get0_group(ec);
//     if (ecg == NULL)
//         return 0;

//     param_pub_key =
//         OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
//     if (include_private)
//         param_priv_key =
//             OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);

//     ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(ec));
//     if (ctx == NULL)
//         goto err;

//     if (param_pub_key != NULL)
//         if (!OSSL_PARAM_get_octet_string(param_pub_key,
//                                          (void **)&pub_key, 0, &pub_key_len)
//             || (pub_point = EC_POINT_new(ecg)) == NULL
//             || !EC_POINT_oct2point(ecg, pub_point, pub_key, pub_key_len, ctx))
//         goto err;

//     if (param_priv_key != NULL && include_private) {
//         int fixed_words;
//         const BIGNUM *order;

//         /*
//          * Key import/export should never leak the bit length of the secret
//          * scalar in the key.
//          *
//          * For this reason, on export we use padded BIGNUMs with fixed length.
//          *
//          * When importing we also should make sure that, even if short lived,
//          * the newly created BIGNUM is marked with the BN_FLG_CONSTTIME flag as
//          * soon as possible, so that any processing of this BIGNUM might opt for
//          * constant time implementations in the backend.
//          *
//          * Setting the BN_FLG_CONSTTIME flag alone is never enough, we also have
//          * to preallocate the BIGNUM internal buffer to a fixed public size big
//          * enough that operations performed during the processing never trigger
//          * a realloc which would leak the size of the scalar through memory
//          * accesses.
//          *
//          * Fixed Length
//          * ------------
//          *
//          * The order of the large prime subgroup of the curve is our choice for
//          * a fixed public size, as that is generally the upper bound for
//          * generating a private key in EC cryptosystems and should fit all valid
//          * secret scalars.
//          *
//          * For padding on export we just use the bit length of the order
//          * converted to bytes (rounding up).
//          *
//          * For preallocating the BIGNUM storage we look at the number of "words"
//          * required for the internal representation of the order, and we
//          * preallocate 2 extra "words" in case any of the subsequent processing
//          * might temporarily overflow the order length.
//          */
//         order = EC_GROUP_get0_order(ecg);
//         if (order == NULL || BN_is_zero(order))
//             goto err;

//         fixed_words = bn_get_top(order) + 2;

//         if ((priv_key = BN_secure_new()) == NULL)
//             goto err;
//         if (bn_wexpand(priv_key, fixed_words) == NULL)
//             goto err;
//         BN_set_flags(priv_key, BN_FLG_CONSTTIME);

//         if (!OSSL_PARAM_get_BN(param_priv_key, &priv_key))
//             goto err;
//     }

//     if (priv_key != NULL
//         && !EC_KEY_set_private_key(ec, priv_key))
//         goto err;

//     if (pub_point != NULL
//         && !EC_KEY_set_public_key(ec, pub_point))
//         goto err;

//     ok = 1;

//  err:
//     BN_CTX_free(ctx);
//     BN_clear_free(priv_key);
//     OPENSSL_free(pub_key);
//     EC_POINT_free(pub_point);
//     return ok;
// }

static
int common_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    EC_KEY *ec = keydata;
    int ok = 1;

    /*
     * In this implementation, we can export/import only keydata in the
     * following combinations:
     *   - domain parameters (+optional other params)
     *   - public key with associated domain parameters (+optional other params)
     *   - private key with associated domain parameters and optional public key
     *         (+optional other params)
     *
     * This means:
     *   - domain parameters must always be requested
     *   - private key must be requested alongside public key
     *   - other parameters are always optional
     */
    // if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
    //     return 0;

    // ok = ok && ossl_ec_group_fromdata(ec, params);

    // if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
    //     int include_private =
    //         selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

    //     ok = ok && ossl_ec_key_fromdata(ec, params, include_private);
    // }
    // if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
    //     ok = ok && ossl_ec_key_otherparams_fromdata(ec, params);

    return ok;
}

static
int provBign_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    printf("74-bign_mgmt Call import function\n");
    return common_import(keydata, selection, params);
}

/* Dispatch table for key operations */
const OSSL_DISPATCH bign_key_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))provBign_key_newctx },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))provBign_key_freectx },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))provBign_key_load },
//    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))provBign_key_get_params },
//    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))provBign_key_gettable_params },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))provBign_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))provBign_export_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))provBign_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))provBign_export_types },
    
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))provBign_key_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))provBign_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))provBign_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))provBign_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))provBign_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))provBign_key_generate },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))provBign_gen_cleanup },
    { 0, NULL }
};

#endif // OPENSSL_VERSION_MAJOR >= 3