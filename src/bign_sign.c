
#include "bee2evp/bee2prov.h"

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <string.h>
#include <stdlib.h>

#include "bee2/core/blob.h"
#include <bee2/core/der.h>
#include "bee2/core/mem.h"
#include <bee2/core/rng.h>
#include "bee2/core/util.h"

#include "bee2evp_lcl.h"
#include "bee2evp/bee2evp.h"

/* Signature-specific context */
typedef struct {
    bign_key* key;
    const OSSL_CORE_HANDLE *core;
    const char *digest_name;       /* Digest name (e.g., "SHA256") */
    EVP_MD_CTX *md_ctx;            /* Message digest context */
    int salt_len;                  /* Salt length for PSS */

	int params_nid;		/*< идентификатор параметров */	
	int hash_nid;		/*< рекомендуемый хэш-алгоритм для ЭЦП */
	u8 flags;			/*< флаги */
	const EVP_MD* md;	/*< алгоритм хэширования для ЭЦП */
	blob_t kdf_ukm;		/*< данные для bake-kdf: ukm */
	int kdf_num;		/*< данные для bake-kdf: номер ключа */
} BIGN_CTX;

typedef struct bign_pkey_ctx
{
    int params_nid;		/*< идентификатор параметров */	
	int hash_nid;		/*< рекомендуемый хэш-алгоритм для ЭЦП */
	u8 flags;			/*< флаги */
	const EVP_MD* md;	/*< алгоритм хэширования для ЭЦП */
	blob_t kdf_ukm;		/*< данные для bake-kdf: ukm */
	int kdf_num;		/*< данные для bake-kdf: номер ключа */
    bign_key* key;
    EVP_MD_CTX *mdctx;
} bign_pkey_ctx;

/* Helper function to free the signature context */
void provBign_freectx(void *vctx) {
	bign_pkey_ctx* dctx = (bign_pkey_ctx*)vctx;
	if (dctx)
	{
		ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
        EVP_MD_CTX_free(dctx->mdctx);
		blobClose(dctx->kdf_ukm);
		blobClose(dctx);
	}
}

/* Helper function to create a new signature context */
void *provBign_newctx(void *provctx, const char *propquery) {
    
	bign_pkey_ctx* dctx;
	// создать контекст
	dctx = (bign_pkey_ctx*)blobCreate(sizeof(bign_pkey_ctx));
	if (!dctx)
		return 0;
	// инициализировать поля
	dctx->params_nid = NID_undef;
	dctx->hash_nid = NID_undef;
	dctx->flags = 0;
	dctx->md = 0;
	dctx->kdf_ukm = 0;
	dctx->kdf_num = 0;
    dctx->key = 0;
    dctx->mdctx = NULL;
    printf("110-bign-sign newctx\n");
    return dctx;
}


static int
provBign_signverify_init(bign_pkey_ctx *ctx, void *ec,
                      OSSL_FUNC_signature_set_ctx_params_fn *set_ctx_params,
                      const OSSL_PARAM params[], int operation,
                      const char *desc)
{

    if (ec == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (ec != NULL) {
        blobClose(ctx->key);
        ctx->key = ec;
    }
    bignParamsPrint(ctx->key->params);

    //ctx->operation = operation;

    if (!set_ctx_params(ctx, params))
        return 0;
    return 1;
}


static int provBign_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    printf("116-bign-sign set_ctx_params\n");
    bign_pkey_ctx *ctx = (bign_pkey_ctx *)vctx;
    const OSSL_PARAM *p;
    size_t mdsize = 0;
    int ret;

    if (ctx == NULL)
        return 0;
    
    printf("116-bign-sign show params\n");
    print_params(params);
    
    // if ((ret = ecdsa_common_set_ctx_params(ctx, params)) <= 0)
    //     return ret;

    // p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    // if (p != NULL) {
    //     char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
    //     char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
    //     const OSSL_PARAM *propsp =
    //         OSSL_PARAM_locate_const(params,
    //                                 OSSL_SIGNATURE_PARAM_PROPERTIES);

    //     if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
    //         return 0;
    //     if (propsp != NULL
    //         && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
    //         return 0;
    //     if (!ecdsa_setup_md(ctx, mdname, mdprops, "ECDSA Set Ctx"))
    //         return 0;
    // }

    // p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    // if (p != NULL) {
    //     if (!OSSL_PARAM_get_size_t(p, &mdsize)
    //         || (!ctx->flag_allow_md && mdsize != ctx->mdsize))
    //         return 0;
    //     ctx->mdsize = mdsize;
    // }
    return 1;
}

/* Signature initialization (signing) */
int provBign_sign_init(void *vctx, void *provkey, const OSSL_PARAM params[]) {
    bign_pkey_ctx* dctx = (bign_pkey_ctx*)vctx;
    printf("110-bign-sign sign init");
    return provBign_signverify_init(dctx, provkey, provBign_set_ctx_params, params,
                                 EVP_PKEY_OP_SIGN, "BIGN Sign Init");

    /* Set the private key for signing */
    // dctx->key = (bign_key *)provkey;
    // if (dctx->key == NULL) {
    //     return 0;
    // }
    // printf("110-bign-sign sign init");
    /* Process additional parameters if needed */
    // if (params) {
    //     const OSSL_PARAM *p;
    //     if ((p = OSSL_PARAM_locate_const(params, "digest")) != NULL) {
    //         ctx->digest_name = OPENSSL_strdup(p->data);
    //     }
    // }
//     if (dctx->mdctx == NULL) {
//         dctx->mdctx = EVP_MD_CTX_new();
//         if (dctx->mdctx == NULL)
//             goto error;
//     }

//     if (!EVP_DigestInit_ex2(dctx->mdctx, dctx->md, params))
//         goto error;

//     return 1;

//  error:
//     EVP_MD_CTX_free(dctx->mdctx);
//     dctx->mdctx = NULL;
//     return 0;
}

/* Signature initialization (verification) */
int provBign_verify_init(void *vctx, void *provkey, const OSSL_PARAM params[]) {
    return provBign_sign_init(vctx, provkey, params);
}

/* Perform signing */
int provBign_sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                              const unsigned char *tbs, size_t tbslen) {
    BIGN_CTX *ctx = (BIGN_CTX *)vctx;
	//EVP_MD_CTX *md_ctx = ctx->md_ctx;
    const EVP_MD *md = EVP_get_digestbyname(ctx->digest_name);
    printf("112-bign-sign sign");

    if (ctx->key == NULL || sig == NULL || siglen == NULL || tbs == NULL) {
        return 0;
    }

    if (md == NULL) {
        return 0; /* Digest not supported */
    }

    // if (EVP_DigestSignInit(md_ctx, NULL, md, NULL, ctx->key) <= 0) {
    //     return 0;
    // }

    // if (EVP_DigestSignUpdate(md_ctx, tbs, tbslen) <= 0) {
    //     return 0;
    // }

    // if (EVP_DigestSignFinal(md_ctx, sig, siglen) <= 0) {
    //     return 0;
    // }

    if (*siglen > sigsize) {
        return 0; /* Output buffer too small */
    }

    return 1;
}

/* Perform verification */
int provBign_verify(void *vctx, const unsigned char *sig, size_t siglen,
                                const unsigned char *tbs, size_t tbslen) {
    BIGN_CTX *ctx = (BIGN_CTX *)vctx;
    //EVP_MD_CTX *md_ctx = ctx->md_ctx; 
    const EVP_MD *md = EVP_get_digestbyname(ctx->digest_name);;

    if (ctx->key == NULL || sig == NULL || tbs == NULL) {
        return 0;
    }

    if (md == NULL) {
        return 0; /* Digest not supported */
    }

    // if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, ctx->key) <= 0) {
    //     return 0;
    // }

    // if (EVP_DigestVerifyUpdate(md_ctx, tbs, tbslen) <= 0) {
    //     return 0;
    // }

    // if (EVP_DigestVerifyFinal(md_ctx, sig, siglen) <= 0) {
    //     return 0; /* Signature verification failed */
    // }

    return 1;
}


/* DigestSign/DigestVerify wrappers */

static int provBign_digest_signverify_init(void *vctx, const char *mdname,
                                        void *ec, const OSSL_PARAM params[],
                                        int operation, const char *desc)
{
    bign_pkey_ctx* dctx = (bign_pkey_ctx*)vctx;
    int md_size;

    printf("113-bign-sign digest_signverify_init %s\n", mdname);

    if (!provBign_signverify_init(vctx, ec, provBign_set_ctx_params, params,
                               operation, desc))
        return 0;
    printf("113-bign-sign digest_signverify_init %p\n", mdname);

//     if (mdname != NULL
//         /* was ecdsa_setup_md already called in ecdsa_signverify_init()? */
//         && (mdname[0] == '\0' || OPENSSL_strcasecmp(ctx->mdname, mdname) != 0)
//         && !ecdsa_setup_md(ctx, mdname, NULL, desc))
//         return 0;

//     ctx->flag_allow_md = 0;

    dctx->md = EVP_MD_fetch(NULL, mdname, NULL);
    if (dctx->md == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s could not be fetched", mdname);
        return 0;
    }
    md_size = EVP_MD_get_size(dctx->md);
    if (md_size <= 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s has invalid md size %d", mdname, md_size);
        goto error;
    }

    if (dctx->mdctx == NULL) {
        dctx->mdctx = EVP_MD_CTX_new();
        if (dctx->mdctx == NULL)
            goto error;
    }

    if (!EVP_DigestInit_ex2(dctx->mdctx, dctx->md, params))
        goto error;
    return 1;
error:
    EVP_MD_CTX_free(dctx->mdctx);
    dctx->mdctx = NULL;
    return 0;
}

static int provBign_digest_sign_init(void *vctx, const char *mdname, void *ec,
                                  const OSSL_PARAM params[])
{
    printf("113-bign-sign digest_sign_init\n");
    return provBign_digest_signverify_init(vctx, mdname, ec, params,
                                        EVP_PKEY_OP_SIGNMSG,
                                        "BIGN Digest Sign Init");
}


static int provBign_signverify_message_update(void *vctx,
                                         const unsigned char *data,
                                         size_t datalen)
{
    bign_pkey_ctx* dctx = (bign_pkey_ctx*)vctx;
    printf("113-bign-sign message_update\n");

    if (dctx == NULL)
        return 0;

    return EVP_DigestUpdate(dctx->mdctx, data, datalen);
}


static int provBign_digest_signverify_update(void *vctx, const unsigned char *data,
                                          size_t datalen)
{
    bign_pkey_ctx* dctx = (bign_pkey_ctx*)vctx;

    printf("115-bign-sign digest_signverify_update\n");
    if (dctx == NULL || dctx->mdctx == NULL)
        return 0;

    printf("115-bign-sign digest_signverify_update 2\n");
    return provBign_signverify_message_update(vctx, data, datalen);
}

static int evpBign_pkey_sign(bign_pkey_ctx* dctx, octet* sig, size_t* siglen, 
	const octet* tbs, size_t tbslen)
{
	bign_key* key;
	const ASN1_OBJECT* obj;
	octet* der;
	size_t der_len;
	int ret;
	// разобрать указатели
	ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
	ASSERT(dctx->key);
	key = dctx->key;
	ASSERT(memIsValid(key, sizeof(bign_key)));
	// подготовить возврат подписи
	if (!sig)
	{
		*siglen = key->params->l / 8 * 3;
		return 1;
	}
	else if (*siglen < key->params->l / 8 * 3)
		return 0;
	*siglen = key->params->l / 8 * 3;
	// установить флаги подписи
	key->flags = dctx->flags;
	// проанализировать алгоритм хэширования 
	// и получить суффикс DER-кодировки oid в [obj->len]obj->data
	if (dctx->md == 0 ||
		EVP_MD_size(dctx->md) != (int)key->params->l / 4 || 
		EVP_MD_size(dctx->md) != (int)tbslen)
		return 0;
	if ((obj = OBJ_nid2obj(EVP_MD_type(dctx->md))) == 0)
		return 0;
	// построить полный DER-код
	der_len = derEnc(0, 6, OBJ_get0_data(obj), OBJ_length(obj));
	if (der_len == SIZE_MAX)
		return 0;
	der = (octet*)blobCreate(der_len);
	if (!der)
		return 0;
	derEnc(der, 6, OBJ_get0_data(obj), OBJ_length(obj));
	// подписать
	if ((key->flags & EVP_BIGN_PKEY_SIG_DETERMINISTIC) || !rngIsValid())
		ret = bignSign2(sig, key->params, der, der_len, tbs, 
			key->privkey, 0, 0) == ERR_OK;
	else
		ret = bignSign(sig, key->params, der, der_len, tbs, 
			key->privkey, rngStepR, 0) == ERR_OK;
	// завершить
	blobClose(der);
	return ret;
}

int provBign_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen,
                            size_t sigsize)
{
    bign_pkey_ctx* dctx = (bign_pkey_ctx*)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    int ok = 1;

    if (dctx == NULL)
        return 0;

    // ok = ecdsa_sign_message_final(ctx, sig, siglen, sigsize);

    // ctx->flag_allow_md = 1;
    printf("115-bign-sign digest_sign_final\n");
    printf("115-bign-sign sig %p bytes\n", sig);
    printf("115-bign-sign siglen %u bytes\n", siglen);
    printf("115-bign-sign sigsize %u bytes\n", sigsize);
    // подготовить возврат подписи
    if (!sig)
	{
		*siglen = dctx->key->params->l / 8 * 3;
		return 1;
	}
	else if (*siglen < dctx->key->params->l / 8 * 3)
		return 0;
	*siglen = dctx->key->params->l / 8 * 3;
    if (!EVP_DigestFinal_ex(dctx->mdctx, digest, &dlen))
        return 0;
    printf("115-bign-sign digest %u bytes\n", dlen);
    ok = evpBign_pkey_sign(dctx, sig, &siglen, digest, dlen);
    printf("115-bign-sign result %d \n", ok);
    return ok;
}

static int provBign_digest_verify_init(void *vctx, const char *mdname, void *ec,
                                    const OSSL_PARAM params[])
{
    return provBign_digest_signverify_init(vctx, mdname, ec, params,
                                        EVP_PKEY_OP_VERIFYMSG,
                                        "ECDSA Digest Verify Init");
}

int provBign_digest_verify_final(void *vctx, const unsigned char *sig,
                              size_t siglen)
{
    //PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    int ok = 0;

    // if (!ossl_prov_is_running() || ctx == NULL || ctx->mdctx == NULL)
    //     return 0;

    // /* Sigalg implementations shouldn't do digest_verify */
    // if (ctx->flag_sigalg)
    //     return 0;

    // if (ecdsa_verify_set_sig(ctx, sig, siglen))
    //     ok = ecdsa_verify_message_final(ctx);

    // ctx->flag_allow_md = 1;

    return ok;
}

/* Gettable parameters for signature */
const OSSL_PARAM *provBign_gettable_ctx_params(void *vctx) {
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t("digest-size", NULL),
        OSSL_PARAM_END
    };
    printf("114-bign-sign gettable_ctx_params");
    return params;
}


static int evpBign_pkey_copy(bign_pkey_ctx* dctx, const bign_pkey_ctx* sctx)
{
	ASSERT(memIsValid(sctx, sizeof(bign_pkey_ctx)));
	ASSERT(memIsValid(dctx, sizeof(bign_pkey_ctx)));
	// переписать поля
	dctx->params_nid = sctx->params_nid;
	dctx->hash_nid = sctx->hash_nid;
	dctx->flags = sctx->flags;
	dctx->md = sctx->md;
	if (sctx->kdf_ukm)
	{
		dctx->kdf_ukm = blobCopy(0, sctx->kdf_ukm);
		if (!dctx->kdf_ukm)
			return 0;
	}
	else
		dctx->kdf_ukm = 0;
    dctx->kdf_num = sctx->kdf_num;
    if (sctx->key)
	{
		dctx->key = blobCopy(0, sctx->key);
		if (!dctx->key)
			return 0;
	}
	else
		dctx->key = 0;
	return 1;
}


static void *provBign_dupctx(void *vctx)
{
    printf("118-bign-sign dupctx\n");
    bign_pkey_ctx *srcctx = (bign_pkey_ctx *)vctx;
    bign_pkey_ctx *dstctx = blobCreate(sizeof(bign_pkey_ctx));
    if (dstctx == NULL)
        return NULL;
    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }
    if(evpBign_pkey_copy(dstctx, srcctx))
        return dstctx;
err:
    blobClose(dstctx);
    return NULL;
}

static int provBign_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    printf("115-bign-sign get_ctx_params");
//     PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
//     OSSL_PARAM *p;

//     if (ctx == NULL)
//         return 0;

//     p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
//     if (p != NULL && !OSSL_PARAM_set_octet_string(p,
//                                                   ctx->aid_len == 0 ? NULL : ctx->aid_buf,
//                                                   ctx->aid_len))
//         return 0;

//     p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
//     if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->mdsize))
//         return 0;

//     p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
//     if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->md == NULL
//                                                     ? ctx->mdname
//                                                     : EVP_MD_get0_name(ctx->md)))
//         return 0;

//     p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_NONCE_TYPE);
//     if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->nonce_type))
//         return 0;

// #ifdef FIPS_MODULE
//     p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_FIPS_VERIFY_MESSAGE);
//     if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->verify_message))
//         return 0;
// #endif

//     if (!OSSL_FIPS_IND_GET_CTX_PARAM(ctx, params))
//         return 0;
    return 1;
}


static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string("digest", NULL, 0),
    OSSL_PARAM_size_t("digest-size", NULL),
    OSSL_PARAM_utf8_string("properties", NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *provBign_settable_ctx_params(void *vctx,
                                                   ossl_unused void *provctx)
{
    printf("117-bign-sign settable_ctx_params");
    return settable_ctx_params;
}

static int provBign_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    bign_pkey_ctx* dctx = (bign_pkey_ctx*)vctx;
    printf("118-bign-sign get_ctx_md_params");
    if (dctx->md == NULL)
        return 0;

    return EVP_MD_CTX_get_params(dctx->mdctx, params);
}

static const OSSL_PARAM *provBign_gettable_ctx_md_params(void *vctx)
{
    bign_pkey_ctx* dctx = (bign_pkey_ctx*)vctx;
    printf("119-bign-sign gettable_ctx_md_params");
    if (dctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(dctx->md);
}

static int provBign_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
    bign_pkey_ctx* dctx = (bign_pkey_ctx*)vctx;
    printf("120-bign-sign set_ctx_md_params");
    if (dctx->md == NULL)
        return 0;

    return EVP_MD_CTX_set_params(dctx->mdctx, params);
}

static const OSSL_PARAM *provBign_settable_ctx_md_params(void *vctx)
{
    bign_pkey_ctx* dctx = (bign_pkey_ctx*)vctx;
    printf("121-bign-sign settable_ctx_md_params");
    if (dctx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(dctx->md);
}

/* Signature method dispatch table */
const OSSL_DISPATCH bign_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))provBign_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))provBign_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))provBign_sign_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))provBign_verify_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))provBign_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))provBign_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))provBign_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))provBign_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))provBign_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))provBign_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))provBign_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))provBign_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))provBign_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, 
        (void (*)(void))provBign_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))provBign_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, 
        (void (*)(void))provBign_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))provBign_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))provBign_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))provBign_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))provBign_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))provBign_settable_ctx_md_params },
    { 0, NULL }
};

#endif // OPENSSL_VERSION_MAJOR >= 3
