/*
*******************************************************************************
\file belt_pbkdf.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief The Belt-based PBKDF
\created 2015.01.19
\version 2021.02.18
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <bee2/core/blob.h>
#include <bee2/crypto/belt.h>
#include "bee2evp/bee2evp.h"

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <bee2/core/mem.h>

/* PBKDF-specific context */
typedef struct {
    //const EVP_MD *md;         /* Message digest algorithm (e.g., SHA-256) */
    unsigned char *salt;      /* Salt value */
    size_t saltlen;           /* Length of the salt */
    size_t iter;        /* Number of iter */
    size_t keylen;            /* Desired key length */
    unsigned char *password;  /* Password */
    size_t passlen;       /* Length of the password */
} BELT_PBKDF_CTX;

static OSSL_FUNC_kdf_newctx_fn provBeltPBKDF_newctx;
static OSSL_FUNC_kdf_dupctx_fn provBeltPBKDF_dupctx;
static OSSL_FUNC_kdf_freectx_fn provBeltPBKDF_freectx;
static OSSL_FUNC_kdf_reset_fn provBeltPBKDF_resetctx;
static OSSL_FUNC_kdf_derive_fn provBeltPBKDF_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn provBeltPBKDF_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn provBeltPBKDF_set_ctx_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn provBeltPBKDF_gettable_ctx_params;
static OSSL_FUNC_kdf_get_ctx_params_fn provBeltPBKDF_get_ctx_params;

/* Allocate a new PBKDF context */
static void *provBeltPBKDF_newctx(void *provctx) {
    BELT_PBKDF_CTX *ctx = blobCreate(sizeof(BELT_PBKDF_CTX));
    if (!ctx)
        return NULL;
    provBeltPBKDF_resetctx(ctx);
    return ctx;
}

/* Duplicate a PBKDF context */
static void *provBeltPBKDF_dupctx(void *vctx) {
    const BELT_PBKDF_CTX *src = (const BELT_PBKDF_CTX *)vctx;
    BELT_PBKDF_CTX *dest = blobCreate(sizeof(BELT_PBKDF_CTX));
    if (!dest)
        return NULL;
    memSetZero(dest, sizeof(BELT_PBKDF_CTX));
    dest->iter = src->iter;
    dest->keylen = src->keylen;
    if (src->saltlen)
    {
        dest->salt = blobCopy(dest->salt, src->salt);
        if(!dest->salt) 
        {
            blobClose(dest);
            return NULL;
        }
        dest->saltlen = src->saltlen;
    }
    if (src->passlen) 
    {
        dest->password = blobCopy(dest->password, src->password);
        if(!dest->password)
        {
            blobClose(dest->salt);
            blobClose(dest);
            return NULL;
        }
        dest->passlen = src->passlen;
    }
    return dest;
}

/* Free the PBKDF context */
static void provBeltPBKDF_freectx(void *vctx) {
    provBeltPBKDF_resetctx(vctx);
    blobClose(vctx);
}

/* Reset the PBKDF context */
static void provBeltPBKDF_resetctx(void *vctx) {
    BELT_PBKDF_CTX *ctx = (BELT_PBKDF_CTX *)vctx;
    if (ctx) {
        blobClose(ctx->salt);
        blobClose(ctx->password);
        memSetZero(ctx, sizeof(BELT_PBKDF_CTX));
        ctx->iter = 10000;
        ctx->keylen = 32;
    }
}

/* Set parameters for the PBKDF context */
static int provBeltPBKDF_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    BELT_PBKDF_CTX *ctx = (BELT_PBKDF_CTX *)vctx;
    const OSSL_PARAM *p;
    printf("23-kdf-set_param_ctx\n");

    if ((p = OSSL_PARAM_locate_const(params, "salt")) != NULL) {
        if (p->data_size > 0) {
            ctx->salt = blobCreate(p->data_size);
            if (ctx->salt == NULL) {
                return 0;
            }
            memcpy(ctx->salt, p->data, p->data_size);
            ctx->saltlen = p->data_size;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, "iter")) != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->iter)) {
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, "keylen")) != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->keylen)) {
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, "pass")) != NULL) {
        if (p->data_size > 0) {
            ctx->password = blobCreate(p->data_size);
            if (ctx->password == NULL) {
                return 0;
            }
            memcpy(ctx->password, p->data, p->data_size);
            ctx->passlen = p->data_size;
        }
    }

    return 1;
}

/* Get parameters for the PBKDF context */
static const OSSL_PARAM *provBeltPBKDF_gettable_ctx_params(void *ctx, void *provctx) {
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t("iter", NULL),
        OSSL_PARAM_size_t("keylen", NULL),
        OSSL_PARAM_octet_string("salt", NULL, 0),
        OSSL_PARAM_octet_string("password", NULL, 0),
        OSSL_PARAM_END
    };
    printf("21-kdf-gettable\n");
    return params;
}

static int provBeltPBKDF_get_ctx_params(void *vctx, OSSL_PARAM *params) {
    BELT_PBKDF_CTX *ctx = (BELT_PBKDF_CTX *)vctx;
    OSSL_PARAM *p;

    printf("22-kdf-get_param_ctx\n");
    if ((p = OSSL_PARAM_locate(params, "iter")) != NULL) {
        if (!OSSL_PARAM_set_size_t(p, ctx->iter)) {
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate(params, "keylen")) != NULL) {
        if (!OSSL_PARAM_set_size_t(p, ctx->keylen)) {
            return 0;
        }
    }

    return 1;
}

/* Derive the key */
static int provBeltPBKDF_derive(void *vctx, unsigned char *out, size_t outlen, const OSSL_PARAM params[]) {
    BELT_PBKDF_CTX *ctx = (BELT_PBKDF_CTX *)vctx;
    blob_t key = 0;
    printf("24-kdf-derive\n");

    /* Update context parameters if provided */
    if (params && !provBeltPBKDF_set_ctx_params(ctx, params)) {
        return 0;
    }
    printf("241-kdf-derive-check-params %p , %p \n", ctx->password, ctx->salt);
    if (ctx->password == NULL || ctx->salt == NULL) {
        return 0; /* Missing required parameters */
    }
    printf("242-kdf-derive-check-keylen\n");
    
    if (ctx->keylen > 32 || outlen != ctx->keylen) {
        return 0; /* Output length mismatch */
    }
    // todo: generate salt 8 bytes min
    if (ctx->saltlen < 8)
        return 0; 
    // Minimal number of iteration is 10000
    if (ctx->iter < 10000) 
        ctx->iter = 10000;
 	// построить ключ
	key = blobCreate(32);
	if (!key)
		return 0;

    if (beltPBKDF2((octet*)key, (const octet*)ctx->password, ctx->passlen, 
        ctx->iter, ctx->salt, ctx->saltlen) == ERR_OK) 
    {
        // задать ключ
        memCopy(out, key, outlen);
        blobClose(key);
        return 1; /* Derivation successed */
    }
	blobClose(key);
    return 0; /* Derivation failed */
}

static const OSSL_PARAM *provBeltPBKDF_settable_ctx_params(ossl_unused void *ctx,
    ossl_unused void *p_ctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_octet_string("pass", NULL, 0),
        OSSL_PARAM_octet_string("salt", NULL, 0),
        OSSL_PARAM_uint64("iter", NULL),
        OSSL_PARAM_uint64("keylen", NULL),
        OSSL_PARAM_END
    };
    printf("20-kdf-settable_ctx_params\n");
    return known_settable_ctx_params;
}

/* PBKDF operation dispatch table */
const OSSL_DISPATCH provBeltPBKDF_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void))provBeltPBKDF_newctx },
    { OSSL_FUNC_KDF_DUPCTX, (void(*)(void))provBeltPBKDF_dupctx },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void))provBeltPBKDF_freectx },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))provBeltPBKDF_resetctx },
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void))provBeltPBKDF_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        (void(*)(void))provBeltPBKDF_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))provBeltPBKDF_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))provBeltPBKDF_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))provBeltPBKDF_get_ctx_params },
    { 0, NULL }
};

#endif

/*
*******************************************************************************
Алгоритм belt-pbkdf --- это реализация схемы PBKDF2 на основе алгоритмов belt.
Подробности -- в PKCS#5, а также в СТБ 34.101.45 (Е.2).

Для подключения belt-pbkdf следует:
1	Выполнить регистрацию, вызвав EVP_PBE_alg_add_type(EVP_PBE_TYPE_PRF, 
	NID_belt_hmac, -1, NID_belt_hash, 0).
2	В ctrl-функциях алгоритмов шифрования, ключ которых будет строиться по 
	паролю, возвращать NID_belt_hmac в ответ на команду EVP_CTRL_PBE_PRF_NID.
	
Параметрами belt-pbkdf являются число итераций и синхропосылка (соль).
В СТБ 34.101.45 рекомендуется использовать не менее чем 64-битовую 
синхропосылку (соль) и не менее чем 10000 итераций. 

В evp.h заданы стандартные для OpenSSL длина синхропосылки и число итераций:
	#define PKCS5_SALT_LEN		8
	#define PKCS5_DEFAULT_ITER	2048
Таким образом, рекомендации по длине синхропосылки поддерживаются, а по числу 
итераций -- нет. Рекомендации можно выполнить, если зарегистрировать 
функцию интерфейса EVP_PBE_KEYGEN (объявленного в evp.h), которая их 
поддерживает.

К сожалению, эта функция не получает управления при работе через командный 
интерфейс OpenSSL. Возможный выход (через патч) -- расширение массива 
builtin_pbe, объявленного в crypto/evp/evp_pbe.c.

\remark По мотивам openssl/crypto/asn1/p5_pbev2.c, 
openssl/crypto/evp/p5_crpt2.c.

todo: полноценное встраивание (?)
*******************************************************************************
*/

const char OID_belt_pbkdf[] = "1.2.112.0.2.0.34.101.31.111";
const char SN_belt_pbkdf[] = "belt-pbkdf";
const char LN_belt_pbkdf[] = "belt-pbkdf";
#define NID_belt_pbkdf OBJ_sn2nid(SN_belt_pbkdf)

int evpBeltPBKDF_keyivgen(EVP_CIPHER_CTX* ctx, const char* pass, int passlen,
	ASN1_TYPE* param, const EVP_CIPHER* c, const EVP_MD* md, int en_de)
{
	int key_len;
	const octet* der;
	int der_len;
	PBKDF2PARAM* kdf = 0;
	octet* salt;
	int salt_len;
	long iter;
	blob_t key = 0;
	int ret = 0;
	// определить длину ключа
	if (!ctx || !EVP_CIPHER_CTX_cipher(ctx))
		return 0;
	key_len = EVP_CIPHER_CTX_key_length(ctx);
	if (key_len > 32)
		return 0;
	// декодировать параметры
	if(!param || param->type != V_ASN1_SEQUENCE)
		return 0;
	der = param->value.sequence->data;
	der_len = param->value.sequence->length;
	kdf = d2i_PBKDF2PARAM(0, &der, der_len);
	if(!kdf)
		return 0;
	// проверить параметры
	if(kdf->keylength && ASN1_INTEGER_get(kdf->keylength) != (int)key_len ||
		OBJ_obj2nid(kdf->prf->algorithm) != NID_belt_hmac ||
		kdf->prf->parameter->type != V_ASN1_NULL ||
		kdf->salt->type != V_ASN1_OCTET_STRING)
		goto err;
	// настроить синхропосылку
	salt = kdf->salt->value.octet_string->data;
	salt_len = kdf->salt->value.octet_string->length;
	if (salt_len < 8)
	{
		salt_len = 8;
		if (!ASN1_OCTET_STRING_set(kdf->salt->value.octet_string, 0, salt_len))
			goto err;
		salt = kdf->salt->value.octet_string->data;
		if (RAND_bytes(salt, salt_len) < 0)
			goto err;
	}
	// настроить число итераций
	iter = ASN1_INTEGER_get(kdf->iter);
	if (iter < 10000)
	{
		iter = 10000;
		if (!ASN1_INTEGER_set(kdf->iter, iter))
			goto err;
	}
	// построить ключ
	key = blobCreate(32);
	if (!key)
		goto err;
	if (beltPBKDF2((octet*)key, (const octet*)pass, passlen, 
		(size_t)iter, salt, salt_len) != ERR_OK)
		goto err;
	// задать ключ
	ret = EVP_CipherInit_ex(ctx, 0, 0, (const octet*)key, 0, en_de);
err:
	blobClose(key);
	PBKDF2PARAM_free(kdf);
	return ret;
}

/*
*******************************************************************************
Регистрация
*******************************************************************************
*/

static int belt_pbkdf_nids[128];
static int belt_pbkdf_count;

#define BELT_PBKDF_REG(name, tmp)\
	(((tmp = NID_##name) != NID_undef) ?\
		belt_pbkdf_nids[belt_pbkdf_count++] = tmp :\
		(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?\
			belt_pbkdf_nids[belt_pbkdf_count++] = tmp : NID_undef))

/*
*******************************************************************************
Подключение / закрытие
*******************************************************************************
*/

int evpBeltPBKDF_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать алгоритмы и получить nid'ы
	if (BELT_PBKDF_REG(belt_pbkdf, tmp) == NID_undef)
		return 0;
	// все нормально
	return 1;
}

void evpBeltPBKDF_finish()
{
}
