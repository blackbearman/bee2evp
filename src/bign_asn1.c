/*
*******************************************************************************
\file bign_asn1.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief ASN.1-structures for bign
\created 2013.11.01
\version 2024.06.18
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/crypto/bign.h>
#include "bee2evp/bee2evp.h"
#include "bee2evp_lcl.h"

/*
*******************************************************************************
Реализована поддержка следующих структур ASN.1, описанных 
в СТБ 34.101.45 [приложение Д]:

  DomainParameters ::= CHOICE {
    specified  ECParameters,
    named      OBJECT IDENTIFIER,
    implicit   NULL
  }

  ECParameters ::= SEQUENCE {
    version  INTEGER {ecpVer1(1)} (ecpVer1),
    fieldID  FieldID,
    curve    Curve,
    base     OCTET STRING (SIZE(32|48|64)),
    order    INTEGER,
    cofactor INTEGER (1) OPTIONAL
  }

  FieldID ::= SEQUENCE {
    fieldType   OBJECT IDENTIFIER (bign-primefield),
    parameters  INTEGER
  } 

  Curve ::= SEQUENCE {
    a     OCTET STRING (SIZE(32|48|64)),
    b     OCTET STRING (SIZE(32|48|64)),
    seed  BIT STRING (SIZE(64))
  }

  PublicKey ::= BIT STRING (SIZE(512|768|1024))
*******************************************************************************
*/

typedef struct
{
	ASN1_OBJECT* fieldType;
	ASN1_INTEGER* prime;
} BIGN_FIELDID;

typedef struct
{
	ASN1_OCTET_STRING* a;
	ASN1_OCTET_STRING* b;
	ASN1_BIT_STRING* seed;
} BIGN_CURVE;

typedef struct
{
	long version;
	BIGN_FIELDID* fieldID;
	BIGN_CURVE* curve;
	ASN1_OCTET_STRING* base;
	ASN1_INTEGER* order;
	ASN1_INTEGER* cofactor;
} BIGN_ECPARAMS;

typedef struct
{
	int	type;
	union {
		ASN1_OBJECT* named;
		BIGN_ECPARAMS* specified;
		ASN1_NULL* implicit;
	} value;
} BIGN_DOMAINPARAMS;

typedef struct 
{
	ASN1_OBJECT* algorithm;
	BIGN_DOMAINPARAMS* parameters;
} BIGN_ALGID;

typedef struct 
{
	long version;
	BIGN_ALGID* keyAlgorithm;
	ASN1_OCTET_STRING* privateKey;
} BIGN_PRIVATEKEY;

ASN1_SEQUENCE(BIGN_FIELDID) =
{
	ASN1_SIMPLE(BIGN_FIELDID, fieldType, ASN1_OBJECT),
	ASN1_SIMPLE(BIGN_FIELDID, prime, ASN1_INTEGER)
} ASN1_SEQUENCE_END(BIGN_FIELDID)

ASN1_SEQUENCE(BIGN_CURVE) = 
{
	ASN1_SIMPLE(BIGN_CURVE, a, ASN1_OCTET_STRING),
	ASN1_SIMPLE(BIGN_CURVE, b, ASN1_OCTET_STRING),
	ASN1_OPT(BIGN_CURVE, seed, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(BIGN_CURVE)

ASN1_SEQUENCE(BIGN_ECPARAMS) = 
{
	ASN1_SIMPLE(BIGN_ECPARAMS, version, LONG),
	ASN1_SIMPLE(BIGN_ECPARAMS, fieldID, BIGN_FIELDID),
	ASN1_SIMPLE(BIGN_ECPARAMS, curve, BIGN_CURVE),
	ASN1_SIMPLE(BIGN_ECPARAMS, base, ASN1_OCTET_STRING),
	ASN1_SIMPLE(BIGN_ECPARAMS, order, ASN1_INTEGER),
	ASN1_OPT(BIGN_ECPARAMS, cofactor, ASN1_INTEGER)
} ASN1_SEQUENCE_END(BIGN_ECPARAMS)

DECLARE_ASN1_ALLOC_FUNCTIONS(BIGN_ECPARAMS)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(BIGN_ECPARAMS)

ASN1_CHOICE(BIGN_DOMAINPARAMS) = 
{
	ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.named, ASN1_OBJECT),
	ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.specified, BIGN_ECPARAMS),
	ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.implicit, ASN1_NULL)
} ASN1_CHOICE_END(BIGN_DOMAINPARAMS)


#if OPENSSL_VERSION_MAJOR >= 3
	DECLARE_ASN1_FUNCTIONS(BIGN_DOMAINPARAMS)
	DECLARE_ASN1_ENCODE_FUNCTIONS_name(BIGN_DOMAINPARAMS, BIGN_DOMAINPARAMS)
	IMPLEMENT_ASN1_FUNCTIONS(BIGN_DOMAINPARAMS)
#else
	DECLARE_ASN1_FUNCTIONS_const(BIGN_DOMAINPARAMS)
	DECLARE_ASN1_ENCODE_FUNCTIONS_const(BIGN_DOMAINPARAMS, BIGN_DOMAINPARAMS)
	IMPLEMENT_ASN1_FUNCTIONS_const(BIGN_DOMAINPARAMS)
#endif


/*
*******************************************************************************
Расширение модуля bee2/bign

\pre Параметры функции evpBign_eq_params() корректны. Поэтому можно сравнивать 
только тройки (p, a, b) [все остальные поля определяются по этой тройке].
*******************************************************************************
*/

int evpBign_eq_params(const bign_params* params1, const bign_params* params2)
{
	return params1 && params2 && 
		params1->l <= 256 && params1->l == params2->l &&
		memEq(params1->p, params2->p, params1->l / 4) &&
		memEq(params1->a, params2->a, params1->l / 4) &&
		memEq(params1->b, params2->b, params1->l / 4);
}

int evpBign_params2nid(const bign_params* params)
{
	bign_params std;

	if (!params)
		return 0;
	if (bignParamsStd(&std, OID_bign_curve256v1) != ERR_OK)
		return 0;
	if (evpBign_eq_params(params, &std))
		return NID_bign_curve256v1;
	if (bignParamsStd(&std, OID_bign_curve384v1) != ERR_OK)
		return 0;
	if (evpBign_eq_params(params, &std))
		return NID_bign_curve384v1;
	if (bignParamsStd(&std, OID_bign_curve512v1) != ERR_OK)
		return 0;
	if (evpBign_eq_params(params, &std))
		return NID_bign_curve512v1;
	return 0;
}

int evpBign_nid2params(bign_params* params, int nid)
{
	if (nid == NID_bign_curve256v1)
		return bignParamsStd(params, OID_bign_curve256v1) == ERR_OK;
	if (nid == NID_bign_curve384v1)
		return bignParamsStd(params, OID_bign_curve384v1) == ERR_OK;
	if (nid == NID_bign_curve512v1)
		return bignParamsStd(params, OID_bign_curve512v1) == ERR_OK;
	return 0;
}

/*
*******************************************************************************
Запись параметров bign_params в структуры ASN.1
*******************************************************************************
*/

static int evpBign_asn1_params2fieldid(BIGN_FIELDID* field, 
	const bign_params* params)
{
	int ok = 0;
	BIGNUM* p = NULL;
	octet rev[64];
	// минимальный входной контроль
	if (!params || !field)
		return 0;
	// установить fieldType
	if (field->fieldType)
		ASN1_OBJECT_free(field->fieldType);
	if (!(field->fieldType = OBJ_txt2obj(SN_bign_primefield, 0)))
		goto err;
	// установить prime
	memCopy(rev, params->p, params->l / 4);
	memRev(rev, params->l / 4);
	if (!(p = BN_new()) || !BN_bin2bn(rev, (int)params->l / 4, p))
		goto err;
	field->prime = BN_to_ASN1_INTEGER(p, field->prime);
	if (!field->prime)
		goto err;
	ok = 1;
	// выход
err:
	p ? BN_free(p) : 0;
	memSetZero(rev, sizeof(rev));
	return ok;
}

static int evpBign_asn1_params2curve(BIGN_CURVE* curve, 
	const bign_params* params)
{
	// входной контроль
	if (!params || !curve || !curve->a || !curve->b)
		return 0;
	// установить a и b
	if (!ASN1_OCTET_STRING_set(curve->a, params->a, (int)params->l / 4) ||
		!ASN1_OCTET_STRING_set(curve->b, params->b, (int)params->l / 4))
		return 0;
	// установить seed (optional)
	if (!curve->seed && !(curve->seed = ASN1_BIT_STRING_new()))
		return 0;
	curve->seed->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 7);
	curve->seed->flags |= ASN1_STRING_FLAG_BITS_LEFT;
	if (!ASN1_BIT_STRING_set(curve->seed, (octet*)params->seed, 8))
		return 0;
	return 1;
}

static BIGN_ECPARAMS* evpBign_asn1_params2ecp(BIGN_ECPARAMS* ecp, 
	const bign_params* params, bool_t cofactor)
{
	int	ok = 0;
	BIGN_ECPARAMS* ret = ecp;
	BIGNUM* order = 0;
	octet rev[64];
	// входной контроль
	if (!params)
		return 0;
	// подготовить возврат
	if (!ret && !(ret = BIGN_ECPARAMS_new()))
		goto err;
	// установить версию (всегда 1)
	ret->version = 1;
	// установить fieldID
	if (!evpBign_asn1_params2fieldid(ret->fieldID, params))
		goto err;
	// установить кривую
	if (!evpBign_asn1_params2curve(ret->curve, params))
		goto err;
	// установить базовую точку
	if (!ASN1_OCTET_STRING_set(ret->base, params->yG, (int)params->l / 4))
		goto err;
	// установить порядок
	memCopy(rev, params->q, params->l / 4);
	memRev(rev, params->l / 4);
	if (!(order = BN_new()) || !BN_bin2bn(rev, (int)params->l / 4, order))
		goto err;
	ret->order = BN_to_ASN1_INTEGER(order, ret->order);
	if (!ret->order)
		goto err;
	// установить кофактор (optional, всегда 1)
	if (cofactor)
	{
		if (!BN_one(order))
			goto err;
		ret->cofactor = BN_to_ASN1_INTEGER(order, ret->cofactor);
		if (!ret->cofactor)
			goto err;
	}
	ok = 1;
err:	
	if (!ok)
	{
		if (ret && !ecp)
			BIGN_ECPARAMS_free(ret);
		ret = 0;
	}
	order ? BN_free(order) : 0;
	memSetZero(rev, sizeof(rev));
	return ret;
}

static BIGN_DOMAINPARAMS* evpBign_asn1_params2dp(BIGN_DOMAINPARAMS* dp, 
	bool_t* specified, const bign_params* params, bool_t cofactor)
{
	BIGN_DOMAINPARAMS* ret = dp;
	int nid;
	// входной контроль
	if (!params || !specified)
		return 0;
	// подготовка возврата
	if (ret)
	{
		if (ret->type == 0 && ret->value.named)
			ASN1_OBJECT_free(ret->value.named);
		else if (ret->type == 1 && ret->value.specified)
			BIGN_ECPARAMS_free(ret->value.specified);
	}
	else
	{
		ret = BIGN_DOMAINPARAMS_new();
		if (!ret)
			return 0;
	}
	// именованные параметры?
	if (!*specified)
	{
		nid = evpBign_params2nid(params);
		if (nid && (ret->value.named = OBJ_nid2obj(nid)))
			ret->type = 0;
		else
			*specified = TRUE;
	}
	// специфицированные параметры?
	if (*specified)
	{	
		ret->value.specified = evpBign_asn1_params2ecp(0, params, cofactor);
		if (ret->value.specified)
			ret->type = 1;
		else
		{
			if (!dp)
				BIGN_DOMAINPARAMS_free(ret);
			ret = dp;
		}
	}
	return ret;
}

/*
*******************************************************************************
Чтение параметров bign_params из структур ASN.1
*******************************************************************************
*/

static int evpBign_asn1_ecp2params(bign_params* params, 
	const BIGN_ECPARAMS* ecp)
{
	int ok = 0;
	BIGNUM* p = 0;
	// входной контроль
	if (!params || !ecp)
		return 0;
	memSetZero(params, sizeof(bign_params));
	// проверить версию
	if (ecp->version != 1)
		goto err;
	// разобрать описание поля GF(p)
	if (!ecp->fieldID || 
		!ecp->fieldID->fieldType || 
		OBJ_obj2nid(ecp->fieldID->fieldType) != NID_bign_primefield || 
		!ecp->fieldID->prime)
		goto err;
	p = ASN1_INTEGER_to_BN(ecp->fieldID->prime, NULL);
	if (!p)
		goto err;
	if (BN_is_negative(p) || BN_is_zero(p) ||
		(params->l = (size_t)BN_num_bits(p)) != 256 && 
			params->l != 384 && params->l != 512)
		goto err;
	params->l /= 2;
	// загрузить p
	if (!BN_bn2bin(p, params->p))
		goto err;
	memRev(params->p, params->l / 4);
	// загрузить a и b
	if (!ecp->curve || 
		!ecp->curve->a || !ecp->curve->a->data || 
		!ecp->curve->b || !ecp->curve->b->data ||
		ecp->curve->a->length != (int)params->l / 4 ||
		ecp->curve->b->length != (int)params->l / 4)
		goto err;
	memCopy(params->a, ecp->curve->a->data, params->l / 4);
	memCopy(params->b, ecp->curve->b->data, params->l / 4);
	// загрузить seed (optional)
	if (ecp->curve->seed)
	{
		if (ecp->curve->seed->length != 8)
			goto err;
		memCopy(params->seed, ecp->curve->seed->data, 8);
	}
	// загрузить base
	if (!ecp->base || !ecp->base->data || 
		ecp->base->length != (int)params->l / 4)
		goto err;
	memCopy(params->yG, ecp->base->data, params->l / 4);
	// загрузить order
	if ((p = ASN1_INTEGER_to_BN(ecp->order, p)) == NULL)
		goto err;
	if (BN_is_negative(p) || BN_is_zero(p) || 
		BN_num_bits(p) != (int)params->l * 2)
		goto err;
	if (!BN_bn2bin(p, params->q))
		goto err;
	memRev(params->q, params->l / 4);
	// загрузить cofactor (optional)
	if (ecp->cofactor)
	{
		if (!(p = ASN1_INTEGER_to_BN(ecp->cofactor, p)) ||
			!BN_is_one(p))
			goto err;
	}
	ok = 1;
err:
	p ? BN_free(p) : 0;
	return ok;
}

static int evpBign_asn1_dp2params(bign_params* params, bool_t* specified,
	const BIGN_DOMAINPARAMS* dp)
{
	// входной контроль
	if (!params || !specified || !dp)
		return 0;
	// именованные параметры?
	if (dp->type == 0)
	{ 
		if (!evpBign_nid2params(params, OBJ_obj2nid(dp->value.named)))
			return 0;
		*specified = FALSE;
	}
	// специфицированные параметры?
	else if (dp->type == 1)
	{ 
		if (!evpBign_asn1_ecp2params(params, dp->value.specified))
			return 0;
		*specified = TRUE;
	}
	// наследованные параметры?
	else if (dp->type == 2)
	{ 
		*specified = FALSE;
		return 0;
	}
	// неверные параметры?
	else
		return 0;
	return 1;
}

/*
*******************************************************************************
Кодирование и декодирование параметров, вложенных в bign_key

\remark Параметры задаются типом DomainParameters [BIGN_DOMAINPARAMS]
*******************************************************************************
*/

int evpBign_asn1_d2i_params(bign_key* key, bool_t* specified, 
	const octet** in, long len)
{
	BIGN_DOMAINPARAMS* dp;
	int ret;
	// входной контроль
	if (!key || !specified)
		return 0;
	// декодировать в dp
	dp = d2i_BIGN_DOMAINPARAMS(0, in, len);
	if (!dp)
		return 0;
	// разобрать dp
	ret = evpBign_asn1_dp2params(key->params, specified, dp);
	BIGN_DOMAINPARAMS_free(dp);
	return ret;
}

int evpBign_asn1_i2d_params(octet** out, bool_t* specified, 
	const bign_key* key)
{
	bool_t cofactor;
	BIGN_DOMAINPARAMS* dp;
	int ret = 0;
	// входной контроль
	if (!key || !specified)
		return 0;
	// преобразовать в стандартную структуру
	*specified = key->flags & EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED;
	cofactor = key->flags & EVP_BIGN_PKEY_ENC_PARAMS_COFACTOR;
	dp = evpBign_asn1_params2dp(0, specified, key->params, cofactor);
	if (!dp)
		return 0;
	// кодировать
	ret = i2d_BIGN_DOMAINPARAMS(dp, out);
	BIGN_DOMAINPARAMS_free(dp);
	return ret;
}

/*
*******************************************************************************
Кодирование и декодирование открытого ключа, вложенного в bign_key

\remark Открытый ключ задается типом PublicKey ::= BIT STRING
*******************************************************************************
*/

int evpBign_asn1_o2i_pubkey(bign_key* key, const octet** in, long len)
{
	// входной контроль
	if (!key || !in || len != (int)key->params->l / 2)
		return 0;
	// сохранить ключ
	memCopy(key->pubkey, *in, len);
	memSetZero(key->pubkey + len, sizeof(key->pubkey) - len);
	return 1;
}

int evpBign_asn1_i2o_pubkey(octet** out, const bign_key* key)
{
	int ret;
	// входной контроль
	if (!key)
		return 0;
	// длина ключа в октетах
	ret = (int)key->params->l / 2;
	if (!out)
		return ret;
	// подготовить буфер
	if (!*out && !(*out = (octet*)OPENSSL_malloc(ret)))
		return 0;
	// возвратить ключ
	memCopy(*out, key->pubkey, ret);
	return ret;
}

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3

/*
The encoder doesn't need to know more about the B<OSSL_CORE_BIO>
pointer than being able to pass it to the appropriate BIO upcalls (see
L<provider-base(7)/Core functions>: <openssl/core_dispatch.h>).

*/

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include "bee2evp/bee2prov.h"

static OSSL_FUNC_encoder_newctx_fn bign_params_encoder_newctx;
static OSSL_FUNC_encoder_freectx_fn bign_params_encoder_freectx;
//static OSSL_FUNC_encoder_get_params_fn 
static OSSL_FUNC_encoder_gettable_params_fn bign_params_encoder_gettable_params;
static OSSL_FUNC_encoder_set_ctx_params_fn bign_params_encoder_set_ctx_params;
static OSSL_FUNC_encoder_settable_ctx_params_fn bign_params_encoder_settable_params;
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
	printf("81-bign-encoder newctx\n");
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
    if (ctx) {
        OPENSSL_free(ctx);
    }
}

/* Check if the encoder supports the given selection and key type */
static int bign_params_encoder_does_selection(void *vctx, int selection) {
    /* This encoder supports private key encoding */
	printf("82-bign-encoder does_selection %d\n", selection);
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY
		|| selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) ? 1 : 0;
}

/* Encode the key into PEM PrivateKeyInfo */
static int bign_params_encoder_encode(void *vctx, OSSL_CORE_BIO *out, const void *key, 
                                  const OSSL_PARAM params[], int selection, 
                                  OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    const bign_key *pkey = (const bign_key *)key;
	octet buf[1000];
	octet *der = buf;
	size_t written;
	bool_t specified;
	printf("85-bign-encoder encode %d\n", selection);

    if (pkey == NULL || !(selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
	printf("85-bign-encoder check key\n");
	if(!evpBign_asn1_i2d_params(&der, &specified, pkey))
		return 0;
	printf("85-bign-encoder write to buf\n");
	if (out == NULL) {
        return 0;
    }
	printf("85-bign-encoder write to output\n");
	if(!BIO_write_ex(out, (char*) buf, der-buf, &written))
		return 0;
	printf("85-bign-encoder finish\n");
    return 1;
}

/* Gettable parameters for the encoder context */
static const OSSL_PARAM *bign_params_encoder_gettable_params(void *provctx) {
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("output", NULL, 0), /* PEM or DER */
        OSSL_PARAM_END
    };
	printf("83-bign-encoder gettable\n");
    return params;
}

/* Settable parameters for the encoder context */
static const OSSL_PARAM *bign_params_encoder_settable_params(void *provctx) {
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
	printf("84-bign-encoder set_ctx_params\n");
    return 1;
}

/* Dispatch table for the encoder functions */
const OSSL_DISPATCH bign_params_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))bign_params_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))bign_params_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))bign_params_encoder_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))bign_params_encoder_encode },
//    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, (void (*)(void))bign_params_encoder_gettable_params },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))bign_params_encoder_settable_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))bign_params_encoder_set_ctx_params },
    { 0, NULL }
};


// static OSSL_FUNC_encoder_import_object_fn rsa_to_EncryptedPrivateKeyInfo_pem_import_object; 
// static OSSL_FUNC_encoder_free_object_fn rsa_to_EncryptedPrivateKeyInfo_pem_free_object; 
// static OSSL_FUNC_encoder_encode_fn rsa_to_EncryptedPrivateKeyInfo_pem_encode; 

// static void * rsa_to_EncryptedPrivateKeyInfo_pem_import_object(void *vctx, int selection, const OSSL_PARAM params[]) 
// { 
//     KEY2ANY_CTX *ctx = vctx; 
//     return ossl_prov_import_key(ossl_rsa_keymgmt_functions, ctx->provctx, selection, params); 
// } 

// static void rsa_to_EncryptedPrivateKeyInfo_pem_free_object(void *key) 
// { 
//     ossl_prov_free_key(ossl_rsa_keymgmt_functions, key); 
// } 

// static int rsa_to_EncryptedPrivateKeyInfo_pem_does_selection(void *ctx, int selection) 
// { 
//     return key2any_check_selection(selection, 0x01); 
// } 

// static int rsa_to_EncryptedPrivateKeyInfo_pem_encode(
//     void *ctx, OSSL_CORE_BIO *cout, const void *key, 
//     const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) 
// { 
//     if (key_abstract != ((void*)0)) 
//     { 
//         ERR_raise(ERR_LIB_PROV, (7)); return 0; 
//     } 
//     if ((selection & 0x01) != 0) 
//         return key2any_encode(ctx, cout, key, 6, "RSA" " PRIVATE KEY", rsa_check_key_type, key_to_epki_pem_priv_bio, cb, cbarg, prepare_rsa_params, rsa_prv_k2d); 
//     ERR_raise(ERR_LIB_PROV, (7)); 
//     return 0; 
// } 

// const OSSL_DISPATCH ossl_rsa_to_EncryptedPrivateKeyInfo_pem_encoder_functions[] = {
//      { 1, (void (*)(void))key2any_newctx }, 
//      { 2, (void (*)(void))key2any_freectx }, 
//      { 6, (void (*)(void))key2any_settable_ctx_params }, 
//      { 5, (void (*)(void))key2any_set_ctx_params }, 
//      { 10, (void (*)(void))rsa_to_EncryptedPrivateKeyInfo_pem_does_selection }, 
//      { 20, (void (*)(void))rsa_to_EncryptedPrivateKeyInfo_pem_import_object }, 
//      { 21, (void (*)(void))rsa_to_EncryptedPrivateKeyInfo_pem_free_object }, 
//      { 11, (void (*)(void))rsa_to_EncryptedPrivateKeyInfo_pem_encode }, 
//      { 0, ((void*)0) } 
// };

#endif // OPENSSL_VERSION_MAJOR >= 3