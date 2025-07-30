/*
*******************************************************************************
\file bee2prov.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Registration of bee2evp provider in OpenSSL
\created 2025.03.10
\version 2025.03.10
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include <bee2/core/rng.h>
#include "bee2evp/bee2prov.h"
#include "bee2evp/info.h"
#include "bee2evp/bee2evp.h"


static OSSL_FUNC_BIO_new_file_fn *c_bio_new_file = NULL;
static OSSL_FUNC_BIO_new_membuf_fn *c_bio_new_membuf = NULL;
static OSSL_FUNC_BIO_read_ex_fn *c_bio_read_ex = NULL;
static OSSL_FUNC_BIO_write_ex_fn *c_bio_write_ex = NULL;
static OSSL_FUNC_BIO_gets_fn *c_bio_gets = NULL;
static OSSL_FUNC_BIO_puts_fn *c_bio_puts = NULL;
static OSSL_FUNC_BIO_ctrl_fn *c_bio_ctrl = NULL;
static OSSL_FUNC_BIO_up_ref_fn *c_bio_up_ref = NULL;
static OSSL_FUNC_BIO_free_fn *c_bio_free = NULL;
static OSSL_FUNC_BIO_vprintf_fn *c_bio_vprintf = NULL;

static OSSL_FUNC_core_obj_create_fn *c_core_obj_create = NULL;

int ossl_prov_bio_from_dispatch(const OSSL_DISPATCH *fns)
{
    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_BIO_NEW_FILE:
            if (c_bio_new_file == NULL)
                c_bio_new_file = OSSL_FUNC_BIO_new_file(fns);
            break;
        case OSSL_FUNC_BIO_NEW_MEMBUF:
            if (c_bio_new_membuf == NULL)
                c_bio_new_membuf = OSSL_FUNC_BIO_new_membuf(fns);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            if (c_bio_read_ex == NULL)
                c_bio_read_ex = OSSL_FUNC_BIO_read_ex(fns);
            break;
        case OSSL_FUNC_BIO_WRITE_EX:
            if (c_bio_write_ex == NULL)
                c_bio_write_ex = OSSL_FUNC_BIO_write_ex(fns);
            break;
        case OSSL_FUNC_BIO_GETS:
            if (c_bio_gets == NULL)
                c_bio_gets = OSSL_FUNC_BIO_gets(fns);
            break;
        case OSSL_FUNC_BIO_PUTS:
            if (c_bio_puts == NULL)
                c_bio_puts = OSSL_FUNC_BIO_puts(fns);
            break;
        case OSSL_FUNC_BIO_CTRL:
            if (c_bio_ctrl == NULL)
                c_bio_ctrl = OSSL_FUNC_BIO_ctrl(fns);
            break;
        case OSSL_FUNC_BIO_UP_REF:
            if (c_bio_up_ref == NULL)
                c_bio_up_ref = OSSL_FUNC_BIO_up_ref(fns);
            break;
        case OSSL_FUNC_BIO_FREE:
            if (c_bio_free == NULL)
                c_bio_free = OSSL_FUNC_BIO_free(fns);
            break;
        case OSSL_FUNC_BIO_VPRINTF:
            if (c_bio_vprintf == NULL)
                c_bio_vprintf = OSSL_FUNC_BIO_vprintf(fns);
            break;
        case OSSL_FUNC_CORE_OBJ_CREATE:
            if (c_core_obj_create == NULL)
                c_core_obj_create = fns->function;
            break;
        }
    }

    return 1;
}

int ossl_core_obj_create(const OSSL_CORE_HANDLE *prov, const char *oid, const char *sn, const char *ln)
{
    if (c_core_obj_create == NULL)
        return NID_undef;
    return c_core_obj_create(prov, oid, sn, ln);    
}


OSSL_CORE_BIO *ossl_prov_bio_new_file(const char *filename, const char *mode)
{
    if (c_bio_new_file == NULL)
        return NULL;
    return c_bio_new_file(filename, mode);
}

OSSL_CORE_BIO *ossl_prov_bio_new_membuf(const char *filename, int len)
{
    if (c_bio_new_membuf == NULL)
        return NULL;
    return c_bio_new_membuf(filename, len);
}

int ossl_prov_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read)
{
    if (c_bio_read_ex == NULL)
        return 0;
    return c_bio_read_ex(bio, data, data_len, bytes_read);
}

int ossl_prov_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                           size_t *written)
{
    if (c_bio_write_ex == NULL)
        return 0;
    return c_bio_write_ex(bio, data, data_len, written);
}

int ossl_prov_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size)
{
    if (c_bio_gets == NULL)
        return -1;
    return c_bio_gets(bio, buf, size);
}

int ossl_prov_bio_puts(OSSL_CORE_BIO *bio, const char *str)
{
    if (c_bio_puts == NULL)
        return -1;
    return c_bio_puts(bio, str);
}

int ossl_prov_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr)
{
    if (c_bio_ctrl == NULL)
        return -1;
    return c_bio_ctrl(bio, cmd, num, ptr);
}

int ossl_prov_bio_up_ref(OSSL_CORE_BIO *bio)
{
    if (c_bio_up_ref == NULL)
        return 0;
    return c_bio_up_ref(bio);
}

int ossl_prov_bio_free(OSSL_CORE_BIO *bio)
{
    if (c_bio_free == NULL)
        return 0;
    return c_bio_free(bio);
}

/* Provider-specific data structure (if needed) */
typedef struct {
    /* Add custom provider-specific data here */
    int version;
} BEE2_PROVIDER_CTX;

static const OSSL_PARAM bee2pro_param_types[] = {
    {"name", OSSL_PARAM_UTF8_PTR, NULL, 0, 0},
    {"version", OSSL_PARAM_UTF8_PTR, NULL, 0, 0},
    {"status", OSSL_PARAM_INTEGER, NULL, 0, 0},
    OSSL_PARAM_END
};

const OSSL_PARAM *bee2_provider_gettable_params(void *provctx) {
    return bee2pro_param_types;
}

int bee2_provider_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, "name");
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Bee2evp Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, "version");
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, BEE2EVP_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, "status");
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

/* Provider cleanup function */
static void bee2_provider_ctx_free(void *provctx) {
    BEE2_PROVIDER_CTX *ctx = (BEE2_PROVIDER_CTX *)provctx;
    if (ctx) {
        printf("Clear bee2pro context\n");
        /* Free any resources allocated in the context */
        if(rngIsValid())
            rngClose();
        OPENSSL_free(ctx);
    }
}

/* Provider initialization function */
static void *bee2_provider_ctx_new(
    const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *in
) {
    BEE2_PROVIDER_CTX *ctx = OPENSSL_zalloc(sizeof(BEE2_PROVIDER_CTX));
    if (!ctx) {
        return NULL;
    }
    /* Initialize provider-specific data here, if necessary */
    if (rngCreate(0, 0) != ERR_OK) {
        OPENSSL_free(ctx);
        return NULL;
    }    
    return ctx;
}


/* Supported digests */
static const OSSL_ALGORITHM bee2_provider_digests[] = 
{
    { "belt-hash:1.2.112.0.2.0.34.101.31.81", "provider=bee2pro", 
        provBeltHash_functions, "The Belt hashing algorithm (belt-hash)"},
    { "bash256:1.2.112.0.2.0.34.101.77.11", "provider=bee2pro", 
        provBash256_functions, "The Bash hashing algorithm (bash256)"},
    { "bash384:1.2.112.0.2.0.34.101.77.12", "provider=bee2pro", 
        provBash384_functions, "The Bash hashing algorithm (bash384)"},
    { "bash512:1.2.112.0.2.0.34.101.77.13", "provider=bee2pro", 
        provBash512_functions, "The Bash hashing algorithm (bash512)"},
    { NULL, NULL, NULL, NULL }
};

/* Supported cipher algorithms */
static const OSSL_ALGORITHM bee2_provider_ciphers[] = {
    { "belt-ecb128:1.2.112.0.2.0.34.101.31.11", "provider=bee2pro", 
        provBeltECB_functions, "Belt encryption algorithm ECB (128)" },
    { NULL, NULL, NULL, NULL }
};


/* Supported PBKDF algorithms */
static const OSSL_ALGORITHM bee2_provider_kdfs[] = {
    { "belt-pbkdf:1.2.112.0.2.0.34.101.31.111", "provider=bee2pro", 
        provBeltPBKDF_functions, "Belt-pbkdf password-based kdf" },
    { NULL, NULL, NULL, NULL }
};

/* Supported key management algorithms */
static const OSSL_ALGORITHM bee2_provider_keymgmt[] = {
    { "bign", "provider=bee2pro", 
        bign_key_functions,  "BIGN key management"},
    { NULL, NULL, NULL, NULL }
};

/* Supported signature algorithms */
static const OSSL_ALGORITHM bee2_provider_signatures[] = {
    { "bign", "provider=bee2pro", bign_signature_functions, 
        "STB 34.101.45 (bign): digital signature" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM bee2_provider_encoders[] = {
    { "bign", "provider=bee2pro,output=PEM,structure=type-specific", 
        bign_params_encoder_functions, "Encoder for BIGN domain parameters" },
    { "bign", "provider=bee2pro,output=PEM,structure=PrivateKeyInfo", 
        bign_key_encoder_functions, "Encoder for BIGN private key" },
    { "bign", "provider=bee2pro,output=PEM,structure=SubjectPublicKeyInfo", 
        bign_key_encoder_functions, "Encoder for BIGN public key" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM bee2_provider_decoders[] = {
    { "bign", "provider=bee2pro,input=PEM,structure=type-specific", 
        bign_params_decoder_functions, "Decoder for BIGN domain parameters" },
    { "bign", "provider=bee2pro,input=DER,structure=PrivateKeyInfo", 
        bign_key_decoder_functions, "Decoder for BIGN private key" },
    { "bign", "provider=bee2pro,input=DER,structure=SubjectPublicKeyInfo", 
        bign_key_decoder_functions, "Decoder for BIGN public key" },
    { NULL, NULL, NULL, NULL }
};

/* Provider query function: Returns the operations supported by this provider */
static const OSSL_ALGORITHM *bee2_provider_query_operation(
    void *provctx, int operation_id, int *no_cache
) {
    /* Return the list of algorithms implemented for the requested operation_id */
    /* Example: Provide algorithms for OSSL_OP_DIGEST (hashing), OSSL_OP_CIPHER, etc. */
    *no_cache = 0; /* Set to 1 if you don't want OpenSSL to cache the result */
    switch (operation_id) {
        case OSSL_OP_SIGNATURE:
             return bee2_provider_signatures;
        case OSSL_OP_DIGEST:
            return bee2_provider_digests; 
        case OSSL_OP_CIPHER:
            return bee2_provider_ciphers; 
        case OSSL_OP_KDF:
            return bee2_provider_kdfs; 
        case OSSL_OP_KEYMGMT:
            return bee2_provider_keymgmt; 
        case OSSL_OP_ENCODER:
            return bee2_provider_encoders;
       case OSSL_OP_DECODER:
           return bee2_provider_decoders;
        default:
            return NULL; /* Operation not supported */
    }
}

/* Provider teardown function */
static void bee2_provider_teardown(void *provctx) {
    bee2_provider_ctx_free(provctx);
}

/* Provider dispatch table: Lists the functions implemented by the provider */
static const OSSL_DISPATCH bee2_provider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, 
        (void (*)(void))bee2_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))bee2_provider_get_params },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))bee2_provider_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, 
        (void (*)(void))bee2_provider_query_operation },
    { 0, NULL } /* Terminate the list */
};

const OSSL_CORE_HANDLE *prov_core = NULL;

#define OBJ_REG(name)\
	if (NID_##name == NID_undef) \
		ossl_core_obj_create(prov_core, OID_##name, SN_##name, LN_##name);


static int register_objects(const OSSL_CORE_HANDLE *core)
{
    prov_core = core;
    OBJ_REG(bign_pubkey);
    OBJ_REG(bign_curve256v1);
    OBJ_REG(bign_curve384v1);
    OBJ_REG(bign_curve512v1);
    OBJ_REG(bign_primefield);
    return 1;
}

/* Provider entry point: Called by OpenSSL to initialize the provider */
int OSSL_provider_init(
    const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *in, 
    const OSSL_DISPATCH **out, void **provctx
) {
    /* Allocate and initialize provider context */
    *provctx = bee2_provider_ctx_new(core, in);
    if (*provctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0; /* Initialization failed */
    }
    /* Set the dispatch table */
    *out = bee2_provider_dispatch_table;
    ossl_prov_bio_from_dispatch(in);
    if (!register_objects(core))
        return 0;
    return 1; /* Initialization successful */
}

#endif // OPENSSL_VERSION_MAJOR >= 3


