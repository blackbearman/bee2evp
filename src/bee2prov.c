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
        /* Free any resources allocated in the context */
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

/* Signature method dispatch table */
static const OSSL_DISPATCH bign_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))provBign_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))provBign_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))provBign_sign_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))provBign_verify_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))provBign_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))provBign_verify },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))provBign_gettable_params },
    { 0, NULL }
};

/* Supported signature algorithms */
static const OSSL_ALGORITHM bee2_provider_signatures[] = {
    { "RSA", "provider=my_provider", bign_signature_functions, 
        "STB 34.101.45 (bign): digital signature" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM bee2_provider_encoders[] = {
    { "bign", "provider=bee2pro,output=pem,structure=DomainParameters", 
        bign_params_encoder_functions, "Encoder for BIGN domain parameters" },
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
        //case OSSL_OP_SIGNATURE:
        //     printf("11-provider signatures\n");
        //     return bee2_provider_signatures;
        case OSSL_OP_DIGEST:
            /* Return supported digest algorithms */
            return bee2_provider_digests; 
        case OSSL_OP_CIPHER:
            /* Return supported cipher algorithms */
            return bee2_provider_ciphers; 
        case OSSL_OP_KDF:
            return bee2_provider_kdfs; /* Provide KDF algorithms */
        case OSSL_OP_KEYMGMT:
            return bee2_provider_keymgmt; /* Provide key management algorithms */
        case OSSL_OP_ENCODER:
            return bee2_provider_encoders;
//        case OSSL_OP_DECODER:
//            return deflt_decoder;
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
    return 1; /* Initialization successful */
}

#endif // OPENSSL_VERSION_MAJOR >= 3

// #include <openssl/core.h>
// #include <openssl/core_dispatch.h>
// #include <openssl/provider.h>
// #include <openssl/params.h>
// #include <openssl/evp.h>
// #include <openssl/err.h>
// #include <string.h>
// #include <stdlib.h>

// /* Key-specific context */
// typedef struct {
//     EVP_PKEY *pkey;    /* Key structure */
//     size_t bits;       /* Key size (in bits) */
//     size_t pub_exp;    /* Public exponent for RSA keys */
// } MY_KEYGEN_CTX;

// /* Create a new key generation context */
// static void *my_keygen_newctx(void *provctx) {
//     MY_KEYGEN_CTX *ctx = OPENSSL_zalloc(sizeof(MY_KEYGEN_CTX));
//     if (ctx == NULL) {
//         return NULL;
//     }
//     ctx->bits = 2048;        /* Default key size */
//     ctx->pub_exp = 65537;    /* Default public exponent */
//     return ctx;
// }

// /* Free the key generation context */
// static void my_keygen_freectx(void *vctx) {
//     MY_KEYGEN_CTX *ctx = (MY_KEYGEN_CTX *)vctx;
//     if (ctx) {
//         EVP_PKEY_free(ctx->pkey);
//         OPENSSL_free(ctx);
//     }
// }

// /* Set parameters for key generation */
// static int my_keygen_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
//     MY_KEYGEN_CTX *ctx = (MY_KEYGEN_CTX *)vctx;
//     const OSSL_PARAM *p;

//     if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS)) != NULL) {
//         if (!OSSL_PARAM_get_size_t(p, &ctx->bits)) {
//             return 0;
//         }
//     }

//     if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL) {
//         if (!OSSL_PARAM_get_size_t(p, &ctx->pub_exp)) {
//             return 0;
//         }
//     }

//     return 1;
// }

// /* Gettable parameters for key generation */
// static const OSSL_PARAM *my_keygen_gettable_ctx_params(void *provctx) {
//     static const OSSL_PARAM params[] = {
//         OSSL_PARAM_size_t(OSSL_PKEY_PARAM_BITS, NULL), /* Key size */
//         OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_E, NULL), /* RSA public exponent */
//         OSSL_PARAM_END
//     };
//     return params;
// }

// /* Generate a private key */
// static int my_keygen_generate(void *vctx, void *provkey, OSSL_CALLBACK *cb, void *cbarg) {
//     MY_KEYGEN_CTX *ctx = (MY_KEYGEN_CTX *)vctx;

//     /* RSA key generation example */
//     BIGNUM *e = BN_new();
//     if (e == NULL || !BN_set_word(e, ctx->pub_exp)) {
//         BN_free(e);
//         return 0;
//     }

//     RSA *rsa = RSA_new();
//     if (rsa == NULL || !RSA_generate_key_ex(rsa, ctx->bits, e, NULL)) {
//         BN_free(e);
//         RSA_free(rsa);
//         return 0;
//     }

//     BN_free(e);

//     /* Set the RSA key into an EVP_PKEY structure */
//     ctx->pkey = EVP_PKEY_new();
//     if (ctx->pkey == NULL || !EVP_PKEY_assign_RSA(ctx->pkey, rsa)) {
//         RSA_free(rsa);
//         return 0;
//     }

//     return 1;
// }

// /* Export key parameters (e.g., modulus, exponent) */
// static int my_key_export(void *vctx, OSSL_CALLBACK *export_cb, void *cbarg) {
//     MY_KEYGEN_CTX *ctx = (MY_KEYGEN_CTX *)vctx;

//     if (ctx->pkey == NULL) {
//         ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
//         return 0; /* No key generated */
//     }

//     RSA *rsa = EVP_PKEY_get0_RSA(ctx->pkey);
//     if (rsa == NULL) {
//         return 0;
//     }

//     /* Extract RSA parameters */
//     const BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
//     RSA_get0_key(rsa, &n, &e, &d);
//     RSA_get0_factors(rsa, &p, &q);

//     /* Export parameters using the callback */
//     OSSL_PARAM params[] = {
//         OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, n),
//         OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, e),
//         OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, d),
//         OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, p),
//         OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, q),
//         OSSL_PARAM_END
//     };

//     return export_cb(params, cbarg);
// }

// /* Dispatch table for key management functions */
// static const OSSL_DISPATCH my_keymgmt_functions[] = {
//     { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))my_keygen_newctx },
//     { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))my_keygen_freectx },
//     { OSSL_FUNC_KEYMGMT_SET_CTX_PARAMS, (void (*)(void))my_keygen_set_ctx_params },
//     { OSSL_FUNC_KEYMGMT_GETTABLE_CTX_PARAMS, (void (*)(void))my_keygen_gettable_ctx_params },
//     { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))my_keygen_generate },
//     { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))my_key_export },
//     { 0, NULL }
// };

