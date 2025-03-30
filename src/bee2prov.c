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
#include "bee2evp/bee2prov.h"

/* Provider-specific data structure (if needed) */
typedef struct {
    /* Add custom provider-specific data here */
    int version;
} BEE2_PROVIDER_CTX;



/* Provider cleanup function */
static void bee2_provider_ctx_free(void *provctx) {
    BEE2_PROVIDER_CTX *ctx = (BEE2_PROVIDER_CTX *)provctx;
    if (ctx) {
        /* Free any resources allocated in the context */
        OPENSSL_free(ctx);
    }
}

/* Provider initialization function */
static void *bee2_provider_ctx_new(const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *in) {
    BEE2_PROVIDER_CTX *ctx = OPENSSL_zalloc(sizeof(BEE2_PROVIDER_CTX));
    if (!ctx) {
        return NULL;
    }
    /* Initialize provider-specific data here, if necessary */
    return ctx;
}


/* Digest method structure */
static const OSSL_DISPATCH provBeltHash_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))provBeltHash_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))provBeltHash_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))provBeltHash_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))provBeltHash_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))provBeltHash_free },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))md_gettable_params },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))provBeltHash_get_params },
    { 0, NULL }
};

/* Digest method structure */
static const OSSL_DISPATCH provBash256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))provBash256_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))provBash256_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))provBash256_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))provBash256_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))provBash256_free },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))md_gettable_params },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))provBash256_get_params },
    { 0, NULL }
};

/* Digest method structure */
static const OSSL_DISPATCH provBash384_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))provBash384_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))provBash384_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))provBash384_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))provBash384_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))provBash384_free },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))md_gettable_params },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))provBash384_get_params },
    { 0, NULL }
};

/* Digest method structure */
static const OSSL_DISPATCH provBash512_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))provBash512_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))provBash512_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))provBash512_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))provBash512_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))provBash512_free },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))md_gettable_params },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))provBash512_get_params },
    { 0, NULL }
};

/* Supported digests */
static const OSSL_ALGORITHM bee2_provider_digests[] = {
    { "belt-hash:1.2.112.0.2.0.34.101.31.81", "provider=bee2pro", provBeltHash_functions, 
    "The Belt hashing algorithm (belt-hash)"},
    { "bash256:1.2.112.0.2.0.34.101.77.11", "provider=bee2pro", provBash256_functions, 
    "The Bash hashing algorithm (bash256)"},
    { "bash384:1.2.112.0.2.0.34.101.77.12", "provider=bee2pro", provBash384_functions, 
    "The Bash hashing algorithm (bash384)"},
    { "bash512:1.2.112.0.2.0.34.101.77.13", "provider=bee2pro", provBash512_functions, 
    "The Bash hashing algorithm (bash512)"},
    { NULL, NULL, NULL, NULL }
};


/* Cipher operation dispatch table */
static const OSSL_DISPATCH provBeltECB_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))provBeltECB_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))provBeltECB_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))provBeltECB_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))provBeltECB_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))provBeltECB_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))provBeltECB_final },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))provBeltECB_set_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))provBeltECB_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))provBeltECB_get_ctx_params },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))provBeltECB_get_params}, 
    { 0, NULL }
};

/* Supported cipher algorithms */
static const OSSL_ALGORITHM bee2_provider_ciphers[] = {
    { "belt-ecb128:1.2.112.0.2.0.34.101.31.11", "provider=bee2pro", provBeltECB_functions,
    "Belt encryption algorithm ECB (128)" },
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

/* Provider query function: Returns the operations supported by this provider */
static const OSSL_ALGORITHM *bee2_provider_query_operation(void *provctx, int operation_id, int *no_cache) {
    /* Return the list of algorithms implemented for the requested operation_id */
    /* Example: Provide algorithms for OSSL_OP_DIGEST (hashing), OSSL_OP_CIPHER, etc. */
    *no_cache = 0; /* Set to 1 if you don't want OpenSSL to cache the result */
    switch (operation_id) {
        case OSSL_OP_SIGNATURE:
            return bee2_provider_signatures;
        case OSSL_OP_DIGEST:
            /* Return supported digest algorithms */
            return bee2_provider_digests; 
        case OSSL_OP_CIPHER:
            /* Return supported cipher algorithms */
            return bee2_provider_ciphers; 
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
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))bee2_provider_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))bee2_provider_query_operation },
    { 0, NULL } /* Terminate the list */
};

/* Provider entry point: Called by OpenSSL to initialize the provider */
int OSSL_provider_init(const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx) {
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
