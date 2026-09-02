/*
 * Minimal X301MLKEM1024 substrate for OpenSSL TLS 1.3.
 *
 * Sources: OpenSSL provider-base(7) "TLS-GROUP", provider-keymgmt(7), and
 * provider-kem(7); FIPS 203 through OpenSSL's EVP ML-KEM-1024
 * implementation selected by the child library context; RFC 10024's
 * ML-KEM-first concatenation, RFC 9954's general
 * hybrid design, and the RFC 9846 TLS 1.3 key schedule.
 * This file implements only the KEYMGMT/KEM operations libssl needs. It
 * defines no standalone key format, KDF, or general hybrid-KEM profile.
 */
#include <stddef.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include "provider_internal.h"

#if defined(X301_SECRET_TAINT_INSTRUMENTATION)
extern void ed301_vg_make_mem_undefined(void *address, size_t length);
# define X301_TAINT_SECRET(address, length) \
    ed301_vg_make_mem_undefined((address), (length))
#else
# define X301_TAINT_SECRET(address, length) ((void)0)
#endif
#define X_BYTES ((size_t)38)
#define ML_PUBLIC_BYTES ((size_t)1568)
#define ML_CIPHERTEXT_BYTES ((size_t)1568)
#define ML_SECRET_BYTES ((size_t)32)
#define HYBRID_PUBLIC_BYTES (ML_PUBLIC_BYTES + X_BYTES)
#define HYBRID_CIPHERTEXT_BYTES (ML_CIPHERTEXT_BYTES + X_BYTES)
#define HYBRID_SECRET_BYTES (ML_SECRET_BYTES + X_BYTES)
#define HYBRID_BITS 1024
#define HYBRID_SECURITY_BITS 256

static const char HYBRID_NAME[] = "X301MLKEM1024";
static const char ML_NAME[] = "ML-KEM-1024";
enum { KEY_EMPTY, KEY_PUBLIC, KEY_PRIVATE };
enum { KEM_NONE, KEM_ENCAPSULATE, KEM_DECAPSULATE };

typedef struct {
    X301_PROVIDER_CONTEXT *provider;
    void *x301;
    EVP_PKEY *mlkem;
    int state;
} HYBRID_KEY;
typedef struct {
    X301_PROVIDER_CONTEXT *provider;
    int keypair;
} HYBRID_GEN_CTX;
typedef struct {
    X301_PROVIDER_CONTEXT *provider;
    HYBRID_KEY *key;
    int operation;
} HYBRID_KEM_CTX;
static const OSSL_PARAM HYBRID_GETTABLE[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM HYBRID_SETTABLE[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM HYBRID_GEN_SETTABLE[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

static void *hybrid_alloc(X301_PROVIDER_CONTEXT *provider, size_t size)
{
    return provider == NULL || provider->zalloc == NULL
        ? NULL : provider->zalloc(size, __FILE__, __LINE__);
}

static void hybrid_clear_free(
    X301_PROVIDER_CONTEXT *provider,
    void *pointer,
    size_t size)
{
    if (provider != NULL && provider->clear_free != NULL && pointer != NULL)
        provider->clear_free(pointer, size, __FILE__, __LINE__);
}

static void hybrid_thread_stop(X301_PROVIDER_CONTEXT *provider)
{
    if (provider != NULL && provider->libctx != NULL)
        OPENSSL_thread_stop_ex(provider->libctx);
}

static int group_matches(const OSSL_PARAM params[])
{
    const OSSL_PARAM *param;
    const size_t length = sizeof(HYBRID_NAME) - 1;

    if (params == NULL
            || (param = OSSL_PARAM_locate_const(
                    params, OSSL_PKEY_PARAM_GROUP_NAME)) == NULL)
        return 1;
    if (param->data_type != OSSL_PARAM_UTF8_STRING || param->data == NULL)
        return 0;
    return (param->data_size == length
            && memcmp(param->data, HYBRID_NAME, length) == 0)
        || (param->data_size == length + 1
            && memcmp(param->data, HYBRID_NAME, length + 1) == 0);
}

static EVP_PKEY *mlkem_import_public(
    X301_PROVIDER_CONTEXT *provider,
    const unsigned char public_key[ML_PUBLIC_BYTES])
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];

    if (provider == NULL || provider->libctx == NULL || public_key == NULL)
        return NULL;
    context = EVP_PKEY_CTX_new_from_name(provider->libctx, ML_NAME, NULL);
    if (context == NULL || EVP_PKEY_fromdata_init(context) <= 0)
        goto cleanup;
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, (void *)public_key, ML_PUBLIC_BYTES);
    params[1] = (OSSL_PARAM)OSSL_PARAM_END;
    if (EVP_PKEY_fromdata(
            context, &key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }

cleanup:
    EVP_PKEY_CTX_free(context);
    hybrid_thread_stop(provider);
    return key;
}

static int mlkem_get_public(
    EVP_PKEY *key,
    unsigned char output[ML_PUBLIC_BYTES])
{
    size_t length = 0;

    return key != NULL && output != NULL
        && EVP_PKEY_get_octet_string_param(
            key, OSSL_PKEY_PARAM_PUB_KEY,
            output, ML_PUBLIC_BYTES, &length) > 0
        && length == ML_PUBLIC_BYTES;
}

static void *hybrid_key_new(void *provider_context)
{
    X301_PROVIDER_CONTEXT *provider = provider_context;
    HYBRID_KEY *key = hybrid_alloc(provider, sizeof(*key));

    if (key == NULL) {
        X301_RAISE(provider, X301_R_ALLOCATION_FAILURE,
            "X301MLKEM1024 key allocation failed");
        return NULL;
    }
    key->provider = provider;
    return key;
}

static void hybrid_key_free(void *key_data)
{
    HYBRID_KEY *key = key_data;
    X301_PROVIDER_CONTEXT *provider;

    if (key == NULL)
        return;
    provider = key->provider;
    if (provider != NULL && provider->rust != NULL)
        provider->rust->key_free(key->x301);
    EVP_PKEY_free(key->mlkem);
    hybrid_clear_free(provider, key, sizeof(*key));
}

static int hybrid_key_has(const void *key_data, int selection)
{
    const HYBRID_KEY *key = key_data;

    if (key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && key->state != KEY_PRIVATE)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
            && key->state < KEY_PUBLIC)
        return 0;
    return 1;
}

static const OSSL_PARAM *hybrid_key_gettable(void *provider_context)
{
    (void)provider_context;
    return HYBRID_GETTABLE;
}

static int hybrid_key_get_params(void *key_data, OSSL_PARAM params[])
{
    HYBRID_KEY *key = key_data;
    OSSL_PARAM *encoded;
    unsigned char public_key[HYBRID_PUBLIC_BYTES];

    if (key == NULL || key->provider == NULL)
        return 0;
    if (params == NULL
        || !x301_param_set_optional_int(
            OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS), HYBRID_BITS)
        || !x301_param_set_optional_int(
            OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS),
            HYBRID_SECURITY_BITS)
        || !x301_param_set_optional_int(
            OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE),
            (int)HYBRID_CIPHERTEXT_BYTES)) {
        X301_RAISE(key->provider, X301_R_INVALID_PARAMETER,
            "invalid X301MLKEM1024 key parameter query");
        return 0;
    }
    encoded = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (encoded == NULL)
        return 1;
    if (key->state < KEY_PUBLIC
        || !mlkem_get_public(key->mlkem, public_key)
        || key->provider->rust->key_get_public(
               key->x301, public_key + ML_PUBLIC_BYTES, X_BYTES)
            != 1) {
        X301_RAISE(key->provider, X301_R_INVALID_KEY,
            "X301MLKEM1024 public key is unavailable");
        return 0;
    }
    if (!x301_param_set_optional_octet_string(
            encoded, public_key, sizeof(public_key))) {
        X301_RAISE(key->provider, X301_R_INVALID_PARAMETER,
            "invalid X301MLKEM1024 encoded-public-key output parameter");
        return 0;
    }
    return 1;
}

static const OSSL_PARAM *hybrid_key_settable(void *provider_context)
{
    (void)provider_context;
    return HYBRID_SETTABLE;
}

static int hybrid_key_set_params(void *key_data, const OSSL_PARAM params[])
{
    HYBRID_KEY *key = key_data;
    const unsigned char *public_key = NULL;
    size_t public_length = 0;
    void *x301 = NULL;
    EVP_PKEY *mlkem = NULL;
    int result = 0;

    if (key == NULL || key->provider == NULL || key->provider->rust == NULL)
        return 0;
    if (key->state != KEY_EMPTY
        || !x301_param_get_strict_octet_string(
            params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            &public_key, &public_length, HYBRID_PUBLIC_BYTES, 0)) {
        X301_RAISE(key->provider, X301_R_INVALID_PARAMETER,
            "invalid X301MLKEM1024 encoded public key parameter");
        return 0;
    }
    if (public_key == NULL)
        return 1;
    mlkem = mlkem_import_public(key->provider, public_key);
    x301 = key->provider->rust->key_new();
    if (mlkem == NULL)
        goto cleanup;
    if (x301 == NULL) {
        X301_RAISE(key->provider, X301_R_ALLOCATION_FAILURE,
            "X301MLKEM1024 X301 key allocation failed");
        goto cleanup;
    }
    if (key->provider->rust->key_set_encoded_public(
            x301, public_key + ML_PUBLIC_BYTES, X_BYTES)
        != 1) {
        X301_RAISE(key->provider, X301_R_INVALID_KEY,
            "invalid X301 component in X301MLKEM1024 public key");
        goto cleanup;
    }
    key->mlkem = mlkem;
    key->x301 = x301;
    key->state = KEY_PUBLIC;
    mlkem = NULL;
    x301 = NULL;
    result = 1;

cleanup:
    EVP_PKEY_free(mlkem);
    key->provider->rust->key_free(x301);
    return result;
}

static const char *hybrid_key_operation_name(int operation_id)
{
    return operation_id == OSSL_OP_KEM ? HYBRID_NAME : NULL;
}

static void *hybrid_gen_init(
    void *provider_context,
    int selection,
    const OSSL_PARAM params[])
{
    X301_PROVIDER_CONTEXT *provider = provider_context;
    HYBRID_GEN_CTX *generation;
    const int keypair =
        (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
            == OSSL_KEYMGMT_SELECT_KEYPAIR;
    const int parameters = !keypair
        && (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0;

    if (provider == NULL)
        return NULL;
    if ((!keypair && !parameters) || !group_matches(params)) {
        X301_RAISE(provider, X301_R_INVALID_PARAMETER,
            "invalid X301MLKEM1024 generation parameters");
        return NULL;
    }
    generation = hybrid_alloc(provider, sizeof(*generation));
    if (generation == NULL) {
        X301_RAISE(provider, X301_R_ALLOCATION_FAILURE,
            "X301MLKEM1024 generation-context allocation failed");
        return NULL;
    }
    generation->provider = provider;
    generation->keypair = keypair;
    return generation;
}

static void *hybrid_gen(
    void *generation_data,
    OSSL_CALLBACK *progress_callback,
    void *callback_argument)
{
    HYBRID_GEN_CTX *generation = generation_data;
    X301_PROVIDER_CONTEXT *provider;
    HYBRID_KEY *key;

    (void)progress_callback;
    (void)callback_argument;
    if (generation == NULL || generation->provider == NULL)
        return NULL;
    provider = generation->provider;
    key = hybrid_key_new(provider);
    if (key == NULL || !generation->keypair)
        return key;
    key->x301 = x301_generate_raw_key(provider);
    key->mlkem = EVP_PKEY_Q_keygen(provider->libctx, NULL, ML_NAME);
    if (key->x301 == NULL || key->mlkem == NULL) {
        hybrid_key_free(key);
        key = NULL;
    } else {
        key->state = KEY_PRIVATE;
    }
    hybrid_thread_stop(provider);
    return key;
}

static int hybrid_gen_set_params(
    void *generation_data,
    const OSSL_PARAM params[])
{
    HYBRID_GEN_CTX *generation = generation_data;

    if (generation == NULL)
        return 0;
    if (!group_matches(params)) {
        X301_RAISE(generation->provider, X301_R_INVALID_PARAMETER,
            "invalid X301MLKEM1024 generation group");
        return 0;
    }
    return 1;
}

static const OSSL_PARAM *hybrid_gen_settable(
    void *generation_data,
    void *provider_context)
{
    (void)generation_data;
    (void)provider_context;
    return HYBRID_GEN_SETTABLE;
}

static void hybrid_gen_cleanup(void *generation_data)
{
    HYBRID_GEN_CTX *generation = generation_data;
    X301_PROVIDER_CONTEXT *provider;

    if (generation == NULL)
        return;
    provider = generation->provider;
    hybrid_clear_free(provider, generation, sizeof(*generation));
}

static void *hybrid_kem_new(void *provider_context)
{
    X301_PROVIDER_CONTEXT *provider = provider_context;
    HYBRID_KEM_CTX *context = hybrid_alloc(provider, sizeof(*context));

    if (context == NULL) {
        X301_RAISE(provider, X301_R_ALLOCATION_FAILURE,
            "X301MLKEM1024 KEM-context allocation failed");
        return NULL;
    }
    context->provider = provider;
    return context;
}

static void hybrid_kem_free(void *context_data)
{
    HYBRID_KEM_CTX *context = context_data;
    X301_PROVIDER_CONTEXT *provider;

    if (context == NULL)
        return;
    provider = context->provider;
    hybrid_clear_free(provider, context, sizeof(*context));
}

static int hybrid_kem_init(
    HYBRID_KEM_CTX *context,
    HYBRID_KEY *key,
    const OSSL_PARAM params[],
    int operation)
{
    if (context == NULL || context->provider == NULL)
        return 0;
    if (params != NULL && params[0].key != NULL) {
        X301_RAISE(context->provider, X301_R_INVALID_PARAMETER,
            "X301MLKEM1024 KEM parameters are unsupported");
        return 0;
    }
    if (key == NULL || key->provider != context->provider
        || (operation == KEM_ENCAPSULATE && key->state < KEY_PUBLIC)
        || (operation == KEM_DECAPSULATE && key->state != KEY_PRIVATE)) {
        X301_RAISE(context->provider, X301_R_INVALID_KEY,
            "invalid X301MLKEM1024 KEM key");
        return 0;
    }
    context->key = key;
    context->operation = operation;
    return 1;
}

static int hybrid_encapsulate_init(
    void *context_data,
    void *key_data,
    const OSSL_PARAM params[])
{
    return hybrid_kem_init(
        context_data, key_data, params, KEM_ENCAPSULATE);
}

static int hybrid_decapsulate_init(
    void *context_data,
    void *key_data,
    const OSSL_PARAM params[])
{
    return hybrid_kem_init(
        context_data, key_data, params, KEM_DECAPSULATE);
}

static int hybrid_encapsulate(
    void *context_data,
    unsigned char *ciphertext,
    size_t *ciphertext_length,
    unsigned char *shared_secret,
    size_t *shared_secret_length)
{
    HYBRID_KEM_CTX *context = context_data;
    EVP_PKEY_CTX *mlkem_context = NULL;
    void *server_x301 = NULL;
    void *exchange = NULL;
    unsigned char temporary_ciphertext[HYBRID_CIPHERTEXT_BYTES] = { 0 };
    unsigned char temporary_secret[HYBRID_SECRET_BYTES] = { 0 };
    size_t mlkem_ciphertext_length = ML_CIPHERTEXT_BYTES;
    size_t mlkem_secret_length = ML_SECRET_BYTES;
    int result = 0;

    if (context == NULL || context->provider == NULL)
        return 0;
    if (context->operation != KEM_ENCAPSULATE || context->key == NULL) {
        X301_RAISE(context->provider, X301_R_INVALID_STATE,
            "X301MLKEM1024 encapsulation is not initialized");
        return 0;
    }
    if (ciphertext == NULL) {
        if (ciphertext_length == NULL && shared_secret_length == NULL) {
            X301_RAISE(context->provider, X301_R_INVALID_PARAMETER,
                "X301MLKEM1024 encapsulation length output is missing");
            return 0;
        }
        if (ciphertext_length != NULL)
            *ciphertext_length = HYBRID_CIPHERTEXT_BYTES;
        if (shared_secret_length != NULL)
            *shared_secret_length = HYBRID_SECRET_BYTES;
        return 1;
    }
    if (ciphertext_length == NULL || shared_secret == NULL
        || shared_secret_length == NULL) {
        X301_RAISE(context->provider, X301_R_INVALID_PARAMETER,
            "invalid X301MLKEM1024 encapsulation output");
        return 0;
    }
    if (*ciphertext_length < HYBRID_CIPHERTEXT_BYTES
            || *shared_secret_length < HYBRID_SECRET_BYTES) {
        *ciphertext_length = HYBRID_CIPHERTEXT_BYTES;
        *shared_secret_length = HYBRID_SECRET_BYTES;
        X301_RAISE(context->provider, X301_R_INVALID_PARAMETER,
            "X301MLKEM1024 encapsulation output buffer is too small");
        return 0;
    }

    mlkem_context = EVP_PKEY_CTX_new_from_pkey(
        context->provider->libctx, context->key->mlkem, NULL);
    if (mlkem_context == NULL
        || EVP_PKEY_encapsulate_init(mlkem_context, NULL) <= 0
        || EVP_PKEY_encapsulate(
               mlkem_context,
               temporary_ciphertext, &mlkem_ciphertext_length,
               temporary_secret, &mlkem_secret_length)
            <= 0)
        goto cleanup;
    if (mlkem_ciphertext_length != ML_CIPHERTEXT_BYTES
        || mlkem_secret_length != ML_SECRET_BYTES) {
        X301_RAISE(context->provider, X301_R_INTERNAL_ERROR,
            "unexpected ML-KEM-1024 encapsulation output length");
        goto cleanup;
    }

    server_x301 = x301_generate_raw_key(context->provider);
    exchange = context->provider->rust->exchange_new();
    if (server_x301 == NULL)
        goto cleanup;
    if (exchange == NULL) {
        X301_RAISE(context->provider, X301_R_ALLOCATION_FAILURE,
            "X301MLKEM1024 exchange-context allocation failed");
        goto cleanup;
    }
    if (context->provider->rust->key_get_public(
            server_x301,
            temporary_ciphertext + ML_CIPHERTEXT_BYTES, X_BYTES)
            != 1
        || context->provider->rust->exchange_init(
               exchange, server_x301)
            != 1
        || context->provider->rust->exchange_set_peer(
               exchange, context->key->x301)
            != 1
        || context->provider->rust->exchange_derive(
               exchange, temporary_secret + ML_SECRET_BYTES, X_BYTES)
            != 1) {
        X301_RAISE(context->provider, X301_R_INTERNAL_ERROR,
            "X301MLKEM1024 X301 encapsulation failed");
        goto cleanup;
    }

    memcpy(ciphertext, temporary_ciphertext, sizeof(temporary_ciphertext));
    X301_TAINT_SECRET(temporary_secret, sizeof(temporary_secret));
    memcpy(shared_secret, temporary_secret, sizeof(temporary_secret));
    *ciphertext_length = sizeof(temporary_ciphertext);
    *shared_secret_length = sizeof(temporary_secret);
    result = 1;

cleanup:
    EVP_PKEY_CTX_free(mlkem_context);
    context->provider->rust->exchange_free(exchange);
    context->provider->rust->key_free(server_x301);
    context->provider->rust->cleanse(
        temporary_secret, sizeof(temporary_secret));
    hybrid_thread_stop(context->provider);
    return result;
}

static int hybrid_decapsulate(
    void *context_data,
    unsigned char *shared_secret,
    size_t *shared_secret_length,
    const unsigned char *ciphertext,
    size_t ciphertext_length)
{
    HYBRID_KEM_CTX *context = context_data;
    EVP_PKEY_CTX *mlkem_context = NULL;
    void *peer_x301 = NULL;
    void *exchange = NULL;
    unsigned char temporary_secret[HYBRID_SECRET_BYTES] = { 0 };
    size_t mlkem_secret_length = ML_SECRET_BYTES;
    int result = 0;

    if (context == NULL || context->provider == NULL)
        return 0;
    if (context->operation != KEM_DECAPSULATE || context->key == NULL) {
        X301_RAISE(context->provider, X301_R_INVALID_STATE,
            "X301MLKEM1024 decapsulation is not initialized");
        return 0;
    }
    if (shared_secret == NULL) {
        if (shared_secret_length == NULL) {
            X301_RAISE(context->provider, X301_R_INVALID_PARAMETER,
                "X301MLKEM1024 decapsulation length output is missing");
            return 0;
        }
        *shared_secret_length = HYBRID_SECRET_BYTES;
        return 1;
    }
    if (shared_secret_length == NULL || ciphertext == NULL
        || ciphertext_length != HYBRID_CIPHERTEXT_BYTES) {
        X301_RAISE(context->provider, X301_R_INVALID_PARAMETER,
            "invalid X301MLKEM1024 decapsulation input");
        return 0;
    }
    if (*shared_secret_length < HYBRID_SECRET_BYTES) {
        *shared_secret_length = HYBRID_SECRET_BYTES;
        X301_RAISE(context->provider, X301_R_INVALID_PARAMETER,
            "X301MLKEM1024 decapsulation output buffer is too small");
        return 0;
    }

    mlkem_context = EVP_PKEY_CTX_new_from_pkey(
        context->provider->libctx, context->key->mlkem, NULL);
    if (mlkem_context == NULL
        || EVP_PKEY_decapsulate_init(mlkem_context, NULL) <= 0
        || EVP_PKEY_decapsulate(
               mlkem_context, temporary_secret, &mlkem_secret_length,
               ciphertext, ML_CIPHERTEXT_BYTES)
            <= 0)
        goto cleanup;
    if (mlkem_secret_length != ML_SECRET_BYTES) {
        X301_RAISE(context->provider, X301_R_INTERNAL_ERROR,
            "unexpected ML-KEM-1024 decapsulation output length");
        goto cleanup;
    }

    peer_x301 = context->provider->rust->key_new();
    exchange = context->provider->rust->exchange_new();
    if (peer_x301 == NULL || exchange == NULL) {
        X301_RAISE(context->provider, X301_R_ALLOCATION_FAILURE,
            "X301MLKEM1024 decapsulation-context allocation failed");
        goto cleanup;
    }
    if (context->provider->rust->key_set_encoded_public(
            peer_x301, ciphertext + ML_CIPHERTEXT_BYTES, X_BYTES)
            != 1
        || context->provider->rust->exchange_init(
               exchange, context->key->x301)
            != 1
        || context->provider->rust->exchange_set_peer(
               exchange, peer_x301)
            != 1
        || context->provider->rust->exchange_derive(
               exchange, temporary_secret + ML_SECRET_BYTES, X_BYTES)
            != 1) {
        X301_RAISE(context->provider, X301_R_INVALID_KEY,
            "invalid X301 component in X301MLKEM1024 ciphertext");
        goto cleanup;
    }

    X301_TAINT_SECRET(temporary_secret, sizeof(temporary_secret));
    memcpy(shared_secret, temporary_secret, sizeof(temporary_secret));
    *shared_secret_length = sizeof(temporary_secret);
    result = 1;

cleanup:
    EVP_PKEY_CTX_free(mlkem_context);
    context->provider->rust->exchange_free(exchange);
    context->provider->rust->key_free(peer_x301);
    context->provider->rust->cleanse(
        temporary_secret, sizeof(temporary_secret));
    hybrid_thread_stop(context->provider);
    return result;
}

const OSSL_DISPATCH X301_MLKEM1024_KEYMGMT_DISPATCH[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))hybrid_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))hybrid_key_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))hybrid_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))hybrid_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))hybrid_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        (void (*)(void))hybrid_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))hybrid_gen_settable },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))hybrid_key_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))hybrid_key_gettable },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))hybrid_key_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))hybrid_key_settable },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))hybrid_key_has },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        (void (*)(void))hybrid_key_operation_name },
    { 0, NULL }
};

const OSSL_DISPATCH X301_MLKEM1024_KEM_DISPATCH[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))hybrid_kem_new },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))hybrid_kem_free },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        (void (*)(void))hybrid_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))hybrid_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
        (void (*)(void))hybrid_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))hybrid_decapsulate },
    { 0, NULL }
};
