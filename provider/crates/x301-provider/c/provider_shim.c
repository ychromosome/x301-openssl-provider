/*
 * Raw X301 OpenSSL provider adapter and optional TLS-GROUP registration.
 * Sources: OpenSSL provider(7), provider-keymgmt(7), provider-keyexch(7),
 * provider-base(7) "TLS-GROUP", RAND_priv_bytes_ex(3), RFC 7748's raw-DH
 * provider shape, and RFC 9846's TLS 1.3 group contract. Raw X301 is
 * deliberately not registered as a TLS group.
 */

#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "provider_internal.h"

#if OPENSSL_VERSION_MAJOR == 3
# define X301_SUPPORTED_CORE_MAJOR 3U
#elif OPENSSL_VERSION_MAJOR == 4
# define X301_SUPPORTED_CORE_MAJOR 4U
#else
# error "The X301 provider requires OpenSSL ABI major 3 or 4 headers"
#endif

#define X301_BYTES ((size_t)38)
#define X301_BITS 301
#define X301_SECURITY_BITS 149
#if defined(X301_ENABLE_HYBRID_MLKEM1024)
# define X301_MLKEM1024_SECURITY_BITS 256
# define X301_MLKEM1024_TLS_GROUP_ID ((unsigned int)0xfe2e)
# define X301_TLS_VERSION_1_3 0x0304
#endif

#if defined(X301_TEST_FAILPOINT_ARTIFACT)
static const char X301_PROVIDER_NAME[] = "X301 Experimental Provider (failpoint)";
#else
static const char X301_PROVIDER_NAME[] = "X301 Experimental Provider";
#endif
static const char X301_PROVIDER_VERSION[] = "0.1.0";
#if defined(X301_ENABLE_HYBRID_MLKEM1024)
static const char X301_PROVIDER_BUILDINFO[] =
    "raw X301-v1 plus X301MLKEM1024 KEYMGMT/KEM/TLS-GROUP";
#else
static const char X301_PROVIDER_BUILDINFO[] =
    "raw X301-v1 KEYMGMT/KEYEXCH";
#endif
static const char X301_NAME[] = "X301";
static const char X301_ALGORITHM_NAMES[] = "X301";
#if defined(X301_ENABLE_HYBRID_MLKEM1024)
static const char X301_MLKEM1024_NAME[] = "X301MLKEM1024";
static const char X301_MLKEM1024_ALGORITHM_NAMES[] = "X301MLKEM1024";
#endif
static const char X301_PROPERTIES[] = "provider=x301";
#if defined(X301_ENABLE_HYBRID_MLKEM1024)
static const char X301_TLS_GROUP_CAPABILITY[] = "TLS-GROUP";
#endif

typedef struct x301_key_st {
    X301_PROVIDER_CONTEXT *provider;
    void *inner;
} X301_KEY;

typedef struct x301_gen_context_st {
    X301_PROVIDER_CONTEXT *provider;
    int selection;
} X301_GEN_CONTEXT;

typedef struct x301_exchange_st {
    X301_PROVIDER_CONTEXT *provider;
    void *inner;
} X301_EXCHANGE;

static const OSSL_ITEM X301_REASON_STRINGS[] = {
    { X301_R_INVALID_KEY, "invalid X301 key" },
    { X301_R_INVALID_STATE, "invalid X301 operation state" },
    { X301_R_INVALID_PARAMETER, "invalid X301 parameter" },
    { X301_R_ALLOCATION_FAILURE, "X301 allocation failure" },
    { X301_R_RANDOM_FAILURE, "X301 private random generation failure" },
    { X301_R_INTERNAL_ERROR, "X301 internal provider error" },
    { 0, NULL }
};

static const OSSL_PARAM X301_PROVIDER_GETTABLE_PARAMS[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM X301_GETTABLE_PARAMS[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM X301_PRIVATE_TYPES[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM X301_PUBLIC_TYPES[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM X301_KEYPAIR_TYPES[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM X301_SETTABLE_PARAMS[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM X301_GEN_SETTABLE_PARAMS[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

static int x301_utf8_param_equals(
    const OSSL_PARAM params[],
    const char *key,
    const char *expected)
{
    const OSSL_PARAM *parameter = params == NULL || key == NULL
        ? NULL
        : OSSL_PARAM_locate_const(params, key);
    const size_t expected_length = strlen(expected);

    if (parameter == NULL)
        return 1;
    if (parameter->data_type != OSSL_PARAM_UTF8_STRING
            || parameter->data == NULL)
        return 0;
    if (parameter->data_size == expected_length)
        return memcmp(parameter->data, expected, expected_length) == 0;
    if (parameter->data_size == expected_length + 1
            && ((const unsigned char *)parameter->data)[expected_length] == 0)
        return memcmp(parameter->data, expected, expected_length) == 0;
    return 0;
}

static int x301_selection_supported(int selection)
{
    return (selection & ~OSSL_KEYMGMT_SELECT_ALL) == 0;
}

static int x301_wants_private(int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int x301_wants_public(int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int x301_params_are_empty(const OSSL_PARAM params[])
{
    return params == NULL || params[0].key == NULL;
}

void x301_raise_error(
    X301_PROVIDER_CONTEXT *provider,
    uint32_t reason,
    const char *file,
    int line,
    const char *function,
    const char *format,
    ...)
{
    va_list arguments;

    if (provider == NULL || provider->new_error == NULL
            || provider->set_error_debug == NULL
            || provider->vset_error == NULL)
        return;

    provider->new_error(provider->handle);
    provider->set_error_debug(provider->handle, file, line, function);
    va_start(arguments, format);
    provider->vset_error(provider->handle, reason, format, arguments);
    va_end(arguments);
}

static void *x301_allocate(X301_PROVIDER_CONTEXT *provider, size_t size)
{
    if (provider == NULL || provider->zalloc == NULL)
        return NULL;
    return provider->zalloc(size, __FILE__, __LINE__);
}

static void x301_clear_free(
    X301_PROVIDER_CONTEXT *provider,
    void *pointer,
    size_t size)
{
    if (provider != NULL && provider->clear_free != NULL && pointer != NULL)
        provider->clear_free(pointer, size, __FILE__, __LINE__);
}

static X301_KEY *x301_wrap_key(X301_PROVIDER_CONTEXT *provider, void *inner)
{
    X301_KEY *key;

    if (provider == NULL || provider->rust == NULL || inner == NULL)
        return NULL;
    key = x301_allocate(provider, sizeof(*key));
    if (key == NULL) {
        provider->rust->key_free(inner);
        X301_RAISE(provider, X301_R_ALLOCATION_FAILURE,
            "X301 key wrapper allocation failed");
        return NULL;
    }
    key->provider = provider;
    key->inner = inner;
    return key;
}

static void *x301_key_new(void *provider_context)
{
    X301_PROVIDER_CONTEXT *provider = provider_context;
    void *inner;

    if (provider == NULL || provider->rust == NULL)
        return NULL;
    inner = provider->rust->key_new();
    if (inner == NULL) {
        X301_RAISE(provider, X301_R_ALLOCATION_FAILURE,
            "X301 key allocation failed");
        return NULL;
    }
    return x301_wrap_key(provider, inner);
}

static void x301_key_free(void *key_data)
{
    X301_KEY *key = key_data;
    X301_PROVIDER_CONTEXT *provider;

    if (key == NULL)
        return;
    provider = key->provider;
    if (provider != NULL && provider->rust != NULL && key->inner != NULL)
        provider->rust->key_free(key->inner);
    x301_clear_free(provider, key, sizeof(*key));
}

static int x301_key_import(
    void *key_data,
    int selection,
    const OSSL_PARAM params[])
{
    X301_KEY *key = key_data;
    const unsigned char *private_key = NULL;
    const unsigned char *public_key = NULL;
    size_t private_length = 0;
    size_t public_length = 0;
    const int wants_private = x301_wants_private(selection);
    const int wants_public = x301_wants_public(selection);

    if (key == NULL || key->provider == NULL || key->inner == NULL
            || params == NULL || !x301_selection_supported(selection)
            || (!wants_private && !wants_public))
        return 0;

    if (wants_private && !x301_param_get_strict_octet_string(
            params,
            OSSL_PKEY_PARAM_PRIV_KEY,
            &private_key,
            &private_length,
            X301_BYTES,
            wants_private && !wants_public))
        goto invalid;
    if (wants_public && !x301_param_get_strict_octet_string(
            params,
            OSSL_PKEY_PARAM_PUB_KEY,
            &public_key,
            &public_length,
            X301_BYTES,
            wants_public && !wants_private))
        goto invalid;

    /*
     * OpenSSL's raw-public constructor may import with KEYPAIR selection but
     * supply only OSSL_PKEY_PARAM_PUB_KEY.  Selection describes the permitted
     * operation, while the parameter list identifies the material present.
     * Require the sole selected component for one-component selections; for
     * KEYPAIR accept either component and let the atomic Rust import derive or
     * cross-check the public key when private material is present.  This is
     * the same contract used by OpenSSL's ECX key managers and by the Ed301
     * provider adapter.
     */
    if ((private_key == NULL && public_key == NULL)
            || (wants_private && !wants_public && private_key == NULL)
            || (wants_public && !wants_private && public_key == NULL))
        goto invalid;

    if (key->provider->rust->key_import(
            key->inner,
            wants_private ? private_key : NULL,
            wants_private ? private_length : 0,
            wants_public ? public_key : NULL,
            wants_public ? public_length : 0) != 1)
        goto invalid;
    return 1;

invalid:
    X301_RAISE(key->provider, X301_R_INVALID_KEY,
        "invalid X301 key material");
    return 0;
}

static const OSSL_PARAM *x301_key_import_types(int selection)
{
    const int wants_private = x301_wants_private(selection);
    const int wants_public = x301_wants_public(selection);

    if (!x301_selection_supported(selection))
        return NULL;
    if (wants_private && wants_public)
        return X301_KEYPAIR_TYPES;
    if (wants_private)
        return X301_PRIVATE_TYPES;
    if (wants_public)
        return X301_PUBLIC_TYPES;
    return NULL;
}

static int x301_key_export(
    void *key_data,
    int selection,
    OSSL_CALLBACK *parameter_callback,
    void *callback_argument)
{
    X301_KEY *key = key_data;
    unsigned char private_key[X301_BYTES] = { 0 };
    unsigned char public_key[X301_BYTES] = { 0 };
    OSSL_PARAM export_params[3];
    size_t parameter_count = 0;
    int result = 0;
    const int wants_private = x301_wants_private(selection);
    const int wants_public = x301_wants_public(selection);

    if (key == NULL || key->provider == NULL || key->inner == NULL
            || parameter_callback == NULL
            || !x301_selection_supported(selection)
            || (!wants_private && !wants_public))
        goto cleanup;
    if (key->provider->rust->key_has(
            key->inner, wants_private, wants_public) != 1)
        goto cleanup;

    if (wants_private) {
        if (key->provider->rust->key_get_private(
                key->inner, private_key, sizeof(private_key)) != 1)
            goto cleanup;
        export_params[parameter_count++] = (OSSL_PARAM)
            OSSL_PARAM_octet_string(
                OSSL_PKEY_PARAM_PRIV_KEY,
                private_key,
                sizeof(private_key));
    }
    if (wants_public) {
        if (key->provider->rust->key_get_public(
                key->inner, public_key, sizeof(public_key)) != 1)
            goto cleanup;
        export_params[parameter_count++] = (OSSL_PARAM)
            OSSL_PARAM_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY,
                public_key,
                sizeof(public_key));
    }
    export_params[parameter_count] = (OSSL_PARAM)OSSL_PARAM_END;
    result = parameter_callback(export_params, callback_argument);

cleanup:
    if (key != NULL && key->provider != NULL && key->provider->rust != NULL)
        key->provider->rust->cleanse(private_key, sizeof(private_key));
    if (result != 1 && key != NULL)
        X301_RAISE(key->provider, X301_R_INVALID_KEY,
            "X301 key export failed");
    return result == 1 ? 1 : 0;
}

static const OSSL_PARAM *x301_key_export_types(int selection)
{
    return x301_key_import_types(selection);
}

static const OSSL_PARAM *x301_key_gettable_params(void *provider_context)
{
    (void)provider_context;
    return X301_GETTABLE_PARAMS;
}

static int x301_key_get_params(void *key_data, OSSL_PARAM params[])
{
    X301_KEY *key = key_data;
    OSSL_PARAM *public_param;
    OSSL_PARAM *encoded_public_param;
    OSSL_PARAM *private_param;
    unsigned char private_key[X301_BYTES] = { 0 };
    unsigned char public_key[X301_BYTES] = { 0 };
    int result = 0;

    if (key == NULL || key->provider == NULL || key->inner == NULL
            || params == NULL)
        goto cleanup;
    if (!x301_param_set_optional_int(
            OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS),
            X301_BITS)
            || !x301_param_set_optional_int(
                OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS),
                X301_SECURITY_BITS)
            || !x301_param_set_optional_int(
                OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE),
                (int)X301_BYTES))
        goto cleanup;

    public_param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    encoded_public_param =
        OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (public_param != NULL || encoded_public_param != NULL) {
        if (key->provider->rust->key_get_public(
                key->inner, public_key, sizeof(public_key)) != 1
                || !x301_param_set_optional_octet_string(
                    public_param, public_key, sizeof(public_key))
                || !x301_param_set_optional_octet_string(
                    encoded_public_param, public_key, sizeof(public_key)))
            goto cleanup;
    }

    private_param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (private_param != NULL) {
        if (key->provider->rust->key_get_private(
                key->inner, private_key, sizeof(private_key)) != 1
                || !x301_param_set_optional_octet_string(
                    private_param, private_key, sizeof(private_key)))
            goto cleanup;
    }
    result = 1;

cleanup:
    if (key != NULL && key->provider != NULL && key->provider->rust != NULL)
        key->provider->rust->cleanse(private_key, sizeof(private_key));
    if (result != 1 && key != NULL)
        X301_RAISE(key->provider, X301_R_INVALID_PARAMETER,
            "X301 key parameter query failed");
    return result;
}

static const OSSL_PARAM *x301_key_settable_params(void *provider_context)
{
    (void)provider_context;
    return X301_SETTABLE_PARAMS;
}

static int x301_key_set_params(void *key_data, const OSSL_PARAM params[])
{
    X301_KEY *key = key_data;
    const unsigned char *public_key = NULL;
    size_t public_length = 0;

    if (key == NULL || key->provider == NULL || key->inner == NULL)
        return 0;
    if (params == NULL
            || OSSL_PARAM_locate_const(
                params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) == NULL)
        return 1;
    if (!x301_param_get_strict_octet_string(
            params,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            &public_key,
            &public_length,
            X301_BYTES,
            1)
            || key->provider->rust->key_set_encoded_public(
                key->inner, public_key, public_length) != 1) {
        X301_RAISE(key->provider, X301_R_INVALID_KEY,
            "invalid X301 encoded public key");
        return 0;
    }
    return 1;
}

static int x301_key_has(const void *key_data, int selection)
{
    const X301_KEY *key = key_data;

    if (key == NULL || key->provider == NULL || key->inner == NULL
            || !x301_selection_supported(selection))
        return 0;
    return key->provider->rust->key_has(
        key->inner,
        x301_wants_private(selection),
        x301_wants_public(selection));
}

static int x301_key_validate(
    const void *key_data,
    int selection,
    int check_type)
{
    const X301_KEY *key = key_data;
    int result;

    if (key == NULL || key->provider == NULL || key->inner == NULL
            || !x301_selection_supported(selection)
            || (check_type != OSSL_KEYMGMT_VALIDATE_FULL_CHECK
                && check_type != OSSL_KEYMGMT_VALIDATE_QUICK_CHECK))
        return 0;
    result = key->provider->rust->key_validate(
        key->inner,
        x301_wants_private(selection),
        x301_wants_public(selection));
    if (result != 1)
        X301_RAISE(key->provider, X301_R_INVALID_KEY,
            "X301 key validation failed");
    return result;
}

static int x301_key_match(
    const void *first_data,
    const void *second_data,
    int selection)
{
    const X301_KEY *first = first_data;
    const X301_KEY *second = second_data;

    if (first == NULL || second == NULL || first->provider == NULL
            || first->provider != second->provider || first->inner == NULL
            || second->inner == NULL || !x301_selection_supported(selection))
        return 0;
    return first->provider->rust->key_match(
        first->inner,
        second->inner,
        x301_wants_private(selection),
        x301_wants_public(selection));
}

static void *x301_key_duplicate(const void *source_data, int selection)
{
    const X301_KEY *source = source_data;
    void *inner;

    if (source == NULL || source->provider == NULL || source->inner == NULL
            || !x301_selection_supported(selection))
        return NULL;
    inner = source->provider->rust->key_duplicate(
        source->inner,
        x301_wants_private(selection),
        x301_wants_public(selection));
    if (inner == NULL) {
        X301_RAISE(source->provider, X301_R_ALLOCATION_FAILURE,
            "X301 key duplication failed");
        return NULL;
    }
    return x301_wrap_key(source->provider, inner);
}

static const char *x301_key_query_operation_name(int operation_id)
{
    return operation_id == OSSL_OP_KEYEXCH ? X301_NAME : NULL;
}

static const OSSL_PARAM *x301_key_gen_settable_params(
    void *generation_context,
    void *provider_context)
{
    (void)generation_context;
    (void)provider_context;
    return X301_GEN_SETTABLE_PARAMS;
}

static int x301_key_gen_set_params(
    void *generation_context,
    const OSSL_PARAM params[])
{
    X301_GEN_CONTEXT *generation = generation_context;

    if (generation == NULL || generation->provider == NULL)
        return 0;
    if (!x301_utf8_param_equals(params, OSSL_PKEY_PARAM_GROUP_NAME, X301_NAME)) {
        X301_RAISE(generation->provider, X301_R_INVALID_PARAMETER,
            "invalid X301 generation group");
        return 0;
    }
    return 1;
}

static void *x301_key_gen_init(
    void *provider_context,
    int selection,
    const OSSL_PARAM params[])
{
    X301_PROVIDER_CONTEXT *provider = provider_context;
    X301_GEN_CONTEXT *generation;
    const int generates_keypair =
        (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
            == OSSL_KEYMGMT_SELECT_KEYPAIR;
    const int generates_parameters =
        selection == OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;

    if (provider == NULL
            || (!generates_keypair && !generates_parameters)
            || !x301_selection_supported(selection)) {
        X301_RAISE(provider, X301_R_INVALID_PARAMETER,
            "invalid X301 key generation selection");
        return NULL;
    }
    generation = x301_allocate(provider, sizeof(*generation));
    if (generation == NULL) {
        X301_RAISE(provider, X301_R_ALLOCATION_FAILURE,
            "X301 generation-context allocation failed");
        return NULL;
    }
    generation->provider = provider;
    generation->selection = selection;
    if (!x301_key_gen_set_params(generation, params)) {
        x301_clear_free(provider, generation, sizeof(*generation));
        return NULL;
    }
    return generation;
}

static int x301_fill_random(
    void *callback_context,
    unsigned char *output,
    size_t output_length)
{
    X301_PROVIDER_CONTEXT *provider = callback_context;

    if (provider == NULL || provider->libctx == NULL || output == NULL
            || output_length != X301_BYTES)
        return 0;
    return RAND_priv_bytes_ex(
        provider->libctx,
        output,
        output_length,
        X301_SECURITY_BITS) == 1;
}

static void *x301_generate_raw_key_internal(X301_PROVIDER_CONTEXT *provider)
{
    if (provider == NULL || provider->rust == NULL || provider->libctx == NULL)
        return NULL;
    return provider->rust->key_generate(x301_fill_random, provider);
}

#if defined(X301_ENABLE_HYBRID_MLKEM1024)
void *x301_generate_raw_key(X301_PROVIDER_CONTEXT *provider)
{
    void *key = x301_generate_raw_key_internal(provider);

    if (key == NULL)
        X301_RAISE(provider, X301_R_RANDOM_FAILURE,
            "OpenSSL private RAND or X301 key generation failed");
    return key;
}
#endif

static void *x301_key_gen(
    void *generation_context,
    OSSL_CALLBACK *progress_callback,
    void *callback_argument)
{
    X301_GEN_CONTEXT *generation = generation_context;
    X301_PROVIDER_CONTEXT *provider;
    void *inner = NULL;
    X301_KEY *key = NULL;

    (void)progress_callback;
    (void)callback_argument;
    if (generation == NULL || generation->provider == NULL)
        return NULL;
    provider = generation->provider;

    if (generation->selection == OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) {
        inner = provider->rust->key_new();
    } else if (provider->libctx != NULL) {
        /* Rust owns and zeroizes the single draw; failures terminate. */
        inner = x301_generate_raw_key_internal(provider);
    }
    if (inner == NULL) {
        X301_RAISE(provider, X301_R_RANDOM_FAILURE,
            "OpenSSL private RAND or X301 key generation failed");
        goto cleanup;
    }
    key = x301_wrap_key(provider, inner);
    inner = NULL;

cleanup:
    if (inner != NULL)
        provider->rust->key_free(inner);
    /* Release this child-context RAND state on the thread that created it. */
    OPENSSL_thread_stop_ex(provider->libctx);
    return key;
}

static void x301_key_gen_cleanup(void *generation_context)
{
    X301_GEN_CONTEXT *generation = generation_context;
    X301_PROVIDER_CONTEXT *provider;

    if (generation == NULL)
        return;
    provider = generation->provider;
    x301_clear_free(provider, generation, sizeof(*generation));
}

static X301_EXCHANGE *x301_wrap_exchange(
    X301_PROVIDER_CONTEXT *provider,
    void *inner)
{
    X301_EXCHANGE *exchange;

    if (provider == NULL || provider->rust == NULL || inner == NULL)
        return NULL;
    exchange = x301_allocate(provider, sizeof(*exchange));
    if (exchange == NULL) {
        provider->rust->exchange_free(inner);
        X301_RAISE(provider, X301_R_ALLOCATION_FAILURE,
            "X301 exchange-context allocation failed");
        return NULL;
    }
    exchange->provider = provider;
    exchange->inner = inner;
    return exchange;
}

static void *x301_exchange_new(void *provider_context)
{
    X301_PROVIDER_CONTEXT *provider = provider_context;
    void *inner;

    if (provider == NULL || provider->rust == NULL)
        return NULL;
    inner = provider->rust->exchange_new();
    if (inner == NULL) {
        X301_RAISE(provider, X301_R_ALLOCATION_FAILURE,
            "X301 exchange-context allocation failed");
        return NULL;
    }
    return x301_wrap_exchange(provider, inner);
}

static void x301_exchange_free(void *exchange_context)
{
    X301_EXCHANGE *exchange = exchange_context;
    X301_PROVIDER_CONTEXT *provider;

    if (exchange == NULL)
        return;
    provider = exchange->provider;
    if (provider != NULL && provider->rust != NULL && exchange->inner != NULL)
        provider->rust->exchange_free(exchange->inner);
    x301_clear_free(provider, exchange, sizeof(*exchange));
}

static void *x301_exchange_duplicate(void *exchange_context)
{
    X301_EXCHANGE *source = exchange_context;
    void *inner;

    if (source == NULL || source->provider == NULL || source->inner == NULL)
        return NULL;
    inner = source->provider->rust->exchange_duplicate(source->inner);
    if (inner == NULL) {
        X301_RAISE(source->provider, X301_R_ALLOCATION_FAILURE,
            "X301 exchange-context duplication failed");
        return NULL;
    }
    return x301_wrap_exchange(source->provider, inner);
}

static int x301_exchange_init(
    void *exchange_context,
    void *key_data,
    const OSSL_PARAM params[])
{
    X301_EXCHANGE *exchange = exchange_context;
    X301_KEY *key = key_data;
    int result;

    if (exchange == NULL || key == NULL || exchange->provider == NULL
            || exchange->provider != key->provider || exchange->inner == NULL
            || key->inner == NULL || !x301_params_are_empty(params))
        return 0;
    result = exchange->provider->rust->exchange_init(
        exchange->inner, key->inner);
    if (result != 1)
        X301_RAISE(exchange->provider, X301_R_INVALID_KEY,
            "X301 exchange requires a private key");
    return result;
}

static int x301_exchange_set_peer(
    void *exchange_context,
    void *peer_key_data)
{
    X301_EXCHANGE *exchange = exchange_context;
    X301_KEY *peer = peer_key_data;
    int result;

    if (exchange == NULL || peer == NULL || exchange->provider == NULL
            || exchange->provider != peer->provider || exchange->inner == NULL
            || peer->inner == NULL)
        return 0;
    result = exchange->provider->rust->exchange_set_peer(
        exchange->inner, peer->inner);
    if (result != 1)
        X301_RAISE(exchange->provider, X301_R_INVALID_KEY,
            "invalid X301 peer key");
    return result;
}

static int x301_exchange_derive(
    void *exchange_context,
    unsigned char *secret,
    size_t *secret_length,
    size_t output_length)
{
    X301_EXCHANGE *exchange = exchange_context;
    unsigned char result[X301_BYTES] = { 0 };
    int status = 0;

    if (exchange == NULL || exchange->provider == NULL
            || exchange->inner == NULL || secret_length == NULL)
        return 0;
    if (secret == NULL) {
        *secret_length = X301_BYTES;
        return 1;
    }
    if (output_length < X301_BYTES) {
        *secret_length = X301_BYTES;
        X301_RAISE(exchange->provider, X301_R_INVALID_PARAMETER,
            "X301 output buffer is too small");
        return 0;
    }

    *secret_length = 0;
    if (exchange->provider->rust->exchange_derive(
            exchange->inner, result, sizeof(result)) != 1) {
        X301_RAISE(exchange->provider, X301_R_INVALID_STATE,
            "X301 key exchange failed");
        goto cleanup;
    }
    memcpy(secret, result, sizeof(result));
    *secret_length = sizeof(result);
    status = 1;

cleanup:
    exchange->provider->rust->cleanse(result, sizeof(result));
    return status;
}

static const OSSL_DISPATCH X301_KEYMGMT_DISPATCH[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))x301_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))x301_key_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))x301_key_gen_init },
    {
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        (void (*)(void))x301_key_gen_set_params
    },
    {
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))x301_key_gen_settable_params
    },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))x301_key_gen },
    {
        OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        (void (*)(void))x301_key_gen_cleanup
    },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))x301_key_get_params },
    {
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        (void (*)(void))x301_key_gettable_params
    },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))x301_key_set_params },
    {
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        (void (*)(void))x301_key_settable_params
    },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))x301_key_has },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))x301_key_validate },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))x301_key_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))x301_key_import },
    {
        OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        (void (*)(void))x301_key_import_types
    },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))x301_key_export },
    {
        OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        (void (*)(void))x301_key_export_types
    },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))x301_key_duplicate },
    {
        OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        (void (*)(void))x301_key_query_operation_name
    },
    { 0, NULL }
};

static const OSSL_DISPATCH X301_KEYEXCH_DISPATCH[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))x301_exchange_new },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))x301_exchange_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))x301_exchange_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))x301_exchange_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))x301_exchange_free },
    {
        OSSL_FUNC_KEYEXCH_DUPCTX,
        (void (*)(void))x301_exchange_duplicate
    },
    { 0, NULL }
};

static const OSSL_ALGORITHM X301_KEYMGMT_ALGORITHMS[] = {
    {
        X301_ALGORITHM_NAMES,
        X301_PROPERTIES,
        X301_KEYMGMT_DISPATCH,
        "Experimental raw X301-v1 key management"
    },
#if defined(X301_ENABLE_HYBRID_MLKEM1024)
    {
        X301_MLKEM1024_ALGORITHM_NAMES,
        X301_PROPERTIES,
        X301_MLKEM1024_KEYMGMT_DISPATCH,
        "TLS X301MLKEM1024 key-management substrate"
    },
#endif
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM X301_KEYEXCH_ALGORITHMS[] = {
    {
        X301_ALGORITHM_NAMES,
        X301_PROPERTIES,
        X301_KEYEXCH_DISPATCH,
        "Experimental raw X301-v1 key exchange"
    },
    { NULL, NULL, NULL, NULL }
};

#if defined(X301_ENABLE_HYBRID_MLKEM1024)
static const OSSL_ALGORITHM X301_KEM_ALGORITHMS[] = {
    {
        X301_MLKEM1024_ALGORITHM_NAMES,
        X301_PROPERTIES,
        X301_MLKEM1024_KEM_DISPATCH,
        "TLS X301MLKEM1024 KEM substrate"
    },
    { NULL, NULL, NULL, NULL }
};
#endif

#if defined(X301_ENABLE_HYBRID_MLKEM1024)
static int x301_provider_get_capabilities(
    void *provider_context,
    const char *capability,
    OSSL_CALLBACK *callback,
    void *callback_argument)
{
    int minimum_tls = X301_TLS_VERSION_1_3;
    int maximum_tls = X301_TLS_VERSION_1_3;
    int minimum_dtls = -1;
    int maximum_dtls = -1;
    unsigned int hybrid_group_id = X301_MLKEM1024_TLS_GROUP_ID;
    unsigned int hybrid_security_bits = X301_MLKEM1024_SECURITY_BITS;
    unsigned int hybrid_is_kem = 1;
    OSSL_PARAM hybrid_group_parameters[] = {
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_GROUP_NAME,
            (char *)X301_MLKEM1024_NAME,
            sizeof(X301_MLKEM1024_NAME)),
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
            (char *)X301_MLKEM1024_NAME,
            sizeof(X301_MLKEM1024_NAME)),
        OSSL_PARAM_utf8_string(
            OSSL_CAPABILITY_TLS_GROUP_ALG,
            (char *)X301_MLKEM1024_NAME,
            sizeof(X301_MLKEM1024_NAME)),
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, &hybrid_group_id),
        OSSL_PARAM_uint(
            OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
            &hybrid_security_bits),
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, &hybrid_is_kem),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &minimum_tls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &maximum_tls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &minimum_dtls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &maximum_dtls),
        OSSL_PARAM_END
    };

    (void)provider_context;
    if (capability == NULL || callback == NULL)
        return 0;
    if (strcmp(capability, X301_TLS_GROUP_CAPABILITY) != 0)
        return 0;
    return callback(hybrid_group_parameters, callback_argument);
}
#endif

static void x301_provider_teardown(void *provider_context)
{
    X301_PROVIDER_CONTEXT *provider = provider_context;

    if (provider == NULL)
        return;
    OSSL_LIB_CTX_free(provider->libctx);
    provider->libctx = NULL;
    if (provider->clear_free != NULL)
        provider->clear_free(provider, sizeof(*provider), __FILE__, __LINE__);
}

static const OSSL_PARAM *x301_provider_gettable_params(void *provider_context)
{
    (void)provider_context;
    return X301_PROVIDER_GETTABLE_PARAMS;
}

static int x301_provider_get_params(
    void *provider_context,
    OSSL_PARAM params[])
{
    X301_PROVIDER_CONTEXT *provider = provider_context;

    if (provider == NULL || params == NULL)
        return 0;
    return x301_param_set_optional_utf8_ptr(
               OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME),
               X301_PROVIDER_NAME)
        && x301_param_set_optional_utf8_ptr(
               OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION),
               X301_PROVIDER_VERSION)
        && x301_param_set_optional_utf8_ptr(
               OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO),
               X301_PROVIDER_BUILDINFO)
        && x301_param_set_optional_int(
               OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS),
               1);
}

static const OSSL_ITEM *x301_provider_get_reason_strings(
    void *provider_context)
{
    (void)provider_context;
    return X301_REASON_STRINGS;
}

static const OSSL_ALGORITHM *x301_provider_query_operation(
    void *provider_context,
    int operation_id,
    int *no_cache)
{
    (void)provider_context;
    if (no_cache != NULL)
        *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return X301_KEYMGMT_ALGORITHMS;
    if (operation_id == OSSL_OP_KEYEXCH)
        return X301_KEYEXCH_ALGORITHMS;
#if defined(X301_ENABLE_HYBRID_MLKEM1024)
    if (operation_id == OSSL_OP_KEM)
        return X301_KEM_ALGORITHMS;
#endif
    return NULL;
}

static const OSSL_DISPATCH X301_PROVIDER_DISPATCH[] = {
    {
        OSSL_FUNC_PROVIDER_TEARDOWN,
        (void (*)(void))x301_provider_teardown
    },
    {
        OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        (void (*)(void))x301_provider_gettable_params
    },
    {
        OSSL_FUNC_PROVIDER_GET_PARAMS,
        (void (*)(void))x301_provider_get_params
    },
    {
        OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
        (void (*)(void))x301_provider_get_reason_strings
    },
    {
        OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        (void (*)(void))x301_provider_query_operation
    },
#if defined(X301_ENABLE_HYBRID_MLKEM1024)
    {
        OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
        (void (*)(void))x301_provider_get_capabilities
    },
#endif
    { 0, NULL }
};

static int x301_parse_decimal_component(
    const char **cursor,
    unsigned int *value)
{
    const char *position;
    unsigned int accumulator = 0;

    if (cursor == NULL || *cursor == NULL || value == NULL)
        return 0;
    position = *cursor;
    if (*position < '0' || *position > '9')
        return 0;
    do {
        unsigned int digit = (unsigned int)(*position - '0');
        if (accumulator > (UINT_MAX - digit) / 10U)
            return 0;
        accumulator = accumulator * 10U + digit;
        position++;
    } while (*position >= '0' && *position <= '9');
    *cursor = position;
    *value = accumulator;
    return 1;
}

static int x301_core_version_is_supported(
    const OSSL_CORE_HANDLE *handle,
    OSSL_FUNC_core_get_params_fn *get_params)
{
    char *core_version = NULL;
    const char *cursor;
    unsigned int major;
    unsigned int minor;
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_CORE_VERSION, &core_version, 0),
        OSSL_PARAM_END
    };

    if (handle == NULL || get_params == NULL
            || get_params(handle, parameters) != 1
            || core_version == NULL)
        return 0;
    cursor = core_version;
    if (!x301_parse_decimal_component(&cursor, &major) || *cursor++ != '.'
            || !x301_parse_decimal_component(&cursor, &minor)
            || (*cursor != '.' && *cursor != '\0'))
        return 0;
    (void)minor;
    return major == X301_SUPPORTED_CORE_MAJOR;
}

static int x301_rust_api_is_valid(const X301_RUST_API *rust)
{
    return rust != NULL
        && rust->abi_version == 1
        && rust->struct_size == sizeof(*rust)
        && rust->secret_bytes == X301_BYTES
        && rust->public_bytes == X301_BYTES
        && rust->shared_bytes == X301_BYTES
        && rust->key_new != NULL
        && rust->key_free != NULL
        && rust->key_import != NULL
        && rust->key_set_encoded_public != NULL
        && rust->key_generate != NULL
        && rust->key_duplicate != NULL
        && rust->key_has != NULL
        && rust->key_validate != NULL
        && rust->key_match != NULL
        && rust->key_get_private != NULL
        && rust->key_get_public != NULL
        && rust->exchange_new != NULL
        && rust->exchange_free != NULL
        && rust->exchange_duplicate != NULL
        && rust->exchange_init != NULL
        && rust->exchange_set_peer != NULL
        && rust->exchange_derive != NULL
        && rust->cleanse != NULL;
}

int x301_shim_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch,
    void **provider_context,
    const X301_RUST_API *rust_api)
{
    const OSSL_DISPATCH *dispatch;
    OSSL_FUNC_core_get_params_fn *core_get_params = NULL;
    OSSL_FUNC_CRYPTO_zalloc_fn *zalloc = NULL;
    OSSL_FUNC_CRYPTO_clear_free_fn *clear_free = NULL;
    OSSL_FUNC_core_new_error_fn *new_error = NULL;
    OSSL_FUNC_core_set_error_debug_fn *set_error_debug = NULL;
    OSSL_FUNC_core_vset_error_fn *vset_error = NULL;
    X301_PROVIDER_CONTEXT *provider;

    if (handle == NULL || input_dispatch == NULL || output_dispatch == NULL
            || provider_context == NULL)
        return 0;
    *output_dispatch = NULL;
    *provider_context = NULL;
    if (!x301_rust_api_is_valid(rust_api))
        return 0;

    for (dispatch = input_dispatch; dispatch->function_id != 0; dispatch++) {
        switch (dispatch->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            core_get_params = OSSL_FUNC_core_get_params(dispatch);
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            zalloc = OSSL_FUNC_CRYPTO_zalloc(dispatch);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_FREE:
            clear_free = OSSL_FUNC_CRYPTO_clear_free(dispatch);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            new_error = OSSL_FUNC_core_new_error(dispatch);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            set_error_debug = OSSL_FUNC_core_set_error_debug(dispatch);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            vset_error = OSSL_FUNC_core_vset_error(dispatch);
            break;
        default:
            break;
        }
    }
    if (core_get_params == NULL || zalloc == NULL || clear_free == NULL
            || !x301_core_version_is_supported(handle, core_get_params))
        return 0;

    provider = zalloc(sizeof(*provider), __FILE__, __LINE__);
    if (provider == NULL)
        return 0;
    provider->handle = handle;
    provider->zalloc = zalloc;
    provider->clear_free = clear_free;
    provider->new_error = new_error;
    provider->set_error_debug = set_error_debug;
    provider->vset_error = vset_error;
    provider->rust = rust_api;
    provider->libctx = OSSL_LIB_CTX_new_child(handle, input_dispatch);
    if (provider->libctx == NULL) {
        clear_free(provider, sizeof(*provider), __FILE__, __LINE__);
        return 0;
    }

    *provider_context = provider;
    *output_dispatch = X301_PROVIDER_DISPATCH;
    return 1;
}
