#define _POSIX_C_SOURCE 200809L

/*
 * X301 EVP KEYMGMT/KEYEXCH and RAND-separation contract tests (T6/T7).
 *
 * Contract sources:
 *   - docs/X301_DRAFT.md sections 7 and 12 (38-byte strict keys, XDH);
 *   - RFC 7748 sections 5-6 (raw XDH/derive API pattern);
 *   - OpenSSL provider-keymgmt(7), provider-keyexch(7), RAND_priv_bytes_ex(3);
 *   - OpenSSL ECX key-management tests for raw-key and RAND policy shape.
 *
 * Expected X301 bytes are frozen independent-reference vectors, not values
 * read back from the provider under test.
 */

#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "generated/x301_adversarial_vectors.h"

#define X301_BYTES 38U
#define X301_NAME "X301"
#define X301_PROVIDER "x301"
#define X301_PROPERTIES "provider=x301"
#define TEST_RAND_PROVIDER "x301_test_rand"
#define TEST_RAND_PROPERTY "provider=x301_test_rand"

static const unsigned char SECRET_A[X301_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25
};
static const unsigned char PUBLIC_A[X301_BYTES] = {
    0xb5, 0xd1, 0x9e, 0x31, 0xe6, 0xbf, 0xa6, 0xf5,
    0xc4, 0x74, 0x11, 0x73, 0x83, 0x60, 0xba, 0x94,
    0xb7, 0xbb, 0xff, 0x1c, 0x4b, 0xb9, 0xfc, 0x64,
    0x6e, 0x97, 0x75, 0xbb, 0xd7, 0x56, 0x5a, 0x60,
    0x52, 0x81, 0x97, 0x81, 0xc2, 0x1a
};
static const unsigned char SECRET_B[X301_BYTES] = {
    0x25, 0x24, 0x23, 0x22, 0x21, 0x20, 0x1f, 0x1e,
    0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16,
    0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, 0x0e,
    0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06,
    0x05, 0x04, 0x03, 0x02, 0x01, 0x00
};
static const unsigned char PUBLIC_B[X301_BYTES] = {
    0x86, 0xa7, 0xfa, 0x2c, 0xcb, 0x11, 0xa7, 0x6c,
    0x34, 0xfd, 0x7b, 0xca, 0x0f, 0x6e, 0x59, 0x2c,
    0x99, 0x91, 0xcb, 0x55, 0x4c, 0xd7, 0xb3, 0x26,
    0xa2, 0x17, 0x7d, 0xf7, 0xdb, 0xb0, 0xf4, 0xc5,
    0x14, 0x38, 0x15, 0x19, 0x92, 0x1d
};
static const unsigned char SHARED_AB[X301_BYTES] = {
    0x70, 0xa5, 0x4b, 0xeb, 0xec, 0xf4, 0xa6, 0xf6,
    0x8a, 0xa3, 0x0e, 0x6b, 0x08, 0x1d, 0x29, 0xfb,
    0x59, 0xda, 0x71, 0xeb, 0xd6, 0xfb, 0xf3, 0x4f,
    0x14, 0x78, 0x06, 0x50, 0xea, 0x2b, 0xaa, 0x07,
    0x6c, 0x3a, 0xfc, 0x7a, 0x41, 0x11
};
static const unsigned char SHARED_AA[X301_BYTES] = {
    0x47, 0xf8, 0x57, 0xc5, 0x9d, 0x9f, 0xe2, 0x8f,
    0x8a, 0x62, 0xaf, 0x17, 0xf6, 0x3b, 0x79, 0x9f,
    0xe5, 0x1e, 0x9d, 0x40, 0xbf, 0xef, 0xdb, 0xdd,
    0x3b, 0xd1, 0x00, 0xb5, 0xdf, 0xdc, 0xb8, 0x50,
    0xaf, 0x1d, 0xb8, 0xa7, 0x2a, 0x1e
};

/*
 * The built-in test RAND emits this exact sequence.  TEST_RAND_PUBLIC was
 * derived independently with reference/x301/x301_reference.py through both
 * its Montgomery ladder and Edwards-to-Montgomery group path.
 */
static const unsigned char TEST_RAND_SEED[X301_BYTES] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5
};
static const unsigned char TEST_RAND_PUBLIC[X301_BYTES] = {
    0x0a, 0x41, 0xc4, 0x68, 0x1e, 0x65, 0xfb, 0x56,
    0x43, 0xe8, 0x1b, 0x66, 0xe0, 0x49, 0x15, 0xd1,
    0x56, 0xfc, 0xd0, 0xd1, 0x7a, 0x10, 0xb9, 0xc0,
    0x11, 0x67, 0x94, 0xe4, 0x1a, 0xf1, 0xce, 0xb8,
    0xb2, 0xe4, 0xd9, 0x80, 0xc8, 0x16
};

/*
 * Independently derived T4 fixture from reference/x301/x301-test-vectors.json.
 * The entries are the complete canonical affine small-order u corpus:
 * 0, 1 and p-1 for p = 2^301 - 2^99 + 947.
 */
static const unsigned char SMALL_ORDER_U[3][X301_BYTES] = {
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0xb2, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0x1f
    }
};

typedef struct test_rand_context_st {
    int state;
} TEST_RAND_CONTEXT;

static unsigned int checks;
static unsigned int rand_generate_calls;
static int rand_poisoned;

static int buffer_is(const unsigned char *buffer, size_t length, unsigned char value)
{
    size_t index;

    for (index = 0; index < length; index++) {
        if (buffer[index] != value)
            return 0;
    }
    return 1;
}

static int hex_decode(
    const char *hex,
    unsigned char *output,
    size_t capacity,
    size_t *output_length)
{
    size_t index;
    size_t length;

    if (hex == NULL || output == NULL || output_length == NULL)
        return 0;
    length = strlen(hex);
    if ((length & 1U) != 0U || length / 2U > capacity)
        return 0;
    *output_length = length / 2U;
    for (index = 0; index < *output_length; index++) {
        unsigned char high = (unsigned char)hex[index * 2U];
        unsigned char low = (unsigned char)hex[index * 2U + 1U];
        unsigned int high_value;
        unsigned int low_value;

        if (high >= '0' && high <= '9')
            high_value = high - '0';
        else if (high >= 'a' && high <= 'f')
            high_value = high - 'a' + 10U;
        else
            return 0;
        if (low >= '0' && low <= '9')
            low_value = low - '0';
        else if (low >= 'a' && low <= 'f')
            low_value = low - 'a' + 10U;
        else
            return 0;
        output[index] = (unsigned char)((high_value << 4) | low_value);
    }
    return 1;
}

static int pass(const char *label)
{
    checks++;
    printf("ok %u - %s\n", checks, label);
    return 1;
}

static int fail(const char *label)
{
    fprintf(stderr, "not ok %u - %s\n", checks + 1U, label);
    ERR_print_errors_fp(stderr);
    return 0;
}

static void *test_rand_newctx(
    void *provider_context,
    void *parent,
    const OSSL_DISPATCH *parent_dispatch)
{
    TEST_RAND_CONTEXT *context = calloc(1, sizeof(*context));

    (void)provider_context;
    (void)parent;
    (void)parent_dispatch;
    if (context != NULL)
        context->state = EVP_RAND_STATE_UNINITIALISED;
    return context;
}

static void test_rand_freectx(void *context)
{
    free(context);
}

static int test_rand_instantiate(
    void *context_data,
    unsigned int strength,
    int prediction_resistance,
    const unsigned char *personalization,
    size_t personalization_length,
    const OSSL_PARAM params[])
{
    TEST_RAND_CONTEXT *context = context_data;

    (void)prediction_resistance;
    (void)personalization;
    (void)personalization_length;
    (void)params;
    if (context == NULL || strength > 256U)
        return 0;
    context->state = EVP_RAND_STATE_READY;
    return 1;
}

static int test_rand_uninstantiate(void *context_data)
{
    TEST_RAND_CONTEXT *context = context_data;

    if (context == NULL)
        return 0;
    context->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

static int test_rand_generate(
    void *context_data,
    unsigned char *output,
    size_t output_length,
    unsigned int strength,
    int prediction_resistance,
    const unsigned char *additional_input,
    size_t additional_input_length)
{
    TEST_RAND_CONTEXT *context = context_data;
    size_t index;

    (void)prediction_resistance;
    (void)additional_input;
    (void)additional_input_length;
    rand_generate_calls++;
    if (context == NULL || context->state != EVP_RAND_STATE_READY
            || output == NULL || strength > 256U || rand_poisoned)
        return 0;
    for (index = 0; index < output_length; index++)
        output[index] = (unsigned char)(0xa0U + index);
    return 1;
}

static int test_rand_enable_locking(void *context)
{
    return context != NULL;
}

static int test_rand_lock(void *context)
{
    return context != NULL;
}

static void test_rand_unlock(void *context)
{
    (void)context;
}

static const OSSL_PARAM *test_rand_gettable(
    void *context,
    void *provider_context)
{
    static const OSSL_PARAM parameters[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };

    (void)context;
    (void)provider_context;
    return parameters;
}

static int test_rand_get_params(void *context_data, OSSL_PARAM params[])
{
    TEST_RAND_CONTEXT *context = context_data;
    OSSL_PARAM *parameter;

    if (context == NULL)
        return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (parameter != NULL
            && OSSL_PARAM_set_int(parameter, context->state) != 1)
        return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (parameter != NULL && OSSL_PARAM_set_uint(parameter, 256U) != 1)
        return 0;
    parameter = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (parameter != NULL
            && OSSL_PARAM_set_size_t(parameter, INT_MAX) != 1)
        return 0;
    return 1;
}

static const OSSL_DISPATCH TEST_RAND_FUNCTIONS[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))test_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))test_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))test_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE,
        (void (*)(void))test_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))test_rand_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,
        (void (*)(void))test_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))test_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))test_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        (void (*)(void))test_rand_gettable },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))test_rand_get_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM TEST_RAND_ALGORITHMS[] = {
    { "CTR-DRBG", TEST_RAND_PROPERTY, TEST_RAND_FUNCTIONS,
        "poisonable X301 contract-test RAND" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *test_rand_query(
    void *provider_context,
    int operation_id,
    int *no_cache)
{
    (void)provider_context;
    if (no_cache != NULL)
        *no_cache = 0;
    return operation_id == OSSL_OP_RAND ? TEST_RAND_ALGORITHMS : NULL;
}

static const OSSL_DISPATCH TEST_RAND_PROVIDER_DISPATCH[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        (void (*)(void))test_rand_query },
    { 0, NULL }
};

static int test_rand_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch,
    void **provider_context)
{
    (void)handle;
    (void)input_dispatch;
    if (output_dispatch == NULL || provider_context == NULL)
        return 0;
    *provider_context = NULL;
    *output_dispatch = TEST_RAND_PROVIDER_DISPATCH;
    return 1;
}

static EVP_PKEY *raw_private(
    OSSL_LIB_CTX *libctx,
    const unsigned char *bytes,
    size_t length)
{
    return EVP_PKEY_new_raw_private_key_ex(
        libctx, X301_NAME, X301_PROPERTIES, bytes, length);
}

static EVP_PKEY *raw_public(
    OSSL_LIB_CTX *libctx,
    const unsigned char *bytes,
    size_t length)
{
    return EVP_PKEY_new_raw_public_key_ex(
        libctx, X301_NAME, X301_PROPERTIES, bytes, length);
}

static int raw_roundtrip(
    EVP_PKEY *private_key,
    EVP_PKEY *public_key,
    const unsigned char secret[X301_BYTES],
    const unsigned char public_bytes[X301_BYTES])
{
    unsigned char output[64];
    size_t length = 0;

    if (EVP_PKEY_get_raw_private_key(private_key, NULL, &length) <= 0
            || length != X301_BYTES)
        return 0;
    memset(output, 0xa5, sizeof(output));
    length = sizeof(output);
    if (EVP_PKEY_get_raw_private_key(private_key, output, &length) <= 0
            || length != X301_BYTES
            || memcmp(output, secret, X301_BYTES) != 0
            || !buffer_is(output + X301_BYTES,
                sizeof(output) - X301_BYTES, 0xa5))
        return 0;
    length = 0;
    if (EVP_PKEY_get_raw_public_key(private_key, NULL, &length) <= 0
            || length != X301_BYTES)
        return 0;
    memset(output, 0xa5, sizeof(output));
    length = sizeof(output);
    if (EVP_PKEY_get_raw_public_key(private_key, output, &length) <= 0
            || length != X301_BYTES
            || memcmp(output, public_bytes, X301_BYTES) != 0
            || !buffer_is(output + X301_BYTES,
                sizeof(output) - X301_BYTES, 0xa5))
        return 0;
    length = 0;
    return EVP_PKEY_get_raw_public_key(public_key, NULL, &length) > 0
        && length == X301_BYTES;
}

static int invalid_lengths_rejected(OSSL_LIB_CTX *libctx)
{
    unsigned char extended[X301_BYTES + 1U];
    const size_t lengths[] = { 0U, X301_BYTES - 1U, X301_BYTES + 1U };
    size_t index;

    memcpy(extended, SECRET_A, X301_BYTES);
    extended[X301_BYTES] = 0;
    for (index = 0; index < sizeof(lengths) / sizeof(lengths[0]); index++) {
        EVP_PKEY *private_key = raw_private(libctx, extended, lengths[index]);
        EVP_PKEY *public_key = raw_public(libctx, extended, lengths[index]);

        if (private_key != NULL || public_key != NULL) {
            EVP_PKEY_free(public_key);
            EVP_PKEY_free(private_key);
            return 0;
        }
        ERR_clear_error();
    }
    return 1;
}

static int derive_exact(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *peer,
    unsigned char output[X301_BYTES])
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    size_t length = 0;
    size_t output_length = X301_BYTES;
    int result = context != NULL
        && EVP_PKEY_derive_init(context) > 0
        && EVP_PKEY_derive_set_peer(context, peer) > 0
        && EVP_PKEY_derive(context, NULL, &length) > 0
        && length == X301_BYTES
        && EVP_PKEY_derive(context, output, &output_length) > 0
        && output_length == X301_BYTES;

    EVP_PKEY_CTX_free(context);
    return result;
}

static int derive_initialized(
    EVP_PKEY_CTX *context,
    unsigned char output[X301_BYTES])
{
    size_t query_length = 0;
    size_t output_length = X301_BYTES;

    return context != NULL
        && EVP_PKEY_derive(context, NULL, &query_length) > 0
        && query_length == X301_BYTES
        && EVP_PKEY_derive(context, output, &output_length) > 0
        && output_length == X301_BYTES;
}

static int peer_replacement_and_repeated_derive(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *first_peer,
    EVP_PKEY *last_peer)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    unsigned char first[X301_BYTES];
    unsigned char second[X301_BYTES];
    int result = context != NULL
        && EVP_PKEY_derive_init(context) > 0
        && EVP_PKEY_derive_set_peer(context, first_peer) > 0
        && EVP_PKEY_derive_set_peer(context, last_peer) > 0
        && derive_initialized(context, first)
        && derive_initialized(context, second)
        && memcmp(first, SHARED_AB, sizeof(first)) == 0
        && memcmp(second, SHARED_AB, sizeof(second)) == 0;

    OPENSSL_cleanse(first, sizeof(first));
    OPENSSL_cleanse(second, sizeof(second));
    EVP_PKEY_CTX_free(context);
    return result;
}

static int duplicated_context_is_independent(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *peer)
{
    EVP_PKEY_CTX *original = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    EVP_PKEY_CTX *duplicate = NULL;
    unsigned char warmup[X301_BYTES];
    unsigned char original_output[X301_BYTES];
    unsigned char duplicate_output[X301_BYTES];
    int result = 0;

    if (original == NULL || EVP_PKEY_derive_init(original) <= 0
            || EVP_PKEY_derive_set_peer(original, peer) <= 0
            || !derive_initialized(original, warmup)
            || !derive_initialized(original, warmup)
            || (duplicate = EVP_PKEY_CTX_dup(original)) == NULL)
        goto done;
    if (!derive_initialized(duplicate, duplicate_output)
            || !derive_initialized(original, original_output)
            || memcmp(original_output, SHARED_AB,
                sizeof(original_output)) != 0
            || memcmp(duplicate_output, SHARED_AB,
                sizeof(duplicate_output)) != 0)
        goto done;
    result = 1;

done:
    OPENSSL_cleanse(warmup, sizeof(warmup));
    OPENSSL_cleanse(original_output, sizeof(original_output));
    OPENSSL_cleanse(duplicate_output, sizeof(duplicate_output));
    EVP_PKEY_CTX_free(duplicate);
    EVP_PKEY_CTX_free(original);
    return result;
}

static int reinitialization_clears_peer(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_a,
    EVP_PKEY *private_b,
    EVP_PKEY *public_a,
    EVP_PKEY *public_b)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_a, X301_PROPERTIES);
    EVP_PKEY_CTX *replacement = NULL;
    unsigned char output[X301_BYTES];
    size_t output_length;
    int result = 0;

    if (context == NULL || EVP_PKEY_derive_init(context) <= 0
            || EVP_PKEY_derive_set_peer(context, public_a) <= 0
            || !derive_initialized(context, output)
            || memcmp(output, SHARED_AA, sizeof(output)) != 0
            || EVP_PKEY_derive_init(context) <= 0)
        goto done;
    memset(output, 0xa5, sizeof(output));
    output_length = sizeof(output);
    if (EVP_PKEY_derive(context, output, &output_length) > 0
            || !buffer_is(output, sizeof(output), 0xa5))
        goto done;
    ERR_clear_error();
    if (EVP_PKEY_derive_set_peer(context, public_b) <= 0
            || !derive_initialized(context, output)
            || memcmp(output, SHARED_AB, sizeof(output)) != 0)
        goto done;

    /*
     * OpenSSL binds the local EVP_PKEY when the EVP_PKEY_CTX is created;
     * there is no public API for replacing it in place.  A local-key switch
     * therefore means a fresh context, which must start without a peer.
     */
    replacement = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_b, X301_PROPERTIES);
    if (replacement == NULL || EVP_PKEY_derive_init(replacement) <= 0)
        goto done;
    memset(output, 0xa5, sizeof(output));
    output_length = sizeof(output);
    if (EVP_PKEY_derive(replacement, output, &output_length) > 0
            || !buffer_is(output, sizeof(output), 0xa5))
        goto done;
    ERR_clear_error();
    if (EVP_PKEY_derive_set_peer(replacement, public_a) <= 0
            || !derive_initialized(replacement, output)
            || memcmp(output, SHARED_AB, sizeof(output)) != 0)
        goto done;
    result = 1;

done:
    ERR_clear_error();
    OPENSSL_cleanse(output, sizeof(output));
    EVP_PKEY_CTX_free(replacement);
    EVP_PKEY_CTX_free(context);
    return result;
}

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned int ready;
    int start;
} DERIVE_GATE;

typedef struct {
    DERIVE_GATE *gate;
    OSSL_LIB_CTX *libctx;
    EVP_PKEY *private_key;
    EVP_PKEY *peer;
    int ok;
} DERIVE_WORKER;

static void *parallel_derive_worker(void *argument)
{
    DERIVE_WORKER *worker = argument;
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        worker->libctx, worker->private_key, X301_PROPERTIES);
    unsigned char output[X301_BYTES];
    unsigned int iteration;
    int ready = context != NULL
        && EVP_PKEY_derive_init(context) > 0
        && EVP_PKEY_derive_set_peer(context, worker->peer) > 0;

    pthread_mutex_lock(&worker->gate->mutex);
    worker->gate->ready++;
    pthread_cond_broadcast(&worker->gate->condition);
    while (!worker->gate->start)
        pthread_cond_wait(&worker->gate->condition, &worker->gate->mutex);
    pthread_mutex_unlock(&worker->gate->mutex);

    worker->ok = ready;
    for (iteration = 0; worker->ok && iteration < 250U; iteration++) {
        worker->ok = derive_initialized(context, output)
            && memcmp(output, SHARED_AB, sizeof(output)) == 0;
    }
    OPENSSL_cleanse(output, sizeof(output));
    EVP_PKEY_CTX_free(context);
    return NULL;
}

static int parallel_derives_share_keys_safely(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *peer)
{
    DERIVE_GATE gate;
    DERIVE_WORKER workers[4];
    pthread_t threads[4];
    size_t created = 0;
    size_t index;
    int mutex_ready = 0;
    int condition_ready = 0;
    int result = 0;

    memset(&gate, 0, sizeof(gate));
    memset(workers, 0, sizeof(workers));
    mutex_ready = pthread_mutex_init(&gate.mutex, NULL) == 0;
    condition_ready = mutex_ready
        && pthread_cond_init(&gate.condition, NULL) == 0;
    if (!condition_ready)
        goto done;
    for (index = 0; index < 4U; index++) {
        workers[index].gate = &gate;
        workers[index].libctx = libctx;
        workers[index].private_key = private_key;
        workers[index].peer = peer;
        if (pthread_create(
                &threads[index], NULL, parallel_derive_worker,
                &workers[index]) != 0)
            break;
        created++;
    }
    pthread_mutex_lock(&gate.mutex);
    while (gate.ready < created)
        pthread_cond_wait(&gate.condition, &gate.mutex);
    gate.start = 1;
    pthread_cond_broadcast(&gate.condition);
    pthread_mutex_unlock(&gate.mutex);
    for (index = 0; index < created; index++)
        pthread_join(threads[index], NULL);
    if (created != 4U)
        goto done;
    for (index = 0; index < 4U; index++) {
        if (!workers[index].ok)
            goto done;
    }
    result = 1;

done:
    if (condition_ready)
        pthread_cond_destroy(&gate.condition);
    if (mutex_ready)
        pthread_mutex_destroy(&gate.mutex);
    return result;
}

static int no_peer_and_short_output_are_atomic(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *peer)
{
    EVP_PKEY_CTX *context = NULL;
    unsigned char output[64];
    size_t length;
    int result = 0;

    context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    if (context == NULL || EVP_PKEY_derive_init(context) <= 0)
        goto done;
    memset(output, 0xa5, sizeof(output));
    length = X301_BYTES;
    if (EVP_PKEY_derive(context, output, &length) > 0
            || !buffer_is(output, sizeof(output), 0xa5))
        goto done;
    ERR_clear_error();
    if (EVP_PKEY_derive_set_peer(context, peer) <= 0)
        goto done;
    memset(output, 0xa5, sizeof(output));
    length = X301_BYTES - 1U;
    if (EVP_PKEY_derive(context, output, &length) > 0
            || length != X301_BYTES
            || !buffer_is(output, sizeof(output), 0xa5))
        goto done;
    ERR_clear_error();
    result = 1;

done:
    EVP_PKEY_CTX_free(context);
    return result;
}

static int small_order_derive_rejects_atomically(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *peer,
    int query_length_first)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    unsigned char output[X301_BYTES];
    size_t length = 0;
    int result = 0;

    if (context == NULL || EVP_PKEY_derive_init(context) <= 0
            || EVP_PKEY_derive_set_peer(context, peer) <= 0)
        goto done;
    if (query_length_first
            && (EVP_PKEY_derive(context, NULL, &length) <= 0
                || length != X301_BYTES))
        goto done;
    memset(output, 0xa5, sizeof(output));
    length = sizeof(output);
    ERR_clear_error();
    if (EVP_PKEY_derive(context, output, &length) > 0
            || !buffer_is(output, sizeof(output), 0xa5))
        goto done;
    result = 1;

done:
    ERR_clear_error();
    EVP_PKEY_CTX_free(context);
    return result;
}

static int all_small_order_peers_rejected(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_a,
    EVP_PKEY *private_b)
{
    EVP_PKEY *private_keys[2] = { private_a, private_b };
    size_t peer_index;
    size_t key_index;

    for (peer_index = 0;
            peer_index < sizeof(SMALL_ORDER_U) / sizeof(SMALL_ORDER_U[0]);
            peer_index++) {
        EVP_PKEY *peer = raw_public(
            libctx, SMALL_ORDER_U[peer_index], X301_BYTES);

        if (peer == NULL)
            return 0;
        for (key_index = 0;
                key_index < sizeof(private_keys) / sizeof(private_keys[0]);
                key_index++) {
            if (!small_order_derive_rejects_atomically(
                    libctx, private_keys[key_index], peer, 0)
                    || !small_order_derive_rejects_atomically(
                        libctx, private_keys[key_index], peer, 1)) {
                EVP_PKEY_free(peer);
                return 0;
            }
        }
        EVP_PKEY_free(peer);
    }
    return 1;
}

static int adversarial_corpus_matches(OSSL_LIB_CTX *libctx)
{
    unsigned char secret[2U * X301_BYTES];
    unsigned char public_bytes[2U * X301_BYTES];
    unsigned char expected[2U * X301_BYTES];
    unsigned char actual[X301_BYTES];
    size_t index;

    if (sizeof(x301_adversarial_vectors)
            / sizeof(x301_adversarial_vectors[0])
            != X301_ADVERSARIAL_VECTOR_COUNT)
        return 0;
    for (index = 0; index < X301_ADVERSARIAL_VECTOR_COUNT; index++) {
        const X301_ADVERSARIAL_VECTOR *vector =
            &x301_adversarial_vectors[index];
        EVP_PKEY *private_key = NULL;
        EVP_PKEY *peer = NULL;
        size_t secret_length = 0;
        size_t public_length = 0;
        size_t expected_length = 0;
        size_t actual_length = sizeof(actual);
        int case_ok = 0;

        if (!hex_decode(vector->secret_hex, secret, sizeof(secret),
                &secret_length)
                || !hex_decode(vector->public_hex, public_bytes,
                    sizeof(public_bytes), &public_length)
                || !hex_decode(vector->expected_output_hex, expected,
                    sizeof(expected), &expected_length))
            return 0;

        private_key = raw_private(libctx, secret, secret_length);
        if (strcmp(vector->operation, "public_from_secret") == 0) {
            if (strcmp(vector->expected, "valid") == 0) {
                case_ok = private_key != NULL
                    && expected_length == X301_BYTES
                    && EVP_PKEY_get_raw_public_key(
                        private_key, actual, &actual_length) > 0
                    && actual_length == X301_BYTES
                    && memcmp(actual, expected, X301_BYTES) == 0;
            } else {
                case_ok = strcmp(vector->expected_error, "secret_length") == 0
                    && private_key == NULL;
            }
        } else if (strcmp(vector->operation, "derive") == 0) {
            if (private_key == NULL)
                goto case_done;
            peer = raw_public(libctx, public_bytes, public_length);
            if (strcmp(vector->expected, "valid") == 0) {
                case_ok = peer != NULL
                    && expected_length == X301_BYTES
                    && derive_exact(libctx, private_key, peer, actual)
                    && memcmp(actual, expected, X301_BYTES) == 0;
            } else if (strcmp(vector->expected_error, "all_zero") == 0) {
                case_ok = peer != NULL
                    && small_order_derive_rejects_atomically(
                        libctx, private_key, peer, 0)
                    && small_order_derive_rejects_atomically(
                        libctx, private_key, peer, 1);
            } else {
                case_ok = peer == NULL
                    && (strcmp(vector->expected_error, "length") == 0
                        || strcmp(vector->expected_error, "noncanonical") == 0
                        || strcmp(vector->expected_error, "reserved_bits") == 0);
            }
        }

case_done:
        EVP_PKEY_free(peer);
        EVP_PKEY_free(private_key);
        ERR_clear_error();
        if (!case_ok) {
            fprintf(stderr,
                "adversarial tcId %u failed (family=%s flags=%s)\n",
                vector->tc_id, vector->family, vector->flags);
            OPENSSL_cleanse(secret, sizeof(secret));
            OPENSSL_cleanse(expected, sizeof(expected));
            OPENSSL_cleanse(actual, sizeof(actual));
            return 0;
        }
    }
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual, sizeof(actual));
    return 1;
}

/*
 * F1-F3 deterministic structured sweep at the public EVP boundary.
 *
 * This is the documented fallback when libFuzzer/AFL++ is unavailable.  It
 * completely covers raw lengths 0..76, every deletion/insertion position,
 * and every one-byte substitution at every position of one valid private
 * and one valid peer key.  The frozen W1-W6 corpus is run immediately before
 * this sweep and therefore supplies its semantic edge-case seeds.
 */
static int swept_peer_is_atomic(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    const unsigned char peer_bytes[X301_BYTES])
{
    EVP_PKEY *peer = raw_public(libctx, peer_bytes, X301_BYTES);
    EVP_PKEY_CTX *context = NULL;
    unsigned char output[X301_BYTES + 16U];
    size_t queried = 0;
    size_t output_length = X301_BYTES;
    int derive_result;
    int result = 0;

    if (peer == NULL) {
        ERR_clear_error();
        return 1;
    }
    context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    if (context == NULL || EVP_PKEY_derive_init(context) <= 0
            || EVP_PKEY_derive_set_peer(context, peer) <= 0
            || EVP_PKEY_derive(context, NULL, &queried) <= 0
            || queried != X301_BYTES)
        goto done;
    memset(output, 0xa5, sizeof(output));
    ERR_clear_error();
    derive_result = EVP_PKEY_derive(
        context, output, &output_length);
    if (derive_result > 0) {
        result = output_length == X301_BYTES
            && !buffer_is(output, X301_BYTES, 0)
            && buffer_is(output + X301_BYTES, 16U, 0xa5);
    } else {
        result = buffer_is(output, sizeof(output), 0xa5);
    }

done:
    ERR_clear_error();
    OPENSSL_cleanse(output, sizeof(output));
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    return result;
}

static int structured_raw_and_derive_sweep(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    unsigned long *case_count)
{
    unsigned char private_input[2U * X301_BYTES + 1U];
    unsigned char public_input[2U * X301_BYTES + 1U];
    unsigned char deleted[X301_BYTES - 1U];
    unsigned char inserted[X301_BYTES + 1U];
    unsigned char recovered_private[X301_BYTES];
    size_t index;
    size_t value;
    size_t length;
    unsigned long cases = 0;

    memset(private_input, 0x3c, sizeof(private_input));
    memset(public_input, 0xc3, sizeof(public_input));
    memcpy(private_input, SECRET_A, X301_BYTES);
    memcpy(public_input, PUBLIC_B, X301_BYTES);

    for (length = 0; length <= 2U * X301_BYTES; length++) {
        EVP_PKEY *private_candidate = raw_private(
            libctx, private_input, length);
        EVP_PKEY *public_candidate = raw_public(
            libctx, public_input, length);

        if ((length == X301_BYTES) != (private_candidate != NULL)
                || (length == X301_BYTES) != (public_candidate != NULL)) {
            EVP_PKEY_free(public_candidate);
            EVP_PKEY_free(private_candidate);
            return 0;
        }
        EVP_PKEY_free(public_candidate);
        EVP_PKEY_free(private_candidate);
        ERR_clear_error();
        cases += 2U;
    }

    for (index = 0; index < X301_BYTES; index++) {
        EVP_PKEY *candidate;

        memcpy(deleted, SECRET_A, index);
        memcpy(deleted + index, SECRET_A + index + 1U,
            X301_BYTES - index - 1U);
        memcpy(inserted, SECRET_A, index);
        inserted[index] = 0xa5;
        memcpy(inserted + index + 1U, SECRET_A + index,
            X301_BYTES - index);
        candidate = raw_private(libctx, deleted, sizeof(deleted));
        if (candidate != NULL) {
            EVP_PKEY_free(candidate);
            return 0;
        }
        ERR_clear_error();
        candidate = raw_private(libctx, inserted, sizeof(inserted));
        if (candidate != NULL) {
            EVP_PKEY_free(candidate);
            return 0;
        }
        ERR_clear_error();

        memcpy(deleted, PUBLIC_B, index);
        memcpy(deleted + index, PUBLIC_B + index + 1U,
            X301_BYTES - index - 1U);
        memcpy(inserted, PUBLIC_B, index);
        inserted[index] = 0xa5;
        memcpy(inserted + index + 1U, PUBLIC_B + index,
            X301_BYTES - index);
        candidate = raw_public(libctx, deleted, sizeof(deleted));
        if (candidate != NULL) {
            EVP_PKEY_free(candidate);
            return 0;
        }
        ERR_clear_error();
        candidate = raw_public(libctx, inserted, sizeof(inserted));
        if (candidate != NULL) {
            EVP_PKEY_free(candidate);
            return 0;
        }
        ERR_clear_error();
        cases += 4U;
    }

    for (index = 0; index < X301_BYTES; index++) {
        for (value = 0; value <= UCHAR_MAX; value++) {
            EVP_PKEY *candidate;
            size_t recovered_length = sizeof(recovered_private);

            memcpy(private_input, SECRET_A, X301_BYTES);
            private_input[index] = (unsigned char)value;
            candidate = raw_private(libctx, private_input, X301_BYTES);
            if (candidate == NULL
                    || EVP_PKEY_get_raw_private_key(
                        candidate, recovered_private,
                        &recovered_length) <= 0
                    || recovered_length != X301_BYTES
                    || CRYPTO_memcmp(
                        recovered_private, private_input,
                        X301_BYTES) != 0) {
                EVP_PKEY_free(candidate);
                return 0;
            }
            EVP_PKEY_free(candidate);
            cases++;

            memcpy(public_input, PUBLIC_B, X301_BYTES);
            public_input[index] = (unsigned char)value;
            if (!swept_peer_is_atomic(
                    libctx, private_key, public_input))
                return 0;
            cases++;
        }
    }
    OPENSSL_cleanse(private_input, sizeof(private_input));
    OPENSSL_cleanse(recovered_private, sizeof(recovered_private));
    *case_count = cases;
    return 1;
}

static EVP_PKEY *keygen(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        libctx, X301_NAME, X301_PROPERTIES);
    EVP_PKEY *key = NULL;

    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0
            || EVP_PKEY_generate(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static void clear_x301_failpoints(void)
{
    unsetenv("X301_PROVIDER_ALLOC_FAILPOINT");
    unsetenv("X301_PROVIDER_PANIC_FAILPOINT");
}

static int allocation_failure_is_reported(void)
{
    unsigned long error;
    int found = 0;

    while ((error = ERR_get_error()) != 0) {
        const char *reason = ERR_reason_error_string(error);

        if (ERR_GET_REASON(error) == 4 && reason != NULL
                && strcmp(reason, "X301 allocation failure") == 0)
            found = 1;
    }
    return found;
}

static int allocation_failpoints_are_atomic(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *peer)
{
    EVP_PKEY *temporary_key = NULL;
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY_CTX *duplicate = NULL;
    unsigned char output[X301_BYTES];
    int result = 0;

    if (setenv("X301_PROVIDER_ALLOC_FAILPOINT", "key_new", 1) != 0)
        goto done;
    temporary_key = raw_private(libctx, SECRET_A, sizeof(SECRET_A));
    if (temporary_key != NULL)
        goto done;
    clear_x301_failpoints();
    ERR_clear_error();
    temporary_key = raw_private(libctx, SECRET_A, sizeof(SECRET_A));
    if (temporary_key == NULL)
        goto done;
    EVP_PKEY_free(temporary_key);
    temporary_key = NULL;

    if (setenv("X301_PROVIDER_ALLOC_FAILPOINT", "key_generate", 1) != 0)
        goto done;
    temporary_key = keygen(libctx);
    if (temporary_key != NULL)
        goto done;
    clear_x301_failpoints();
    ERR_clear_error();
    temporary_key = keygen(libctx);
    if (temporary_key == NULL)
        goto done;
    EVP_PKEY_free(temporary_key);
    temporary_key = NULL;

    if (setenv("X301_PROVIDER_ALLOC_FAILPOINT", "key_duplicate", 1) != 0)
        goto done;
    ERR_clear_error();
    temporary_key = EVP_PKEY_dup(private_key);
    if (temporary_key != NULL || !allocation_failure_is_reported())
        goto done;
    clear_x301_failpoints();
    ERR_clear_error();
    temporary_key = EVP_PKEY_dup(private_key);
    if (temporary_key == NULL)
        goto done;
    EVP_PKEY_free(temporary_key);
    temporary_key = NULL;

    if (setenv("X301_PROVIDER_ALLOC_FAILPOINT", "exchange_new", 1) != 0)
        goto done;
    context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    if (context != NULL && EVP_PKEY_derive_init(context) > 0)
        goto done;
    EVP_PKEY_CTX_free(context);
    context = NULL;
    clear_x301_failpoints();
    ERR_clear_error();
    if (!derive_exact(libctx, private_key, peer, output))
        goto done;

    context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    if (context == NULL || EVP_PKEY_derive_init(context) <= 0
            || EVP_PKEY_derive_set_peer(context, peer) <= 0
            || setenv("X301_PROVIDER_ALLOC_FAILPOINT",
                "exchange_duplicate", 1) != 0)
        goto done;
    ERR_clear_error();
    duplicate = EVP_PKEY_CTX_dup(context);
    if (duplicate != NULL || !allocation_failure_is_reported())
        goto done;
    clear_x301_failpoints();
    ERR_clear_error();
    duplicate = EVP_PKEY_CTX_dup(context);
    if (duplicate == NULL || !derive_initialized(duplicate, output)
            || memcmp(output, SHARED_AB, sizeof(output)) != 0)
        goto done;
    result = 1;

done:
    clear_x301_failpoints();
    ERR_clear_error();
    OPENSSL_cleanse(output, sizeof(output));
    EVP_PKEY_CTX_free(duplicate);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(temporary_key);
    return result;
}

static int one_panic_failpoint_fails_closed(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *peer,
    const char *site)
{
    EVP_PKEY *temporary_key = NULL;
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY_CTX *duplicate = NULL;
    unsigned char output[X301_BYTES];
    size_t output_length = sizeof(output);
    int failed = 0;

    clear_x301_failpoints();
    if (strcmp(site, "key_new") == 0
            || strcmp(site, "key_import") == 0) {
        if (setenv("X301_PROVIDER_PANIC_FAILPOINT", site, 1) != 0)
            goto done;
        temporary_key = raw_private(libctx, SECRET_A, sizeof(SECRET_A));
        failed = temporary_key == NULL;
    } else if (strcmp(site, "key_set_encoded_public") == 0) {
        if (setenv("X301_PROVIDER_PANIC_FAILPOINT", site, 1) != 0)
            goto done;
        failed = EVP_PKEY_set1_encoded_public_key(
            peer, PUBLIC_B, sizeof(PUBLIC_B)) <= 0;
    } else if (strcmp(site, "key_generate") == 0) {
        if (setenv("X301_PROVIDER_PANIC_FAILPOINT", site, 1) != 0)
            goto done;
        temporary_key = keygen(libctx);
        failed = temporary_key == NULL;
    } else if (strcmp(site, "key_duplicate") == 0) {
        if (setenv("X301_PROVIDER_PANIC_FAILPOINT", site, 1) != 0)
            goto done;
        temporary_key = EVP_PKEY_dup(private_key);
        failed = temporary_key == NULL;
    } else if (strcmp(site, "key_validate") == 0) {
        context = EVP_PKEY_CTX_new_from_pkey(
            libctx, private_key, X301_PROPERTIES);
        if (context == NULL
                || setenv("X301_PROVIDER_PANIC_FAILPOINT", site, 1) != 0)
            goto done;
        failed = EVP_PKEY_check(context) <= 0;
    } else if (strcmp(site, "exchange_new") == 0) {
        if (setenv("X301_PROVIDER_PANIC_FAILPOINT", site, 1) != 0)
            goto done;
        context = EVP_PKEY_CTX_new_from_pkey(
            libctx, private_key, X301_PROPERTIES);
        failed = context == NULL || EVP_PKEY_derive_init(context) <= 0;
    } else {
        context = EVP_PKEY_CTX_new_from_pkey(
            libctx, private_key, X301_PROPERTIES);
        if (context == NULL)
            goto done;
        if (strcmp(site, "exchange_init") == 0) {
            if (setenv("X301_PROVIDER_PANIC_FAILPOINT", site, 1) != 0)
                goto done;
            failed = EVP_PKEY_derive_init(context) <= 0;
        } else if (EVP_PKEY_derive_init(context) <= 0) {
            goto done;
        } else if (strcmp(site, "exchange_set_peer") == 0) {
            if (setenv("X301_PROVIDER_PANIC_FAILPOINT", site, 1) != 0)
                goto done;
            failed = EVP_PKEY_derive_set_peer(context, peer) <= 0;
        } else if (EVP_PKEY_derive_set_peer(context, peer) <= 0) {
            goto done;
        } else if (strcmp(site, "exchange_duplicate") == 0) {
            if (setenv("X301_PROVIDER_PANIC_FAILPOINT", site, 1) != 0)
                goto done;
            duplicate = EVP_PKEY_CTX_dup(context);
            failed = duplicate == NULL;
        } else if (strcmp(site, "exchange_derive") == 0) {
            memset(output, 0xa5, sizeof(output));
            if (setenv("X301_PROVIDER_PANIC_FAILPOINT", site, 1) != 0)
                goto done;
            failed = EVP_PKEY_derive(
                    context, output, &output_length) <= 0
                && buffer_is(output, sizeof(output), 0xa5);
        }
    }

done:
    clear_x301_failpoints();
    ERR_clear_error();
    OPENSSL_cleanse(output, sizeof(output));
    EVP_PKEY_CTX_free(duplicate);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(temporary_key);
    return failed;
}

static int panic_failpoints_are_atomic(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    EVP_PKEY *peer)
{
    static const char *const sites[] = {
        "key_new",
        "key_import",
        "key_set_encoded_public",
        "key_generate",
        "key_duplicate",
        "key_validate",
        "exchange_new",
        "exchange_duplicate",
        "exchange_init",
        "exchange_set_peer",
        "exchange_derive"
    };
    unsigned char output[X301_BYTES];
    size_t index;

    for (index = 0; index < sizeof(sites) / sizeof(sites[0]); index++) {
        if (!one_panic_failpoint_fails_closed(
                libctx, private_key, peer, sites[index])) {
            fprintf(stderr, "panic failpoint did not fail closed: %s\n",
                sites[index]);
            return 0;
        }
        if (!derive_exact(libctx, private_key, peer, output)
                || memcmp(output, SHARED_AB, sizeof(output)) != 0)
            return 0;
    }
    OPENSSL_cleanse(output, sizeof(output));
    return 1;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *rand_provider = NULL;
    OSSL_PROVIDER *x301_provider = NULL;
    EVP_KEYMGMT *keymgmt = NULL;
    EVP_KEYEXCH *keyexch = NULL;
    EVP_PKEY *private_a = NULL;
    EVP_PKEY *private_b = NULL;
    EVP_PKEY *public_a = NULL;
    EVP_PKEY *public_b = NULL;
    EVP_PKEY *generated = NULL;
    unsigned char first[X301_BYTES];
    unsigned char second[X301_BYTES];
    const char *failpoint_mode = getenv("X301_PROVIDER_FAILPOINT_MODE");
    const int structured_sweep =
        getenv("X301_STRUCTURED_SWEEP") != NULL;
    unsigned long sweep_cases = 0;
    unsigned int calls_before;
    int success = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s PROVIDER_MODULE_DIRECTORY\n", argv[0]);
        return 2;
    }
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) <= 0
            || OSSL_PROVIDER_add_builtin(
                libctx, TEST_RAND_PROVIDER, test_rand_provider_init) != 1
            || (rand_provider = OSSL_PROVIDER_load(
                    libctx, TEST_RAND_PROVIDER)) == NULL
            || EVP_set_default_properties(libctx, TEST_RAND_PROPERTY) != 1
            || (x301_provider = OSSL_PROVIDER_load(
                    libctx, X301_PROVIDER)) == NULL) {
        fail("load isolated RAND and X301 providers");
        goto done;
    }
    pass("load isolated RAND and X301 providers");

    keymgmt = EVP_KEYMGMT_fetch(libctx, X301_NAME, X301_PROPERTIES);
    keyexch = EVP_KEYEXCH_fetch(libctx, X301_NAME, X301_PROPERTIES);
    if (keymgmt == NULL || keyexch == NULL) {
        fail("fetch X301 KEYMGMT and KEYEXCH");
        goto done;
    }
    pass("fetch X301 KEYMGMT and KEYEXCH");

    private_a = raw_private(libctx, SECRET_A, sizeof(SECRET_A));
    private_b = raw_private(libctx, SECRET_B, sizeof(SECRET_B));
    public_a = raw_public(libctx, PUBLIC_A, sizeof(PUBLIC_A));
    public_b = raw_public(libctx, PUBLIC_B, sizeof(PUBLIC_B));
    if (private_a == NULL || private_b == NULL
            || public_a == NULL || public_b == NULL
            || !raw_roundtrip(private_a, public_a, SECRET_A, PUBLIC_A)
            || !raw_roundtrip(private_b, public_b, SECRET_B, PUBLIC_B)) {
        fail("T6 raw private/public roundtrips and 38-byte size queries");
        goto done;
    }
    pass("T6 raw private/public roundtrips and 38-byte size queries");

    if (failpoint_mode != NULL && strcmp(failpoint_mode, "active") == 0) {
        if (!allocation_failpoints_are_atomic(
                libctx, private_a, public_b)) {
            fail("M6 Rust allocation failpoints fail closed and recover");
            goto done;
        }
        pass("M6 Rust allocation failpoints fail closed and recover");
        if (!panic_failpoints_are_atomic(libctx, private_a, public_b)) {
            fail("M6 all Rust FFI panic boundaries fail closed and recover");
            goto done;
        }
        pass("M6 all Rust FFI panic boundaries fail closed and recover");
    } else if (failpoint_mode != NULL
            && strcmp(failpoint_mode, "inert") == 0) {
        if (setenv("X301_PROVIDER_ALLOC_FAILPOINT",
                "exchange_derive", 1) != 0
                || setenv("X301_PROVIDER_PANIC_FAILPOINT",
                    "exchange_derive", 1) != 0
                || !derive_exact(libctx, private_a, public_b, first)
                || memcmp(first, SHARED_AB, sizeof(first)) != 0) {
            clear_x301_failpoints();
            fail("M6 ordinary module keeps test failpoint hooks compiled out");
            goto done;
        }
        clear_x301_failpoints();
        pass("M6 ordinary module keeps test failpoint hooks compiled out");
    }

    if (!invalid_lengths_rejected(libctx)) {
        fail("T6 raw private/public lengths 0, 37 and 39 are rejected");
        goto done;
    }
    pass("T6 raw private/public lengths 0, 37 and 39 are rejected");

    if (EVP_PKEY_eq(private_a, public_a) != 1
            || EVP_PKEY_eq(private_a, private_b) != 0) {
        fail("T6 KEYMGMT match identifies equal and unequal keys");
        goto done;
    }
    pass("T6 KEYMGMT match identifies equal and unequal keys");

    calls_before = rand_generate_calls;
    generated = keygen(libctx);
    if (generated == NULL
            || rand_generate_calls != calls_before + 1U
            || !raw_roundtrip(generated, generated,
                TEST_RAND_SEED, TEST_RAND_PUBLIC)) {
        fail("T7 deterministic application RAND fixes seed and public key");
        goto done;
    }
    pass("T7 deterministic application RAND fixes seed and public key");
    EVP_PKEY_free(generated);
    generated = NULL;

    rand_poisoned = 1;
    calls_before = rand_generate_calls;
    if (!derive_exact(libctx, private_a, public_b, first)
            || !derive_exact(libctx, private_a, public_b, second)
            || memcmp(first, SHARED_AB, sizeof(first)) != 0
            || memcmp(second, SHARED_AB, sizeof(second)) != 0
            || memcmp(first, second, sizeof(first)) != 0
            || rand_generate_calls != calls_before) {
        fail("T6/T7 exact deterministic derive succeeds without RAND");
        goto done;
    }
    pass("T6/T7 exact deterministic derive succeeds without RAND");

    if (!derive_exact(libctx, private_b, public_a, second)
            || memcmp(second, SHARED_AB, sizeof(second)) != 0) {
        fail("T6 EVP derive is symmetric for the independent A/B KAT");
        goto done;
    }
    pass("T6 EVP derive is symmetric for the independent A/B KAT");

    if (!all_small_order_peers_rejected(libctx, private_a, private_b)) {
        fail("T4 u=0, u=1 and u=p-1 reject atomically in both KAT directions");
        goto done;
    }
    pass("T4 u=0, u=1 and u=p-1 reject atomically in both KAT directions");

    if (!no_peer_and_short_output_are_atomic(libctx, private_a, public_b)) {
        fail("T6 missing peer and 37-byte output fail without partial write");
        goto done;
    }
    pass("T6 missing peer and 37-byte output fail without partial write");

    if (!peer_replacement_and_repeated_derive(
            libctx, private_a, public_a, public_b)) {
        fail("M1/M2 second peer wins and repeated derive is stable");
        goto done;
    }
    pass("M1/M2 second peer wins and repeated derive is stable");

    if (!duplicated_context_is_independent(libctx, private_a, public_b)) {
        fail("M3 dupctx preserves independent derive state");
        goto done;
    }
    pass("M3 dupctx preserves independent derive state");

    if (!reinitialization_clears_peer(
            libctx, private_a, private_b, public_a, public_b)) {
        fail("M4 reinit and local-key replacement never retain an old peer");
        goto done;
    }
    pass("M4 reinit and local-key replacement never retain an old peer");

    if (!parallel_derives_share_keys_safely(libctx, private_a, public_b)) {
        fail("M5 four threads derive 1000 times from shared immutable keys");
        goto done;
    }
    pass("M5 four threads derive 1000 times from shared immutable keys");

    if (!adversarial_corpus_matches(libctx)) {
        fail("W1-W6 and 512 oracle cases pass through EVP KEYMGMT/KEYEXCH");
        goto done;
    }
    pass("W1-W6 and 512 oracle cases pass through EVP KEYMGMT/KEYEXCH");

    if (structured_sweep) {
        if (!structured_raw_and_derive_sweep(
                libctx, private_a, &sweep_cases)) {
            fail("F1-F3 raw import/u-decode/derive structured sweep");
            goto done;
        }
        {
            char label[192];

            snprintf(label, sizeof(label),
                "F1-F3 raw import/u-decode/derive structured sweep "
                "(%lu cases)", sweep_cases);
            pass(label);
        }
    }

    calls_before = rand_generate_calls;
    generated = keygen(libctx);
    if (generated != NULL || rand_generate_calls != calls_before + 1U) {
        fail("T7 poisoned application RAND makes keygen fail closed");
        goto done;
    }
    ERR_clear_error();
    pass("T7 poisoned application RAND makes keygen fail closed");

    success = 1;
    printf("provider_x301_contract_pass=1 checks=%u\n", checks);

done:
    clear_x301_failpoints();
    OPENSSL_cleanse(first, sizeof(first));
    OPENSSL_cleanse(second, sizeof(second));
    EVP_PKEY_free(generated);
    EVP_PKEY_free(public_b);
    EVP_PKEY_free(public_a);
    EVP_PKEY_free(private_b);
    EVP_PKEY_free(private_a);
    EVP_KEYEXCH_free(keyexch);
    EVP_KEYMGMT_free(keymgmt);
    OSSL_PROVIDER_unload(x301_provider);
    OSSL_PROVIDER_unload(rand_provider);
    OSSL_LIB_CTX_free(libctx);
    return success ? 0 : 1;
}
