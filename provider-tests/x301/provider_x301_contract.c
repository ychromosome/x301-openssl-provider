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
