/*
 * Verify the property boundary of nested ML-KEM fetches in MLKEM1024X301.
 * The probe providers implement only test KEYMGMT key generation; no
 * cryptographic operation or wire format is defined here.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define HYBRID_NAME "MLKEM1024X301"
#define MLKEM_NAME "ML-KEM-1024"
#define X301_NAME "X301"
#define X301_BYTES 38U

typedef struct probe_state_st {
    const char *property;
    unsigned int generation_calls;
    int fail_generation;
} PROBE_STATE;

static PROBE_STATE probe_a = { "x301.probe=a", 0, 0 };
static PROBE_STATE probe_b = { "x301.probe=b", 0, 0 };
static PROBE_STATE probe_fail = { "x301.probe=fail", 0, 1 };
static unsigned int checks;
static unsigned int failures;

static void *probe_key_new(void *provider_context)
{
    (void)provider_context;
    return OPENSSL_zalloc(1);
}

static void probe_key_free(void *key_data)
{
    OPENSSL_free(key_data);
}

static int probe_key_has(const void *key_data, int selection)
{
    return key_data != NULL
        && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;
}

static void *probe_gen_init(void *provider_context, int selection,
    const OSSL_PARAM params[])
{
    PROBE_STATE *state = provider_context;

    (void)params;
    return state != NULL
            && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0
        ? state : NULL;
}

static void *probe_gen(void *generation_context,
    OSSL_CALLBACK *progress_callback, void *callback_argument)
{
    PROBE_STATE *state = generation_context;

    (void)progress_callback;
    (void)callback_argument;
    if (state == NULL)
        return NULL;
    state->generation_calls++;
    if (state->fail_generation)
        return NULL;
    return probe_key_new(state);
}

static void probe_gen_cleanup(void *generation_context)
{
    (void)generation_context;
}

static int probe_gen_set_params(void *generation_context,
    const OSSL_PARAM params[])
{
    (void)params;
    return generation_context != NULL;
}

static const OSSL_PARAM *probe_gen_settable_params(
    void *generation_context, void *provider_context)
{
    static const OSSL_PARAM none[] = { OSSL_PARAM_END };

    (void)generation_context;
    (void)provider_context;
    return none;
}

static const OSSL_DISPATCH probe_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))probe_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))probe_key_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))probe_key_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))probe_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))probe_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))probe_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        (void (*)(void))probe_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))probe_gen_settable_params },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM probe_a_algorithms[] = {
    { MLKEM_NAME, "provider=mlkem_a,x301.probe=a", probe_keymgmt_functions,
        "ML-KEM property-selection probe A" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM probe_b_algorithms[] = {
    { MLKEM_NAME, "provider=mlkem_b,x301.probe=b", probe_keymgmt_functions,
        "ML-KEM property-selection probe B" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM probe_fail_algorithms[] = {
    { MLKEM_NAME, "provider=mlkem_fail,x301.probe=fail",
        probe_keymgmt_functions,
        "failing ML-KEM property-selection probe" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *probe_query(void *provider_context,
    int operation_id, int *no_cache)
{
    PROBE_STATE *state = provider_context;

    if (no_cache != NULL)
        *no_cache = 0;
    if (operation_id != OSSL_OP_KEYMGMT || state == NULL)
        return NULL;
    if (state == &probe_a)
        return probe_a_algorithms;
    if (state == &probe_b)
        return probe_b_algorithms;
    return state == &probe_fail ? probe_fail_algorithms : NULL;
}

static const OSSL_DISPATCH probe_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))probe_query },
    OSSL_DISPATCH_END
};

static int probe_init(PROBE_STATE *state,
    const OSSL_DISPATCH **output_dispatch, void **provider_context)
{
    if (state == NULL || output_dispatch == NULL || provider_context == NULL)
        return 0;
    *provider_context = state;
    *output_dispatch = probe_provider_functions;
    return 1;
}

static int probe_a_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch, void **provider_context)
{
    (void)handle;
    (void)input_dispatch;
    return probe_init(&probe_a, output_dispatch, provider_context);
}

static int probe_b_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch, void **provider_context)
{
    (void)handle;
    (void)input_dispatch;
    return probe_init(&probe_b, output_dispatch, provider_context);
}

static int probe_fail_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *input_dispatch,
    const OSSL_DISPATCH **output_dispatch, void **provider_context)
{
    (void)handle;
    (void)input_dispatch;
    return probe_init(&probe_fail, output_dispatch, provider_context);
}

static EVP_PKEY *generate(OSSL_LIB_CTX *libctx, const char *name,
    const char *properties)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        libctx, name, properties);
    EVP_PKEY *key = NULL;

    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0
            || EVP_PKEY_generate(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int raw_import_works(OSSL_LIB_CTX *libctx)
{
    static const unsigned char secret[X301_BYTES] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25
    };
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(
        libctx, X301_NAME, "provider=x301", secret, sizeof(secret));
    unsigned char public_key[X301_BYTES];
    size_t public_length = sizeof(public_key);
    int result = key != NULL
        && EVP_PKEY_get_raw_public_key(key, public_key, &public_length) > 0
        && public_length == sizeof(public_key);

    EVP_PKEY_free(key);
    return result;
}

static void unload(OSSL_PROVIDER *x301, OSSL_PROVIDER *fail,
    OSSL_PROVIDER *b, OSSL_PROVIDER *a, OSSL_PROVIDER *deflt,
    OSSL_LIB_CTX *libctx)
{
    OSSL_PROVIDER_unload(x301);
    OSSL_PROVIDER_unload(fail);
    OSSL_PROVIDER_unload(b);
    OSSL_PROVIDER_unload(a);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
}

static int run_selection(const char *module_directory, PROBE_STATE *inner,
    PROBE_STATE *outer_preference)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL, *a = NULL, *b = NULL;
    OSSL_PROVIDER *x301 = NULL;
    EVP_PKEY *direct = NULL, *hybrid = NULL;
    char defaults[64], outer[64];
    int result = 0;

    inner->generation_calls = 0;
    outer_preference->generation_calls = 0;
    if (libctx == NULL
            || OSSL_PROVIDER_add_builtin(libctx, "mlkem_a", probe_a_init) <= 0
            || OSSL_PROVIDER_add_builtin(libctx, "mlkem_b", probe_b_init) <= 0
            || OSSL_PROVIDER_set_default_search_path(
                libctx, module_directory) <= 0)
        goto done;
    deflt = OSSL_PROVIDER_load(libctx, "default");
    a = OSSL_PROVIDER_load(libctx, "mlkem_a");
    b = OSSL_PROVIDER_load(libctx, "mlkem_b");
    snprintf(defaults, sizeof(defaults), "?%s", inner->property);
    snprintf(outer, sizeof(outer), "?%s", outer_preference->property);
    if (deflt == NULL || a == NULL || b == NULL
            || EVP_set_default_properties(libctx, defaults) <= 0)
        goto done;
    x301 = OSSL_PROVIDER_load(libctx, "x301");
    if (x301 == NULL)
        goto done;

    direct = generate(libctx, MLKEM_NAME, outer);
    if (direct == NULL || outer_preference->generation_calls != 1U
            || inner->generation_calls != 0U)
        goto done;
    EVP_PKEY_free(direct);
    direct = NULL;

    inner->generation_calls = 0;
    outer_preference->generation_calls = 0;
    hybrid = generate(libctx, HYBRID_NAME, outer);
    if (hybrid == NULL || inner->generation_calls != 1U
            || outer_preference->generation_calls != 0U)
        goto done;
    result = 1;

done:
    if (!result)
        fprintf(stderr, "nested selection failed: inner=%s outer=%s\n",
            inner->property, outer_preference->property);
    EVP_PKEY_free(hybrid);
    EVP_PKEY_free(direct);
    unload(x301, NULL, b, a, deflt, libctx);
    return result;
}

static int run_failure(const char *module_directory)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL, *fail = NULL;
    OSSL_PROVIDER *x301 = NULL;
    EVP_PKEY *hybrid = NULL;
    int result = 0;

    probe_fail.generation_calls = 0;
    if (libctx == NULL
            || OSSL_PROVIDER_add_builtin(
                libctx, "mlkem_fail", probe_fail_init) <= 0
            || OSSL_PROVIDER_set_default_search_path(
                libctx, module_directory) <= 0)
        goto done;
    deflt = OSSL_PROVIDER_load(libctx, "default");
    fail = OSSL_PROVIDER_load(libctx, "mlkem_fail");
    if (deflt == NULL || fail == NULL
            || EVP_set_default_properties(
                libctx, "?x301.probe=fail") <= 0)
        goto done;
    x301 = OSSL_PROVIDER_load(libctx, "x301");
    if (x301 == NULL)
        goto done;

    ERR_clear_error();
    hybrid = generate(libctx, HYBRID_NAME, "provider=x301");
    result = hybrid == NULL && probe_fail.generation_calls == 1U
        && raw_import_works(libctx);
    ERR_clear_error();

done:
    if (!result)
        fprintf(stderr, "nested failure was not atomic\n");
    EVP_PKEY_free(hybrid);
    unload(x301, fail, NULL, NULL, deflt, libctx);
    return result;
}

static int check(int result, const char *label)
{
    checks++;
    if (result) {
        printf("ok %u - %s\n", checks, label);
        return 1;
    }
    failures++;
    fprintf(stderr, "not ok %u - %s\n", checks, label);
    ERR_print_errors_fp(stderr);
    return 0;
}

int main(int argc, char **argv)
{
    int result = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s MODULE_DIRECTORY\n", argv[0]);
        return EXIT_FAILURE;
    }
    result &= check(run_selection(argv[1], &probe_a, &probe_b),
        "child default A overrides outer preference B for nested ML-KEM");
    result &= check(run_selection(argv[1], &probe_b, &probe_a),
        "child default B overrides outer preference A for nested ML-KEM");
    result &= check(run_failure(argv[1]),
        "nested ML-KEM failure is atomic while fixed raw X301 import works");
    printf("provider_x301_nested_properties: %u passed, %u failed\n",
        checks - failures, failures);
    return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
