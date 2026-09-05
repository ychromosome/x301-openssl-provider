/*
 * Coverage-guided EVP fuzz target for X301 and X301MLKEM1024.
 *
 * This test uses public OpenSSL APIs only. It exercises arbitrary-length and
 * exact-length mutations at the Rust/C provider boundary; it does not define
 * a persistent hybrid format or a new combiner.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define X301_PROVIDER "x301"
#define X301_PROPERTIES "provider=x301"
#define X301_NAME "X301"
#define HYBRID_NAME "X301MLKEM1024"
#define X301_BYTES 38U
#define HYBRID_PUBLIC_BYTES 1606U
#define HYBRID_CIPHERTEXT_BYTES 1606U
#define HYBRID_SECRET_BYTES 70U
#define MAX_FUZZ_INPUT 4096U
#define CANARY 0xa5U

static OSSL_LIB_CTX *fuzz_libctx;
static OSSL_PROVIDER *fuzz_default_provider;
static OSSL_PROVIDER *fuzz_x301_provider;
static EVP_PKEY *fuzz_hybrid_private;
static EVP_PKEY *fuzz_x301_private;
static unsigned char fuzz_hybrid_public[HYBRID_PUBLIC_BYTES];
static unsigned char fuzz_hybrid_ciphertext[HYBRID_CIPHERTEXT_BYTES];
static unsigned char fuzz_x301_public[X301_BYTES];
static const unsigned char empty_input[1] = { 0 };
static const unsigned char field_modulus[X301_BYTES] = {
    0xb3, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x1f
};

static void invariant_failed(void)
{
    __builtin_trap();
}

static int buffer_is(
    const unsigned char *buffer,
    size_t length,
    unsigned char value)
{
    size_t index;

    for (index = 0; index < length; index++) {
        if (buffer[index] != value)
            return 0;
    }
    return 1;
}

static void mutate_exact(
    unsigned char *output,
    const unsigned char *baseline,
    size_t output_length,
    const unsigned char *mutation,
    size_t mutation_length)
{
    size_t index;
    size_t position;

    memcpy(output, baseline, output_length);
    for (index = 0; index < mutation_length; index++) {
        position = (index * 131U + mutation[index]) % output_length;
        output[position] ^= (unsigned char)(mutation[index] ^ index ^ 0x5bU);
    }
}

static void canonicalize_public(
    const unsigned char input[X301_BYTES],
    unsigned char output[X301_BYTES])
{
    size_t index;
    unsigned int borrow = 0;
    int at_least_modulus = 1;

    memcpy(output, input, X301_BYTES);
    output[X301_BYTES - 1U] &= 0x1fU;
    for (index = X301_BYTES; index > 0; index--) {
        if (output[index - 1U] == field_modulus[index - 1U])
            continue;
        at_least_modulus = output[index - 1U] > field_modulus[index - 1U];
        break;
    }
    if (!at_least_modulus)
        return;
    for (index = 0; index < X301_BYTES; index++) {
        unsigned int subtrahend = field_modulus[index] + borrow;
        unsigned int value = output[index];

        output[index] = (unsigned char)(value - subtrahend);
        borrow = value < subtrahend;
    }
}

static EVP_PKEY *new_empty_hybrid(void)
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;

    context = EVP_PKEY_CTX_new_from_name(
        fuzz_libctx, HYBRID_NAME, X301_PROPERTIES);
    if (context == NULL || EVP_PKEY_paramgen_init(context) <= 0
            || EVP_PKEY_generate(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static EVP_PKEY *generate_key(const char *algorithm)
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;

    context = EVP_PKEY_CTX_new_from_name(
        fuzz_libctx, algorithm, X301_PROPERTIES);
    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0
            || EVP_PKEY_CTX_set_group_name(context, algorithm) <= 0
            || EVP_PKEY_generate(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static void fuzz_hybrid_public_key(
    const unsigned char *data,
    size_t size,
    int exact_length)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY *duplicate = NULL;
    EVP_PKEY_CTX *check_context = NULL;
    unsigned char exact[HYBRID_PUBLIC_BYTES];
    unsigned char expected[HYBRID_PUBLIC_BYTES];
    unsigned char *exported = NULL;
    const unsigned char *encoded = size == 0 ? empty_input : data;
    size_t encoded_length = size;
    size_t exported_length;

    if (exact_length) {
        mutate_exact(exact, fuzz_hybrid_public, sizeof(exact), data, size);
        encoded = exact;
        encoded_length = sizeof(exact);
    }
    key = new_empty_hybrid();
    if (key == NULL
            || EVP_PKEY_set1_encoded_public_key(
                key, encoded, encoded_length) <= 0)
        goto done;

    exported_length = EVP_PKEY_get1_encoded_public_key(key, &exported);
    if (exported_length != HYBRID_PUBLIC_BYTES || exported == NULL)
        invariant_failed();
    if (encoded_length == HYBRID_PUBLIC_BYTES) {
        memcpy(expected, encoded, sizeof(expected));
        canonicalize_public(
            encoded + HYBRID_PUBLIC_BYTES - X301_BYTES,
            expected + HYBRID_PUBLIC_BYTES - X301_BYTES);
        if (CRYPTO_memcmp(exported, expected, sizeof(expected)) != 0)
            invariant_failed();
    }
    duplicate = EVP_PKEY_dup(key);
    check_context = EVP_PKEY_CTX_new_from_pkey(
        fuzz_libctx, key, X301_PROPERTIES);
    if (check_context != NULL)
        (void)EVP_PKEY_public_check(check_context);

done:
    EVP_PKEY_CTX_free(check_context);
    EVP_PKEY_free(duplicate);
    OPENSSL_free(exported);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(exact, sizeof(exact));
}

static void check_secret_output(
    int result,
    const unsigned char *output,
    size_t output_size,
    size_t capacity,
    size_t output_length,
    size_t expected_length)
{
    if (result > 0) {
        if (capacity < expected_length || output_length != expected_length
                || !buffer_is(output + expected_length,
                    output_size - expected_length, CANARY))
            invariant_failed();
    } else if (!buffer_is(output, output_size, CANARY)) {
        invariant_failed();
    }
}

static void fuzz_hybrid_decapsulation(
    const unsigned char *data,
    size_t size,
    int exact_length)
{
    EVP_PKEY_CTX *context = NULL;
    unsigned char exact[HYBRID_CIPHERTEXT_BYTES];
    unsigned char output[HYBRID_SECRET_BYTES + 16U];
    const unsigned char *ciphertext = size == 0 ? empty_input : data;
    size_t ciphertext_length = size;
    size_t output_length;
    size_t capacity;
    unsigned int control = size == 0 ? 0U : data[0];
    int result;

    if (exact_length) {
        mutate_exact(
            exact, fuzz_hybrid_ciphertext, sizeof(exact), data, size);
        ciphertext = exact;
        ciphertext_length = sizeof(exact);
    }
    capacity = control % 3U == 0U
        ? HYBRID_SECRET_BYTES - 1U
        : (control % 3U == 1U
            ? HYBRID_SECRET_BYTES : sizeof(output));
    context = EVP_PKEY_CTX_new_from_pkey(
        fuzz_libctx, fuzz_hybrid_private, X301_PROPERTIES);
    if (context == NULL || EVP_PKEY_decapsulate_init(context, NULL) <= 0)
        goto done;
    memset(output, CANARY, sizeof(output));
    output_length = capacity;
    result = EVP_PKEY_decapsulate(
        context, output, &output_length, ciphertext, ciphertext_length);
    check_secret_output(
        result, output, sizeof(output), capacity, output_length,
        HYBRID_SECRET_BYTES);

done:
    EVP_PKEY_CTX_free(context);
    OPENSSL_cleanse(output, sizeof(output));
    OPENSSL_cleanse(exact, sizeof(exact));
}

static void fuzz_x301_derive(
    const unsigned char *data,
    size_t size,
    int exact_length)
{
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *context = NULL;
    unsigned char exact[X301_BYTES];
    unsigned char expected[X301_BYTES];
    unsigned char exported[X301_BYTES];
    unsigned char output[X301_BYTES + 16U];
    const unsigned char *encoded = size == 0 ? empty_input : data;
    size_t encoded_length = size;
    size_t output_length;
    size_t exported_length = sizeof(exported);
    size_t capacity;
    unsigned int control = size == 0 ? 0U : data[0];
    int result;

    if (exact_length) {
        mutate_exact(exact, fuzz_x301_public, sizeof(exact), data, size);
        encoded = exact;
        encoded_length = sizeof(exact);
    }
    peer = EVP_PKEY_new_raw_public_key_ex(
        fuzz_libctx, X301_NAME, X301_PROPERTIES, encoded, encoded_length);
    if (peer == NULL)
        goto done;
    if (encoded_length == X301_BYTES) {
        canonicalize_public(encoded, expected);
        if (EVP_PKEY_get_raw_public_key(peer, exported, &exported_length) <= 0
                || exported_length != sizeof(exported)
                || CRYPTO_memcmp(exported, expected, sizeof(expected)) != 0)
            invariant_failed();
    }
    context = EVP_PKEY_CTX_new_from_pkey(
        fuzz_libctx, fuzz_x301_private, X301_PROPERTIES);
    if (context == NULL || EVP_PKEY_derive_init(context) <= 0
            || EVP_PKEY_derive_set_peer(context, peer) <= 0)
        goto done;
    capacity = (control & 1U) == 0U ? X301_BYTES - 1U : sizeof(output);
    memset(output, CANARY, sizeof(output));
    output_length = capacity;
    result = EVP_PKEY_derive(context, output, &output_length);
    check_secret_output(
        result, output, sizeof(output), capacity, output_length, X301_BYTES);

done:
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    OPENSSL_cleanse(output, sizeof(output));
    OPENSSL_cleanse(exported, sizeof(exported));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(exact, sizeof(exact));
}

static void fuzz_context_duplication(const unsigned char *data, size_t size)
{
    EVP_PKEY_CTX *first = NULL;
    EVP_PKEY_CTX *second = NULL;
    unsigned char output[HYBRID_SECRET_BYTES];
    size_t output_length = sizeof(output);
    unsigned int control = size == 0 ? 0U : data[0];

    first = EVP_PKEY_CTX_new_from_pkey(
        fuzz_libctx, fuzz_hybrid_private, X301_PROPERTIES);
    if (first == NULL || EVP_PKEY_decapsulate_init(first, NULL) <= 0)
        goto done;
    second = EVP_PKEY_CTX_dup(first);
    if (second == NULL)
        goto done;
    if ((control & 1U) != 0U) {
        EVP_PKEY_CTX_free(first);
        first = second;
        second = NULL;
    }
    (void)EVP_PKEY_decapsulate(
        first, output, &output_length,
        fuzz_hybrid_ciphertext, sizeof(fuzz_hybrid_ciphertext));

done:
    EVP_PKEY_CTX_free(second);
    EVP_PKEY_CTX_free(first);
    OPENSSL_cleanse(output, sizeof(output));
}

static void fuzz_cleanup(void)
{
    EVP_PKEY_free(fuzz_x301_private);
    EVP_PKEY_free(fuzz_hybrid_private);
    OSSL_PROVIDER_unload(fuzz_x301_provider);
    OSSL_PROVIDER_unload(fuzz_default_provider);
    OSSL_LIB_CTX_free(fuzz_libctx);
    OPENSSL_cleanse(fuzz_x301_public, sizeof(fuzz_x301_public));
    OPENSSL_cleanse(fuzz_hybrid_ciphertext, sizeof(fuzz_hybrid_ciphertext));
    OPENSSL_cleanse(fuzz_hybrid_public, sizeof(fuzz_hybrid_public));
}

static void initialization_failed(const char *message)
{
    fprintf(stderr, "X301 provider fuzz initialization failed: %s\n", message);
    ERR_print_errors_fp(stderr);
    fuzz_cleanup();
    exit(1);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    EVP_PKEY_CTX *context = NULL;
    unsigned char *public_key = NULL;
    unsigned char secret[HYBRID_SECRET_BYTES];
    size_t public_length;
    size_t ciphertext_length = sizeof(fuzz_hybrid_ciphertext);
    size_t secret_length = sizeof(secret);
    size_t x301_public_length = sizeof(fuzz_x301_public);
    const char *module_directory = getenv("X301_FUZZ_MODULE_DIR");

    (void)argc;
    (void)argv;
    if (module_directory == NULL || module_directory[0] == '\0')
        initialization_failed("X301_FUZZ_MODULE_DIR is not set");
    fuzz_libctx = OSSL_LIB_CTX_new();
    if (fuzz_libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(
                fuzz_libctx, module_directory) <= 0)
        initialization_failed("cannot create library context");
    fuzz_default_provider = OSSL_PROVIDER_load(fuzz_libctx, "default");
    fuzz_x301_provider = OSSL_PROVIDER_load(fuzz_libctx, X301_PROVIDER);
    if (fuzz_default_provider == NULL || fuzz_x301_provider == NULL)
        initialization_failed("cannot load providers");

    fuzz_hybrid_private = generate_key(HYBRID_NAME);
    fuzz_x301_private = generate_key(X301_NAME);
    if (fuzz_hybrid_private == NULL || fuzz_x301_private == NULL
            || EVP_PKEY_get_raw_public_key(
                fuzz_x301_private, fuzz_x301_public,
                &x301_public_length) <= 0
            || x301_public_length != sizeof(fuzz_x301_public))
        initialization_failed("cannot generate baseline keys");
    public_length = EVP_PKEY_get1_encoded_public_key(
        fuzz_hybrid_private, &public_key);
    if (public_length != sizeof(fuzz_hybrid_public) || public_key == NULL)
        initialization_failed("cannot export hybrid public key");
    memcpy(fuzz_hybrid_public, public_key, sizeof(fuzz_hybrid_public));

    context = EVP_PKEY_CTX_new_from_pkey(
        fuzz_libctx, fuzz_hybrid_private, X301_PROPERTIES);
    if (context == NULL || EVP_PKEY_encapsulate_init(context, NULL) <= 0
            || EVP_PKEY_encapsulate(
                context, fuzz_hybrid_ciphertext, &ciphertext_length,
                secret, &secret_length) <= 0
            || ciphertext_length != sizeof(fuzz_hybrid_ciphertext)
            || secret_length != sizeof(secret))
        initialization_failed("cannot create baseline ciphertext");
    if (atexit(fuzz_cleanup) != 0)
        initialization_failed("cannot register cleanup");

    EVP_PKEY_CTX_free(context);
    OPENSSL_free(public_key);
    OPENSSL_cleanse(secret, sizeof(secret));
    ERR_clear_error();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const unsigned char *payload;
    size_t payload_size;
    unsigned int operation;

    if (size > MAX_FUZZ_INPUT)
        return 0;
    ERR_clear_error();
    operation = size == 0 ? 0U : data[0] % 7U;
    payload = size <= 1 ? empty_input : data + 1;
    payload_size = size <= 1 ? 0U : size - 1U;
    switch (operation) {
    case 0:
        fuzz_hybrid_public_key(payload, payload_size, 0);
        break;
    case 1:
        fuzz_hybrid_public_key(payload, payload_size, 1);
        break;
    case 2:
        fuzz_hybrid_decapsulation(payload, payload_size, 0);
        break;
    case 3:
        fuzz_hybrid_decapsulation(payload, payload_size, 1);
        break;
    case 4:
        fuzz_x301_derive(payload, payload_size, 0);
        break;
    case 5:
        fuzz_x301_derive(payload, payload_size, 1);
        break;
    default:
        fuzz_context_duplication(payload, payload_size);
        break;
    }
    ERR_clear_error();
    return 0;
}
