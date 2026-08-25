#define _POSIX_C_SOURCE 200809L

/* Exact-count EVP benchmark; orchestration and provenance live in the runner. */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <valgrind/callgrind.h>

#define MAX_KEY_BYTES 56U

static volatile unsigned char sink;

static int monotonic_ns(uint64_t *value)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0
            || now.tv_sec < 0 || now.tv_nsec < 0)
        return 0;
    *value = (uint64_t)now.tv_sec * UINT64_C(1000000000)
        + (uint64_t)now.tv_nsec;
    return 1;
}

static int parse_size(const char *text, size_t maximum, size_t *value)
{
    char *end = NULL;
    uintmax_t parsed;

    if (text == NULL || text[0] == '\0' || text[0] == '-'
            || text[0] == '+')
        return 0;
    errno = 0;
    parsed = strtoumax(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > maximum)
        return 0;
    *value = (size_t)parsed;
    return 1;
}

static EVP_PKEY *raw_key(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties, int selection, const char *parameter,
    unsigned char *bytes, size_t length)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        libctx, algorithm, properties);
    EVP_PKEY *key = NULL;
    OSSL_PARAM parameters[2] = {
        OSSL_PARAM_construct_octet_string(parameter, bytes, length),
        OSSL_PARAM_construct_end()
    };

    if (context == NULL || EVP_PKEY_fromdata_init(context) <= 0
            || EVP_PKEY_fromdata(context, &key, selection, parameters) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int operation_is(const char *operation, const char *name)
{
    return strcmp(operation, name) == 0;
}

int main(int argc, char **argv)
{
    const char *operation;
    const char *algorithm;
    const char *properties;
    const char *module_directory;
    size_t key_bytes;
    size_t count;
    size_t index;
    size_t public_length = 0;
    size_t output_length = 0;
    size_t ciphertext_length = 0;
    size_t shared_length = 0;
    uint64_t started;
    uint64_t finished;
    unsigned char private_a[MAX_KEY_BYTES];
    unsigned char private_b[MAX_KEY_BYTES];
    unsigned char public_b[MAX_KEY_BYTES];
    unsigned char output[MAX_KEY_BYTES];
    unsigned char *ciphertext = NULL;
    unsigned char *shared = NULL;
    unsigned char *received = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *x301_provider = NULL;
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY_CTX *derive = NULL;
    EVP_PKEY_CTX *encaps = NULL;
    EVP_PKEY_CTX *decaps = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY *generated = NULL;
    int status = EXIT_FAILURE;

    if (argc != 7 || !parse_size(argv[5], MAX_KEY_BYTES, &key_bytes)
            || !parse_size(argv[6], 100000000U, &count) || count == 0) {
        fprintf(stderr, "usage: %s <keygen|derive|kem-keygen|encaps|decaps> "
            "<algorithm> <properties|-> <module-dir|-> <key-bytes> <count>\n",
            argv[0]);
        return EXIT_FAILURE;
    }
    operation = argv[1];
    algorithm = argv[2];
    properties = strcmp(argv[3], "-") == 0 ? NULL : argv[3];
    module_directory = argv[4];
    if (!operation_is(operation, "keygen")
            && !operation_is(operation, "derive")
            && !operation_is(operation, "kem-keygen")
            && !operation_is(operation, "encaps")
            && !operation_is(operation, "decaps"))
        goto done;
    if (operation_is(operation, "derive") && key_bytes == 0)
        goto done;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || (strcmp(module_directory, "-") != 0
                && OSSL_PROVIDER_set_default_search_path(
                    libctx, module_directory) <= 0))
        goto done;
    default_provider = OSSL_PROVIDER_load(libctx, "default");
    if (default_provider == NULL)
        goto done;
    if (strcmp(module_directory, "-") != 0) {
        x301_provider = OSSL_PROVIDER_load(libctx, "x301");
        if (x301_provider == NULL)
            goto done;
    }

    if (operation_is(operation, "keygen")) {
        key = EVP_PKEY_Q_keygen(libctx, properties, algorithm);
        if (key == NULL)
            goto done;
        EVP_PKEY_free(key);
        key = NULL;
    } else if (operation_is(operation, "derive")) {
        for (index = 0; index < key_bytes; index++) {
            private_a[index] = (unsigned char)index;
            private_b[index] = (unsigned char)(key_bytes - 1U - index);
        }
        key = raw_key(libctx, algorithm, properties, EVP_PKEY_PRIVATE_KEY,
            OSSL_PKEY_PARAM_PRIV_KEY, private_a, key_bytes);
        generated = raw_key(libctx, algorithm, properties,
            EVP_PKEY_PRIVATE_KEY, OSSL_PKEY_PARAM_PRIV_KEY,
            private_b, key_bytes);
        public_length = sizeof(public_b);
        if (key == NULL || generated == NULL
                || EVP_PKEY_get_raw_public_key(
                    generated, public_b, &public_length) <= 0
                || public_length != key_bytes)
            goto done;
        peer = raw_key(libctx, algorithm, properties, EVP_PKEY_PUBLIC_KEY,
            OSSL_PKEY_PARAM_PUB_KEY, public_b, public_length);
        derive = EVP_PKEY_CTX_new_from_pkey(libctx, key, properties);
        output_length = sizeof(output);
        if (peer == NULL || derive == NULL
                || EVP_PKEY_derive_init(derive) <= 0
                || EVP_PKEY_derive_set_peer(derive, peer) <= 0
                || EVP_PKEY_derive(derive, NULL, &output_length) <= 0
                || output_length != key_bytes)
            goto done;
    } else {
        context = EVP_PKEY_CTX_new_from_name(libctx, algorithm, properties);
        if (context == NULL || EVP_PKEY_keygen_init(context) <= 0
                || EVP_PKEY_generate(context, &key) <= 0)
            goto done;
        encaps = EVP_PKEY_CTX_new_from_pkey(libctx, key, properties);
        if (encaps == NULL || EVP_PKEY_encapsulate_init(encaps, NULL) <= 0
                || EVP_PKEY_encapsulate(encaps, NULL, &ciphertext_length,
                    NULL, &shared_length) <= 0)
            goto done;
        ciphertext = OPENSSL_malloc(ciphertext_length);
        shared = OPENSSL_malloc(shared_length);
        received = OPENSSL_malloc(shared_length);
        if (ciphertext == NULL || shared == NULL || received == NULL
                || EVP_PKEY_encapsulate(encaps, ciphertext,
                    &ciphertext_length, shared, &shared_length) <= 0)
            goto done;
        decaps = EVP_PKEY_CTX_new_from_pkey(libctx, key, properties);
        output_length = shared_length;
        if (decaps == NULL || EVP_PKEY_decapsulate_init(decaps, NULL) <= 0
                || EVP_PKEY_decapsulate(decaps, received, &output_length,
                    ciphertext, ciphertext_length) <= 0
                || output_length != shared_length)
            goto done;
    }

    EVP_PKEY_free(generated);
    generated = NULL;
    CALLGRIND_ZERO_STATS;
    CALLGRIND_START_INSTRUMENTATION;
    if (!monotonic_ns(&started))
        goto done;
    for (index = 0; index < count; index++) {
        if (operation_is(operation, "keygen")) {
            generated = EVP_PKEY_Q_keygen(libctx, properties, algorithm);
            if (generated == NULL)
                goto done;
            sink ^= (unsigned char)(uintptr_t)generated;
            EVP_PKEY_free(generated);
            generated = NULL;
        } else if (operation_is(operation, "derive")) {
            output_length = key_bytes;
            if (EVP_PKEY_derive(derive, output, &output_length) <= 0
                    || output_length != key_bytes)
                goto done;
            sink ^= output[0];
        } else if (operation_is(operation, "kem-keygen")) {
            if (EVP_PKEY_generate(context, &generated) <= 0)
                goto done;
            sink ^= (unsigned char)(uintptr_t)generated;
            EVP_PKEY_free(generated);
            generated = NULL;
        } else if (operation_is(operation, "encaps")) {
            size_t current_ciphertext = ciphertext_length;
            size_t current_shared = shared_length;
            if (EVP_PKEY_encapsulate(encaps, ciphertext,
                    &current_ciphertext, shared, &current_shared) <= 0
                    || current_ciphertext != ciphertext_length
                    || current_shared != shared_length)
                goto done;
            sink ^= ciphertext[0] ^ shared[0];
        } else {
            output_length = shared_length;
            if (EVP_PKEY_decapsulate(decaps, received, &output_length,
                    ciphertext, ciphertext_length) <= 0
                    || output_length != shared_length)
                goto done;
            sink ^= received[0];
        }
    }
    if (!monotonic_ns(&finished) || finished < started)
        goto done;
    CALLGRIND_STOP_INSTRUMENTATION;
    printf("RESULT operation=%s algorithm=%s count=%zu total_ns=%" PRIu64
           " mean_ns=%.1f\n", operation, algorithm, count,
        finished - started, (double)(finished - started) / (double)count);
    status = EXIT_SUCCESS;

done:
    if (status != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_free(generated);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(decaps);
    EVP_PKEY_CTX_free(encaps);
    EVP_PKEY_CTX_free(derive);
    EVP_PKEY_CTX_free(context);
    OPENSSL_clear_free(received, shared_length);
    OPENSSL_clear_free(shared, shared_length);
    OPENSSL_free(ciphertext);
    OSSL_PROVIDER_unload(x301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return status;
}
