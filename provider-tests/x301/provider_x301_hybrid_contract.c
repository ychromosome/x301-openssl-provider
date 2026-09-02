/*
 * Direct EVP contract tests for the TLS-only X301MLKEM1024 substrate (T9).
 *
 * Sources:
 *   - FIPS 203 through the ML-KEM-1024 implementation selected by the child
 *     library context;
 *   - RFC 10024 (ML-KEM-first key-share/shared-secret ordering);
 *   - RFC 9954 (hybrid TLS concatenation/failure model);
 *   - docs/X301_DRAFT.md sections 10-12;
 *   - OpenSSL provider-kem(7), provider-keymgmt(7), provider-base(7).
 *
 * No persistent hybrid format or hybrid KDF is tested or defined here.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define X301_PROVIDER "x301"
#define X301_PROPERTIES "provider=x301"
#define DEFAULT_PROVIDER "default"
#define DEFAULT_PROPERTIES "provider=default"
#define X301_NAME "X301"
#define MLKEM_NAME "ML-KEM-1024"
#define HYBRID_NAME "X301MLKEM1024"
#define X301_BYTES 38U
#define MLKEM_PUBLIC_BYTES 1568U
#define MLKEM_CIPHERTEXT_BYTES 1568U
#define MLKEM_SECRET_BYTES 32U
#define HYBRID_PUBLIC_BYTES (MLKEM_PUBLIC_BYTES + X301_BYTES)
#define HYBRID_CIPHERTEXT_BYTES (MLKEM_CIPHERTEXT_BYTES + X301_BYTES)
#define HYBRID_SECRET_BYTES (MLKEM_SECRET_BYTES + X301_BYTES)
#define CANARY_BYTES 16U

static unsigned int checks;
static unsigned long allocation_countdown;
static unsigned long allocation_total;
static const unsigned char FIELD_MODULUS[X301_BYTES] = {
    0xb3, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x1f
};

static void *counting_malloc(size_t size, const char *file, int line)
{
    (void)file;
    (void)line;
    allocation_total++;
    if (allocation_countdown > 0 && --allocation_countdown == 0)
        return NULL;
    return malloc(size);
}

static void *counting_realloc(
    void *pointer,
    size_t size,
    const char *file,
    int line)
{
    (void)file;
    (void)line;
    allocation_total++;
    if (allocation_countdown > 0 && --allocation_countdown == 0)
        return NULL;
    return realloc(pointer, size);
}

static void counting_free(void *pointer, const char *file, int line)
{
    (void)file;
    (void)line;
    free(pointer);
}

static int buffer_is(const unsigned char *buffer, size_t length, unsigned char value)
{
    size_t index;

    for (index = 0; index < length; index++) {
        if (buffer[index] != value)
            return 0;
    }
    return 1;
}

static void canonicalize_x301_oracle(
    const unsigned char input[X301_BYTES],
    unsigned char output[X301_BYTES])
{
    size_t index;
    unsigned int borrow = 0;
    int at_least_modulus = 1;

    memcpy(output, input, X301_BYTES);
    output[X301_BYTES - 1U] &= 0x1fU;
    for (index = X301_BYTES; index > 0; index--) {
        if (output[index - 1U] == FIELD_MODULUS[index - 1U])
            continue;
        at_least_modulus = output[index - 1U] > FIELD_MODULUS[index - 1U];
        break;
    }
    if (!at_least_modulus)
        return;
    for (index = 0; index < X301_BYTES; index++) {
        unsigned int subtrahend = FIELD_MODULUS[index] + borrow;
        unsigned int value = output[index];

        output[index] = (unsigned char)(value - subtrahend);
        borrow = value < subtrahend;
    }
}

static int x301_encoding_is_canonical(
    const unsigned char public_bytes[X301_BYTES])
{
    size_t index;

    if ((public_bytes[X301_BYTES - 1U] & 0xe0U) != 0)
        return 0;
    for (index = X301_BYTES; index > 0; index--) {
        if (public_bytes[index - 1U] != FIELD_MODULUS[index - 1U])
            return public_bytes[index - 1U] < FIELD_MODULUS[index - 1U];
    }
    return 0;
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

static EVP_PKEY *generate_hybrid(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        libctx, HYBRID_NAME, X301_PROPERTIES);
    EVP_PKEY *key = NULL;

    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0
            || EVP_PKEY_CTX_set_group_name(context, HYBRID_NAME) <= 0
            || EVP_PKEY_generate(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static EVP_PKEY *empty_hybrid(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        libctx, HYBRID_NAME, X301_PROPERTIES);
    EVP_PKEY *key = NULL;

    if (context == NULL || EVP_PKEY_paramgen_init(context) <= 0
            || EVP_PKEY_generate(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static EVP_PKEY *import_hybrid_public(
    OSSL_LIB_CTX *libctx,
    const unsigned char *encoded,
    size_t encoded_length)
{
    EVP_PKEY *key = empty_hybrid(libctx);

    if (key == NULL
            || EVP_PKEY_set1_encoded_public_key(
                key, encoded, encoded_length) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    return key;
}

static int export_hybrid_public(
    EVP_PKEY *key,
    unsigned char output[HYBRID_PUBLIC_BYTES])
{
    unsigned char *allocated = NULL;
    size_t length = EVP_PKEY_get1_encoded_public_key(key, &allocated);
    int result = length == HYBRID_PUBLIC_BYTES && allocated != NULL;

    if (result)
        memcpy(output, allocated, HYBRID_PUBLIC_BYTES);
    OPENSSL_free(allocated);
    return result;
}

static int rejected_public_mutation_leaves_key_empty(
    OSSL_LIB_CTX *libctx,
    const unsigned char *invalid,
    size_t invalid_length,
    const unsigned char valid[HYBRID_PUBLIC_BYTES])
{
    EVP_PKEY *key = empty_hybrid(libctx);
    unsigned char *unexpected = NULL;
    unsigned char recovered[HYBRID_PUBLIC_BYTES];
    int result = 0;

    if (key == NULL)
        goto done;
    ERR_clear_error();
    if (EVP_PKEY_set1_encoded_public_key(
            key, invalid, invalid_length) > 0)
        goto done;
    ERR_clear_error();
    if (EVP_PKEY_get1_encoded_public_key(key, &unexpected) != 0
            || unexpected != NULL)
        goto done;
    if (EVP_PKEY_set1_encoded_public_key(
            key, valid, HYBRID_PUBLIC_BYTES) <= 0
            || !export_hybrid_public(key, recovered)
            || CRYPTO_memcmp(
                recovered, valid, HYBRID_PUBLIC_BYTES) != 0)
        goto done;
    result = 1;

done:
    ERR_clear_error();
    OPENSSL_free(unexpected);
    EVP_PKEY_free(key);
    return result;
}

static int hybrid_public_boundary_mutations_are_atomic(
    OSSL_LIB_CTX *libctx,
    const unsigned char valid[HYBRID_PUBLIC_BYTES])
{
    unsigned char deleted[HYBRID_PUBLIC_BYTES - 1U];
    unsigned char inserted[HYBRID_PUBLIC_BYTES + 1U];

    memcpy(deleted, valid, MLKEM_PUBLIC_BYTES);
    memcpy(deleted + MLKEM_PUBLIC_BYTES,
        valid + MLKEM_PUBLIC_BYTES + 1U,
        X301_BYTES - 1U);
    memcpy(inserted, valid, MLKEM_PUBLIC_BYTES);
    inserted[MLKEM_PUBLIC_BYTES] = 0xa5;
    memcpy(inserted + MLKEM_PUBLIC_BYTES + 1U,
        valid + MLKEM_PUBLIC_BYTES,
        X301_BYTES);

    return rejected_public_mutation_leaves_key_empty(
               libctx, deleted, sizeof(deleted), valid)
        && rejected_public_mutation_leaves_key_empty(
               libctx, inserted, sizeof(inserted), valid);
}

static EVP_PKEY *import_mlkem_public(
    OSSL_LIB_CTX *libctx,
    const unsigned char public_key[MLKEM_PUBLIC_BYTES])
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        libctx, MLKEM_NAME, DEFAULT_PROPERTIES);
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, (void *)public_key, MLKEM_PUBLIC_BYTES);
    params[1] = OSSL_PARAM_construct_end();
    if (context == NULL || EVP_PKEY_fromdata_init(context) <= 0
            || EVP_PKEY_fromdata(
                context, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static EVP_PKEY *import_x301_public(
    OSSL_LIB_CTX *libctx,
    const unsigned char public_key[X301_BYTES])
{
    return EVP_PKEY_new_raw_public_key_ex(
        libctx, X301_NAME, X301_PROPERTIES, public_key, X301_BYTES);
}

static int hybrid_public_lengths_rejected(
    OSSL_LIB_CTX *libctx,
    const unsigned char valid[HYBRID_PUBLIC_BYTES])
{
    unsigned char extended[HYBRID_PUBLIC_BYTES + 1U];
    EVP_PKEY *short_key;
    EVP_PKEY *long_key;

    memcpy(extended, valid, HYBRID_PUBLIC_BYTES);
    extended[HYBRID_PUBLIC_BYTES] = 0;
    ERR_clear_error();
    short_key = import_hybrid_public(
        libctx, valid, HYBRID_PUBLIC_BYTES - 1U);
    ERR_clear_error();
    long_key = import_hybrid_public(libctx, extended, sizeof(extended));
    ERR_clear_error();
    if (short_key != NULL || long_key != NULL) {
        EVP_PKEY_free(long_key);
        EVP_PKEY_free(short_key);
        return 0;
    }
    return 1;
}

static int encapsulate(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *public_key,
    unsigned char ciphertext[HYBRID_CIPHERTEXT_BYTES],
    unsigned char secret[HYBRID_SECRET_BYTES])
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, public_key, X301_PROPERTIES);
    size_t queried_ciphertext = 0;
    size_t queried_secret = 0;
    size_t ciphertext_length = HYBRID_CIPHERTEXT_BYTES;
    size_t secret_length = HYBRID_SECRET_BYTES;
    int result = context != NULL
        && EVP_PKEY_encapsulate_init(context, NULL) > 0
        && EVP_PKEY_encapsulate(
            context, NULL, &queried_ciphertext, NULL, &queried_secret) > 0
        && queried_ciphertext == HYBRID_CIPHERTEXT_BYTES
        && queried_secret == HYBRID_SECRET_BYTES
        && EVP_PKEY_encapsulate(
            context, ciphertext, &ciphertext_length, secret, &secret_length) > 0
        && ciphertext_length == HYBRID_CIPHERTEXT_BYTES
        && secret_length == HYBRID_SECRET_BYTES;

    EVP_PKEY_CTX_free(context);
    return result;
}

static int decapsulate(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    const unsigned char *ciphertext,
    size_t ciphertext_length,
    unsigned char secret[HYBRID_SECRET_BYTES])
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    size_t queried_secret = 0;
    size_t secret_length = HYBRID_SECRET_BYTES;
    int result = context != NULL
        && EVP_PKEY_decapsulate_init(context, NULL) > 0
        && EVP_PKEY_decapsulate(
            context, NULL, &queried_secret,
            ciphertext, ciphertext_length) > 0
        && queried_secret == HYBRID_SECRET_BYTES
        && EVP_PKEY_decapsulate(
            context, secret, &secret_length,
            ciphertext, ciphertext_length) > 0
        && secret_length == HYBRID_SECRET_BYTES;

    EVP_PKEY_CTX_free(context);
    return result;
}

static int full_hybrid_cycle(const char *module_directory)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *x301 = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    unsigned char public_bytes[HYBRID_PUBLIC_BYTES];
    unsigned char ciphertext[HYBRID_CIPHERTEXT_BYTES];
    unsigned char encapsulated[HYBRID_SECRET_BYTES];
    unsigned char decapsulated[HYBRID_SECRET_BYTES];
    int result = 0;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(
                libctx, module_directory) <= 0
            || (deflt = OSSL_PROVIDER_load(
                    libctx, DEFAULT_PROVIDER)) == NULL
            || (x301 = OSSL_PROVIDER_load(
                    libctx, X301_PROVIDER)) == NULL
            || (private_key = generate_hybrid(libctx)) == NULL
            || !export_hybrid_public(private_key, public_bytes)
            || (public_key = import_hybrid_public(
                    libctx, public_bytes, sizeof(public_bytes))) == NULL
            || !encapsulate(
                libctx, public_key, ciphertext, encapsulated)
            || !decapsulate(
                libctx, private_key, ciphertext,
                sizeof(ciphertext), decapsulated)
            || CRYPTO_memcmp(
                encapsulated, decapsulated,
                sizeof(encapsulated)) != 0)
        goto done;
    result = 1;

done:
    OPENSSL_cleanse(decapsulated, sizeof(decapsulated));
    OPENSSL_cleanse(encapsulated, sizeof(encapsulated));
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    OSSL_PROVIDER_unload(x301);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    ERR_clear_error();
    return result;
}

static int encapsulation_short_buffers_are_atomic(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *public_key)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, public_key, X301_PROPERTIES);
    unsigned char ciphertext[HYBRID_CIPHERTEXT_BYTES + CANARY_BYTES];
    unsigned char secret[HYBRID_SECRET_BYTES + CANARY_BYTES];
    size_t ciphertext_length = HYBRID_CIPHERTEXT_BYTES - 1U;
    size_t secret_length = HYBRID_SECRET_BYTES;
    int result = 0;

    if (context == NULL || EVP_PKEY_encapsulate_init(context, NULL) <= 0)
        goto done;
    memset(ciphertext, 0xa5, sizeof(ciphertext));
    memset(secret, 0xa5, sizeof(secret));
    ERR_clear_error();
    if (EVP_PKEY_encapsulate(
            context, ciphertext, &ciphertext_length,
            secret, &secret_length)
            > 0
        || ciphertext_length != HYBRID_CIPHERTEXT_BYTES
        || secret_length != HYBRID_SECRET_BYTES
        || ERR_peek_error() == 0
        || !buffer_is(ciphertext, sizeof(ciphertext), 0xa5)
        || !buffer_is(secret, sizeof(secret), 0xa5))
        goto done;
    ERR_clear_error();

    ciphertext_length = HYBRID_CIPHERTEXT_BYTES;
    secret_length = HYBRID_SECRET_BYTES - 1U;
    if (EVP_PKEY_encapsulate(
            context, ciphertext, &ciphertext_length,
            secret, &secret_length)
            > 0
        || ciphertext_length != HYBRID_CIPHERTEXT_BYTES
        || secret_length != HYBRID_SECRET_BYTES
        || ERR_peek_error() == 0
        || !buffer_is(ciphertext, sizeof(ciphertext), 0xa5)
        || !buffer_is(secret, sizeof(secret), 0xa5))
        goto done;
    result = 1;

done:
    ERR_clear_error();
    OPENSSL_cleanse(secret, sizeof(secret));
    EVP_PKEY_CTX_free(context);
    return result;
}

static int encapsulation_failure_is_atomic(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *public_key)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, public_key, X301_PROPERTIES);
    unsigned char ciphertext[HYBRID_CIPHERTEXT_BYTES + CANARY_BYTES];
    unsigned char secret[HYBRID_SECRET_BYTES + CANARY_BYTES];
    size_t ciphertext_length = HYBRID_CIPHERTEXT_BYTES;
    size_t secret_length = HYBRID_SECRET_BYTES;
    int result = 0;

    memset(ciphertext, 0xa5, sizeof(ciphertext));
    memset(secret, 0xa5, sizeof(secret));
    ERR_clear_error();
    if (context != NULL && EVP_PKEY_encapsulate_init(context, NULL) > 0
            && EVP_PKEY_encapsulate(
                context, ciphertext, &ciphertext_length,
                secret, &secret_length) <= 0
            && ERR_peek_error() != 0
            && buffer_is(ciphertext, sizeof(ciphertext), 0xa5)
            && buffer_is(secret, sizeof(secret), 0xa5))
        result = 1;

    ERR_clear_error();
    OPENSSL_cleanse(secret, sizeof(secret));
    EVP_PKEY_CTX_free(context);
    return result;
}

static int low_order_client_shares_are_rejected(
    OSSL_LIB_CTX *libctx,
    const unsigned char valid[HYBRID_PUBLIC_BYTES])
{
    unsigned char candidate[HYBRID_PUBLIC_BYTES];
    unsigned char low_order[3][X301_BYTES] = { { 0 }, { 0 }, { 0 } };
    size_t index;

    low_order[1][0] = 1;
    memcpy(low_order[2], FIELD_MODULUS, X301_BYTES);
    low_order[2][0]--;
    for (index = 0; index < 3; index++) {
        EVP_PKEY *key;

        memcpy(candidate, valid, sizeof(candidate));
        memcpy(candidate + MLKEM_PUBLIC_BYTES, low_order[index], X301_BYTES);
        key = import_hybrid_public(libctx, candidate, sizeof(candidate));
        if (key == NULL || !encapsulation_failure_is_atomic(libctx, key)) {
            EVP_PKEY_free(key);
            return 0;
        }
        EVP_PKEY_free(key);
    }
    return 1;
}

static int decapsulation_failure_is_atomic(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    const unsigned char *ciphertext,
    size_t ciphertext_length,
    size_t output_capacity)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    unsigned char output[HYBRID_SECRET_BYTES + CANARY_BYTES];
    size_t output_length = output_capacity;
    int result = 0;

    if (context == NULL || EVP_PKEY_decapsulate_init(context, NULL) <= 0)
        goto done;
    memset(output, 0xa5, sizeof(output));
    ERR_clear_error();
    result = EVP_PKEY_decapsulate(
                 context, output, &output_length,
                 ciphertext, ciphertext_length)
            <= 0
        && ERR_peek_error() != 0
        && buffer_is(output, sizeof(output), 0xa5);

done:
    ERR_clear_error();
    OPENSSL_cleanse(output, sizeof(output));
    EVP_PKEY_CTX_free(context);
    return result;
}

static int hybrid_ciphertext_boundary_mutations_are_atomic(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    const unsigned char valid[HYBRID_CIPHERTEXT_BYTES])
{
    unsigned char deleted[HYBRID_CIPHERTEXT_BYTES - 1U];
    unsigned char inserted[HYBRID_CIPHERTEXT_BYTES + 1U];

    memcpy(deleted, valid, MLKEM_CIPHERTEXT_BYTES);
    memcpy(deleted + MLKEM_CIPHERTEXT_BYTES,
        valid + MLKEM_CIPHERTEXT_BYTES + 1U,
        X301_BYTES - 1U);
    memcpy(inserted, valid, MLKEM_CIPHERTEXT_BYTES);
    inserted[MLKEM_CIPHERTEXT_BYTES] = 0xa5;
    memcpy(inserted + MLKEM_CIPHERTEXT_BYTES + 1U,
        valid + MLKEM_CIPHERTEXT_BYTES,
        X301_BYTES);

    return decapsulation_failure_is_atomic(
               libctx, private_key, deleted, sizeof(deleted),
               HYBRID_SECRET_BYTES)
        && decapsulation_failure_is_atomic(
               libctx, private_key, inserted, sizeof(inserted),
               HYBRID_SECRET_BYTES);
}

static int hybrid_aliases_canonicalize_before_storage_and_decapsulation(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    const unsigned char canonical_public[HYBRID_PUBLIC_BYTES],
    const unsigned char canonical_ciphertext[HYBRID_CIPHERTEXT_BYTES],
    const unsigned char canonical_secret[HYBRID_SECRET_BYTES])
{
    EVP_PKEY *alias_key = NULL;
    unsigned char aliased_public[HYBRID_PUBLIC_BYTES];
    unsigned char exported_public[HYBRID_PUBLIC_BYTES];
    unsigned char aliased_ciphertext[HYBRID_CIPHERTEXT_BYTES];
    unsigned char canonicalized_ciphertext[HYBRID_CIPHERTEXT_BYTES];
    unsigned char alias_secret[HYBRID_SECRET_BYTES];
    unsigned char comparison_secret[HYBRID_SECRET_BYTES];
    unsigned int mask;
    int result = 0;

    for (mask = 0x20U; mask <= 0xe0U; mask += 0x20U) {
        memcpy(aliased_public, canonical_public, sizeof(aliased_public));
        aliased_public[HYBRID_PUBLIC_BYTES - 1U] |= (unsigned char)mask;
        alias_key = import_hybrid_public(
            libctx, aliased_public, sizeof(aliased_public));
        if (alias_key == NULL || !export_hybrid_public(
                alias_key, exported_public)
                || CRYPTO_memcmp(
                    exported_public, canonical_public,
                    HYBRID_PUBLIC_BYTES) != 0)
            goto done;
        EVP_PKEY_free(alias_key);
        alias_key = NULL;

        memcpy(aliased_ciphertext, canonical_ciphertext,
            sizeof(aliased_ciphertext));
        aliased_ciphertext[HYBRID_CIPHERTEXT_BYTES - 1U]
            |= (unsigned char)mask;
        if (!decapsulate(
                libctx, private_key, aliased_ciphertext,
                sizeof(aliased_ciphertext), alias_secret)
                || CRYPTO_memcmp(
                    alias_secret, canonical_secret,
                    HYBRID_SECRET_BYTES) != 0)
            goto done;
    }

    memcpy(aliased_public, canonical_public, sizeof(aliased_public));
    memcpy(aliased_public + MLKEM_PUBLIC_BYTES,
        FIELD_MODULUS, X301_BYTES);
    aliased_public[MLKEM_PUBLIC_BYTES] += 2U;
    alias_key = import_hybrid_public(
        libctx, aliased_public, sizeof(aliased_public));
    memcpy(exported_public, canonical_public, sizeof(exported_public));
    memset(exported_public + MLKEM_PUBLIC_BYTES, 0, X301_BYTES);
    exported_public[MLKEM_PUBLIC_BYTES] = 2U;
    if (alias_key == NULL || !export_hybrid_public(alias_key, aliased_public)
            || CRYPTO_memcmp(
                aliased_public, exported_public,
                HYBRID_PUBLIC_BYTES) != 0)
        goto done;
    EVP_PKEY_free(alias_key);
    alias_key = NULL;

    memcpy(aliased_ciphertext, canonical_ciphertext,
        sizeof(aliased_ciphertext));
    memcpy(aliased_ciphertext + MLKEM_CIPHERTEXT_BYTES,
        FIELD_MODULUS, X301_BYTES);
    aliased_ciphertext[MLKEM_CIPHERTEXT_BYTES] += 2U;
    memcpy(canonicalized_ciphertext, canonical_ciphertext,
        sizeof(canonicalized_ciphertext));
    memset(canonicalized_ciphertext + MLKEM_CIPHERTEXT_BYTES,
        0, X301_BYTES);
    canonicalized_ciphertext[MLKEM_CIPHERTEXT_BYTES] = 2U;
    if (!decapsulate(
            libctx, private_key, aliased_ciphertext,
            sizeof(aliased_ciphertext), alias_secret)
            || !decapsulate(
                libctx, private_key, canonicalized_ciphertext,
                sizeof(canonicalized_ciphertext), comparison_secret)
            || CRYPTO_memcmp(
                alias_secret, comparison_secret,
                HYBRID_SECRET_BYTES) != 0)
        goto done;

    memcpy(aliased_ciphertext, canonical_ciphertext,
        sizeof(aliased_ciphertext));
    memcpy(aliased_ciphertext + MLKEM_CIPHERTEXT_BYTES,
        FIELD_MODULUS, X301_BYTES);
    if (!decapsulation_failure_is_atomic(
            libctx, private_key, aliased_ciphertext,
            sizeof(aliased_ciphertext), HYBRID_SECRET_BYTES))
        goto done;

    result = 1;

done:
    OPENSSL_cleanse(comparison_secret, sizeof(comparison_secret));
    OPENSSL_cleanse(alias_secret, sizeof(alias_secret));
    EVP_PKEY_free(alias_key);
    return result;
}

/*
 * F1-F3 deterministic structured sweep at the hybrid EVP boundary.  This is
 * the documented fallback when libFuzzer/AFL++ is unavailable.  It covers
 * every length 0..1607, every bit of one valid client/server share, and every
 * deletion/insertion position.  Acceptance of mutated ML-KEM public keys is
 * deliberately left to FIPS 203/OpenSSL; state and output atomicity are not.
 */
static int swept_hybrid_public_is_atomic(
    OSSL_LIB_CTX *libctx,
    const unsigned char *candidate,
    size_t candidate_length,
    const unsigned char valid[HYBRID_PUBLIC_BYTES])
{
    EVP_PKEY *key = empty_hybrid(libctx);
    unsigned char *unexpected = NULL;
    unsigned char recovered[HYBRID_PUBLIC_BYTES];
    unsigned char expected[HYBRID_PUBLIC_BYTES];
    int accepted;
    int result = 0;

    if (key == NULL)
        goto done;
    ERR_clear_error();
    accepted = EVP_PKEY_set1_encoded_public_key(
        key, candidate, candidate_length);
    if (accepted > 0) {
        if (candidate_length != HYBRID_PUBLIC_BYTES)
            goto done;
        memcpy(expected, candidate, HYBRID_PUBLIC_BYTES);
        canonicalize_x301_oracle(
            candidate + MLKEM_PUBLIC_BYTES,
            expected + MLKEM_PUBLIC_BYTES);
        if (!export_hybrid_public(key, recovered)
                || CRYPTO_memcmp(
                    recovered, expected, HYBRID_PUBLIC_BYTES) != 0)
            goto done;
    } else {
        ERR_clear_error();
        if (EVP_PKEY_get1_encoded_public_key(key, &unexpected) != 0
                || unexpected != NULL
                || EVP_PKEY_set1_encoded_public_key(
                    key, valid, HYBRID_PUBLIC_BYTES) <= 0
                || !export_hybrid_public(key, recovered)
                || CRYPTO_memcmp(
                    recovered, valid, HYBRID_PUBLIC_BYTES) != 0)
            goto done;
    }
    result = 1;

done:
    ERR_clear_error();
    OPENSSL_free(unexpected);
    EVP_PKEY_free(key);
    return result;
}

static int swept_hybrid_ciphertext_is_atomic(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    const unsigned char *candidate,
    size_t candidate_length,
    const unsigned char original_secret[HYBRID_SECRET_BYTES],
    int require_implicit_rejection_success)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, private_key, X301_PROPERTIES);
    unsigned char output[HYBRID_SECRET_BYTES + CANARY_BYTES];
    size_t queried = 0;
    size_t output_length = HYBRID_SECRET_BYTES;
    int query_result;
    int decap_result;
    int result = 0;

    if (context == NULL || EVP_PKEY_decapsulate_init(context, NULL) <= 0)
        goto done;
    memset(output, 0xa5, sizeof(output));
    ERR_clear_error();
    query_result = EVP_PKEY_decapsulate(
        context, NULL, &queried, candidate, candidate_length);
    if (query_result <= 0) {
        result = !require_implicit_rejection_success
            && buffer_is(output, sizeof(output), 0xa5);
        goto done;
    }
    if (queried != HYBRID_SECRET_BYTES)
        goto done;
    decap_result = EVP_PKEY_decapsulate(
        context, output, &output_length, candidate, candidate_length);
    if (decap_result > 0) {
        result = output_length == HYBRID_SECRET_BYTES
            && !buffer_is(
                output + MLKEM_SECRET_BYTES, X301_BYTES, 0)
            && buffer_is(
                output + HYBRID_SECRET_BYTES, CANARY_BYTES, 0xa5);
        if (result && require_implicit_rejection_success) {
            result = CRYPTO_memcmp(
                output + MLKEM_SECRET_BYTES,
                original_secret + MLKEM_SECRET_BYTES,
                X301_BYTES) == 0;
        }
    } else {
        result = !require_implicit_rejection_success
            && buffer_is(output, sizeof(output), 0xa5);
    }

done:
    ERR_clear_error();
    OPENSSL_cleanse(output, sizeof(output));
    EVP_PKEY_CTX_free(context);
    return result;
}

static int structured_hybrid_parser_sweep(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *private_key,
    const unsigned char valid_public[HYBRID_PUBLIC_BYTES],
    const unsigned char valid_ciphertext[HYBRID_CIPHERTEXT_BYTES],
    const unsigned char original_secret[HYBRID_SECRET_BYTES],
    unsigned long *case_count)
{
    unsigned char public_candidate[HYBRID_PUBLIC_BYTES + 1U];
    unsigned char ciphertext_candidate[HYBRID_CIPHERTEXT_BYTES + 1U];
    unsigned char deleted[HYBRID_PUBLIC_BYTES - 1U];
    size_t index;
    unsigned int bit;
    size_t length;
    unsigned long cases = 0;

    memcpy(public_candidate, valid_public, HYBRID_PUBLIC_BYTES);
    public_candidate[HYBRID_PUBLIC_BYTES] = 0xa5;
    memcpy(ciphertext_candidate, valid_ciphertext,
        HYBRID_CIPHERTEXT_BYTES);
    ciphertext_candidate[HYBRID_CIPHERTEXT_BYTES] = 0xa5;

    for (length = 0; length <= HYBRID_PUBLIC_BYTES + 1U; length++) {
        if (!swept_hybrid_public_is_atomic(
                libctx, public_candidate, length, valid_public))
            return 0;
        if (!swept_hybrid_ciphertext_is_atomic(
                libctx, private_key, ciphertext_candidate, length,
                original_secret, 0))
            return 0;
        cases += 2U;
    }

    for (index = 0; index < HYBRID_PUBLIC_BYTES; index++) {
        for (bit = 0; bit < 8U; bit++) {
            memcpy(public_candidate, valid_public, HYBRID_PUBLIC_BYTES);
            public_candidate[index] ^= (unsigned char)(1U << bit);
            if (!swept_hybrid_public_is_atomic(
                    libctx, public_candidate, HYBRID_PUBLIC_BYTES,
                    valid_public))
                return 0;

            memcpy(ciphertext_candidate, valid_ciphertext,
                HYBRID_CIPHERTEXT_BYTES);
            ciphertext_candidate[index] ^= (unsigned char)(1U << bit);
            if (!swept_hybrid_ciphertext_is_atomic(
                    libctx, private_key, ciphertext_candidate,
                    HYBRID_CIPHERTEXT_BYTES, original_secret,
                    index < MLKEM_CIPHERTEXT_BYTES))
                return 0;
            cases += 2U;
        }
    }

    for (index = 0; index < HYBRID_PUBLIC_BYTES; index++) {
        memcpy(deleted, valid_public, index);
        memcpy(deleted + index, valid_public + index + 1U,
            HYBRID_PUBLIC_BYTES - index - 1U);
        if (!swept_hybrid_public_is_atomic(
                libctx, deleted, sizeof(deleted), valid_public))
            return 0;

        memcpy(deleted, valid_ciphertext, index);
        memcpy(deleted + index, valid_ciphertext + index + 1U,
            HYBRID_CIPHERTEXT_BYTES - index - 1U);
        if (!swept_hybrid_ciphertext_is_atomic(
                libctx, private_key, deleted, sizeof(deleted),
                original_secret, 0))
            return 0;
        cases += 2U;
    }

    for (index = 0; index <= HYBRID_PUBLIC_BYTES; index++) {
        memcpy(public_candidate, valid_public, index);
        public_candidate[index] = 0xa5;
        memcpy(public_candidate + index + 1U, valid_public + index,
            HYBRID_PUBLIC_BYTES - index);
        if (!swept_hybrid_public_is_atomic(
                libctx, public_candidate, sizeof(public_candidate),
                valid_public))
            return 0;

        memcpy(ciphertext_candidate, valid_ciphertext, index);
        ciphertext_candidate[index] = 0xa5;
        memcpy(ciphertext_candidate + index + 1U,
            valid_ciphertext + index,
            HYBRID_CIPHERTEXT_BYTES - index);
        if (!swept_hybrid_ciphertext_is_atomic(
                libctx, private_key, ciphertext_candidate,
                sizeof(ciphertext_candidate), original_secret, 0))
            return 0;
        cases += 2U;
    }
    *case_count = cases;
    return 1;
}

static int oversized_success_preserves_tail(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *public_key,
    EVP_PKEY *private_key)
{
    EVP_PKEY_CTX *encap = NULL;
    EVP_PKEY_CTX *decap = NULL;
    unsigned char ciphertext[HYBRID_CIPHERTEXT_BYTES + CANARY_BYTES];
    unsigned char secret_a[HYBRID_SECRET_BYTES + CANARY_BYTES];
    unsigned char secret_b[HYBRID_SECRET_BYTES + CANARY_BYTES];
    size_t ciphertext_length = sizeof(ciphertext);
    size_t secret_a_length = sizeof(secret_a);
    size_t secret_b_length = sizeof(secret_b);
    int result = 0;

    encap = EVP_PKEY_CTX_new_from_pkey(libctx, public_key, X301_PROPERTIES);
    decap = EVP_PKEY_CTX_new_from_pkey(libctx, private_key, X301_PROPERTIES);
    memset(ciphertext, 0xa5, sizeof(ciphertext));
    memset(secret_a, 0xa5, sizeof(secret_a));
    memset(secret_b, 0xa5, sizeof(secret_b));
    if (encap == NULL || decap == NULL
            || EVP_PKEY_encapsulate_init(encap, NULL) <= 0
            || EVP_PKEY_encapsulate(
                encap, ciphertext, &ciphertext_length,
                secret_a, &secret_a_length) <= 0
            || ciphertext_length != HYBRID_CIPHERTEXT_BYTES
            || secret_a_length != HYBRID_SECRET_BYTES
            || !buffer_is(ciphertext + HYBRID_CIPHERTEXT_BYTES,
                CANARY_BYTES, 0xa5)
            || !buffer_is(secret_a + HYBRID_SECRET_BYTES,
                CANARY_BYTES, 0xa5)
            || EVP_PKEY_decapsulate_init(decap, NULL) <= 0
            || EVP_PKEY_decapsulate(
                decap, secret_b, &secret_b_length,
                ciphertext, HYBRID_CIPHERTEXT_BYTES) <= 0
            || secret_b_length != HYBRID_SECRET_BYTES
            || CRYPTO_memcmp(secret_a, secret_b, HYBRID_SECRET_BYTES) != 0
            || !buffer_is(secret_b + HYBRID_SECRET_BYTES,
                CANARY_BYTES, 0xa5))
        goto done;
    result = 1;

done:
    OPENSSL_cleanse(secret_b, sizeof(secret_b));
    OPENSSL_cleanse(secret_a, sizeof(secret_a));
    EVP_PKEY_CTX_free(decap);
    EVP_PKEY_CTX_free(encap);
    return result;
}

typedef struct hybrid_lifecycle_worker_st {
    OSSL_LIB_CTX *libctx;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int ready;
    int release;
    int operations_ok;
} HYBRID_LIFECYCLE_WORKER;

static void *hybrid_lifecycle_worker(void *argument)
{
    HYBRID_LIFECYCLE_WORKER *worker = argument;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    unsigned char public_bytes[HYBRID_PUBLIC_BYTES];
    unsigned char ciphertext[HYBRID_CIPHERTEXT_BYTES];
    unsigned char encapsulated[HYBRID_SECRET_BYTES];
    unsigned char decapsulated[HYBRID_SECRET_BYTES];

    private_key = generate_hybrid(worker->libctx);
    if (private_key != NULL
            && export_hybrid_public(private_key, public_bytes)
            && (public_key = import_hybrid_public(
                    worker->libctx, public_bytes,
                    sizeof(public_bytes))) != NULL
            && encapsulate(
                worker->libctx, public_key, ciphertext, encapsulated)
            && decapsulate(
                worker->libctx, private_key, ciphertext,
                sizeof(ciphertext), decapsulated)
            && CRYPTO_memcmp(
                encapsulated, decapsulated,
                sizeof(encapsulated)) == 0)
        worker->operations_ok = 1;

    OPENSSL_cleanse(decapsulated, sizeof(decapsulated));
    OPENSSL_cleanse(encapsulated, sizeof(encapsulated));
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);

    /*
     * OpenSSL's OSSL_LIB_CTX contract requires each application thread to
     * release thread-local state for the host context before another thread
     * frees that context.  The provider can clean its own child context, but
     * it neither owns nor can access this host context.  Doing the host-side
     * cleanup here leaves Valgrind able to detect any stale child-context
     * handler independently.
     */
    OPENSSL_thread_stop_ex(worker->libctx);

    if (pthread_mutex_lock(&worker->mutex) != 0)
        return NULL;
    worker->ready = 1;
    pthread_cond_signal(&worker->condition);
    while (!worker->release)
        pthread_cond_wait(&worker->condition, &worker->mutex);
    pthread_mutex_unlock(&worker->mutex);
    return NULL;
}

static int hybrid_cross_thread_child_libctx_lifecycle(const char *module_directory)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *x301 = NULL;
    HYBRID_LIFECYCLE_WORKER worker;
    pthread_t thread;
    int mutex_ready = 0;
    int condition_ready = 0;
    int thread_started = 0;
    int thread_joined = 0;
    int x301_unloaded = 0;
    int default_unloaded = 0;
    int result = 0;

    memset(&worker, 0, sizeof(worker));
    worker.libctx = libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(
                libctx, module_directory) <= 0
            || (deflt = OSSL_PROVIDER_load(
                    libctx, DEFAULT_PROVIDER)) == NULL
            || (x301 = OSSL_PROVIDER_load(
                    libctx, X301_PROVIDER)) == NULL)
        goto done;
    mutex_ready = pthread_mutex_init(&worker.mutex, NULL) == 0;
    condition_ready = mutex_ready
        && pthread_cond_init(&worker.condition, NULL) == 0;
    if (!condition_ready)
        goto done;
    thread_started = pthread_create(
        &thread, NULL, hybrid_lifecycle_worker, &worker) == 0;
    if (!thread_started)
        goto done;

    pthread_mutex_lock(&worker.mutex);
    while (!worker.ready)
        pthread_cond_wait(&worker.condition, &worker.mutex);
    pthread_mutex_unlock(&worker.mutex);

    x301_unloaded = OSSL_PROVIDER_unload(x301) == 1;
    x301 = NULL;
    default_unloaded = OSSL_PROVIDER_unload(deflt) == 1;
    deflt = NULL;
    OSSL_LIB_CTX_free(libctx);
    libctx = NULL;

    pthread_mutex_lock(&worker.mutex);
    worker.release = 1;
    pthread_cond_signal(&worker.condition);
    pthread_mutex_unlock(&worker.mutex);
    thread_joined = pthread_join(thread, NULL) == 0;
    thread_started = 0;
    result = worker.operations_ok && x301_unloaded
        && default_unloaded && thread_joined;

done:
    if (thread_started) {
        pthread_mutex_lock(&worker.mutex);
        worker.release = 1;
        pthread_cond_signal(&worker.condition);
        pthread_mutex_unlock(&worker.mutex);
        pthread_join(thread, NULL);
    }
    OSSL_PROVIDER_unload(x301);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    if (condition_ready)
        pthread_cond_destroy(&worker.condition);
    if (mutex_ready)
        pthread_mutex_destroy(&worker.mutex);
    ERR_clear_error();
    return result;
}

static int hybrid_fails_cleanly_without_mlkem(const char *module_directory)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *null_provider = NULL;
    OSSL_PROVIDER *x301 = NULL;
    int result = 0;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(
                libctx, module_directory) <= 0
            || (null_provider = OSSL_PROVIDER_load(libctx, "null")) == NULL
            || OSSL_PROVIDER_available(libctx, DEFAULT_PROVIDER) != 0)
        goto done;
    x301 = OSSL_PROVIDER_load(libctx, X301_PROVIDER);
    ERR_clear_error();
    result = x301 == NULL
        && OSSL_PROVIDER_available(libctx, DEFAULT_PROVIDER) == 0;

done:
    ERR_clear_error();
    OSSL_PROVIDER_unload(x301);
    OSSL_PROVIDER_unload(null_provider);
    OSSL_LIB_CTX_free(libctx);
    return result;
}

static int hybrid_honors_child_default_properties(
    const char *module_directory)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *null_provider = NULL;
    OSSL_PROVIDER *x301 = NULL;
    EVP_KEYMGMT *hybrid_keymgmt = NULL;
    EVP_PKEY *generated = NULL;
    int result = 0;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(
                libctx, module_directory) <= 0
            || (deflt = OSSL_PROVIDER_load(
                    libctx, DEFAULT_PROVIDER)) == NULL
            || (null_provider = OSSL_PROVIDER_load(
                    libctx, "null")) == NULL
            || (x301 = OSSL_PROVIDER_load(
                    libctx, X301_PROVIDER)) == NULL
            || EVP_set_default_properties(libctx, "provider=null") <= 0)
        goto done;
    hybrid_keymgmt = EVP_KEYMGMT_fetch(
        libctx, HYBRID_NAME, X301_PROPERTIES);
    if (hybrid_keymgmt == NULL
            || OSSL_PROVIDER_available(libctx, DEFAULT_PROVIDER) != 1)
        goto done;

    ERR_clear_error();
    generated = generate_hybrid(libctx);
    if (generated != NULL)
        goto done;
    result = 1;

done:
    ERR_clear_error();
    EVP_PKEY_free(generated);
    EVP_KEYMGMT_free(hybrid_keymgmt);
    OSSL_PROVIDER_unload(x301);
    OSSL_PROVIDER_unload(null_provider);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return result;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *x301 = NULL;
    EVP_KEYMGMT *ml_keymgmt = NULL;
    EVP_KEM *ml_kem = NULL;
    EVP_KEYMGMT *own_ml_keymgmt = NULL;
    EVP_KEM *own_ml_kem = NULL;
    EVP_KEYMGMT *hybrid_keymgmt = NULL;
    EVP_KEM *hybrid_kem = NULL;
    EVP_KEYMGMT *legacy_keymgmt = NULL;
    EVP_KEM *legacy_kem = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    EVP_PKEY *ml_public = NULL;
    EVP_PKEY *x_public = NULL;
    unsigned char public_bytes[HYBRID_PUBLIC_BYTES];
    unsigned char ciphertext[HYBRID_CIPHERTEXT_BYTES];
    unsigned char ciphertext_long[HYBRID_CIPHERTEXT_BYTES + 1U];
    unsigned char original_secret[HYBRID_SECRET_BYTES];
    unsigned char decapsulated_secret[HYBRID_SECRET_BYTES];
    unsigned char mutated_ciphertext[HYBRID_CIPHERTEXT_BYTES];
    unsigned char mutated_secret_a[HYBRID_SECRET_BYTES];
    unsigned char mutated_secret_b[HYBRID_SECRET_BYTES];
    const int allocation_sweep =
        getenv("X301_HYBRID_ALLOC_SWEEP") != NULL;
    const int structured_sweep =
        getenv("X301_STRUCTURED_SWEEP") != NULL;
    unsigned long sweep_cases = 0;
    int success = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s PROVIDER_MODULE_DIRECTORY\n", argv[0]);
        return 2;
    }
    if (allocation_sweep
            && CRYPTO_set_mem_functions(
                counting_malloc, counting_realloc, counting_free) != 1) {
        fprintf(stderr, "cannot install X301 counting allocator\n");
        return 2;
    }
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) <= 0
            || (deflt = OSSL_PROVIDER_load(libctx, DEFAULT_PROVIDER)) == NULL
            || (x301 = OSSL_PROVIDER_load(libctx, X301_PROVIDER)) == NULL) {
        fail("load default and X301 providers");
        goto done;
    }
    pass("load default and X301 providers");

    ml_keymgmt = EVP_KEYMGMT_fetch(libctx, MLKEM_NAME, DEFAULT_PROPERTIES);
    ml_kem = EVP_KEM_fetch(libctx, MLKEM_NAME, DEFAULT_PROPERTIES);
    own_ml_keymgmt = EVP_KEYMGMT_fetch(libctx, MLKEM_NAME, X301_PROPERTIES);
    own_ml_kem = EVP_KEM_fetch(libctx, MLKEM_NAME, X301_PROPERTIES);
    if (ml_keymgmt == NULL || ml_kem == NULL
            || strcmp(OSSL_PROVIDER_get0_name(
                    EVP_KEYMGMT_get0_provider(ml_keymgmt)),
                DEFAULT_PROVIDER) != 0
            || strcmp(OSSL_PROVIDER_get0_name(EVP_KEM_get0_provider(ml_kem)),
                DEFAULT_PROVIDER) != 0
            || own_ml_keymgmt != NULL || own_ml_kem != NULL) {
        fail("E1 normative lane ML-KEM-1024 is OpenSSL default-provider-owned");
        goto done;
    }
    ERR_clear_error();
    pass("E1 normative lane ML-KEM-1024 is OpenSSL default-provider-owned");

    hybrid_keymgmt = EVP_KEYMGMT_fetch(
        libctx, HYBRID_NAME, X301_PROPERTIES);
    hybrid_kem = EVP_KEM_fetch(libctx, HYBRID_NAME, X301_PROPERTIES);
    if (hybrid_keymgmt == NULL || hybrid_kem == NULL) {
        fail("fetch minimal X301MLKEM1024 KEYMGMT/KEM substrate");
        goto done;
    }
    pass("fetch minimal X301MLKEM1024 KEYMGMT/KEM substrate");

    legacy_keymgmt = EVP_KEYMGMT_fetch(
        libctx, "MLKEM1024X301", X301_PROPERTIES);
    legacy_kem = EVP_KEM_fetch(
        libctx, "MLKEM1024X301", X301_PROPERTIES);
    if (legacy_keymgmt != NULL || legacy_kem != NULL) {
        fail("obsolete hybrid name is rejected");
        goto done;
    }
    ERR_clear_error();
    pass("obsolete hybrid name is rejected");

    private_key = generate_hybrid(libctx);
    if (private_key == NULL || !export_hybrid_public(private_key, public_bytes)
            || !x301_encoding_is_canonical(
                public_bytes + MLKEM_PUBLIC_BYTES)) {
        fail("H2 hybrid client share is exactly 1568+38=1606 bytes");
        goto done;
    }
    pass("H2 hybrid client share is exactly 1568+38=1606 bytes");

    ml_public = import_mlkem_public(libctx, public_bytes);
    x_public = import_x301_public(libctx, public_bytes + MLKEM_PUBLIC_BYTES);
    if (ml_public == NULL || x_public == NULL) {
        fail("H1 client share parses as ML-KEM-first then X301");
        goto done;
    }
    pass("H1 client share parses as ML-KEM-first then X301");

    if (!hybrid_public_lengths_rejected(libctx, public_bytes)) {
        fail("H2 client-share component boundary lengths 1605/1607 reject");
        goto done;
    }
    pass("H2 client-share component boundary lengths 1605/1607 reject");

    if (!hybrid_public_boundary_mutations_are_atomic(
            libctx, public_bytes)) {
        fail("H2 client-share delete/insert at offset 1568 reject atomically");
        goto done;
    }
    pass("H2 client-share delete/insert at offset 1568 reject atomically");

    public_key = import_hybrid_public(libctx, public_bytes, sizeof(public_bytes));
    if (public_key == NULL
            || !encapsulate(
                libctx, public_key, ciphertext, original_secret)
            || !decapsulate(
                libctx, private_key, ciphertext,
                sizeof(ciphertext), decapsulated_secret)
            || !x301_encoding_is_canonical(
                ciphertext + MLKEM_CIPHERTEXT_BYTES)
            || CRYPTO_memcmp(
                original_secret, decapsulated_secret,
                sizeof(original_secret)) != 0) {
        fail("H2 direct KEM roundtrip is exactly 1606/1606/70");
        goto done;
    }
    pass("H2 direct KEM roundtrip is exactly 1606/1606/70");

    if (!low_order_client_shares_are_rejected(libctx, public_bytes)) {
        fail("T9 low-order X301 client shares reject encapsulation atomically");
        goto done;
    }
    pass("T9 low-order X301 client shares reject encapsulation atomically");

    if (!hybrid_aliases_canonicalize_before_storage_and_decapsulation(
            libctx, private_key, public_bytes, ciphertext,
            original_secret)) {
        fail("D2 hybrid client and server aliases canonicalize consistently");
        goto done;
    }
    pass("D2 hybrid client and server aliases canonicalize consistently");

    if (!encapsulation_short_buffers_are_atomic(libctx, public_key)) {
        fail("H2 short ciphertext/secret buffers fail atomically");
        goto done;
    }
    pass("H2 short ciphertext/secret buffers fail atomically");

    memcpy(ciphertext_long, ciphertext, sizeof(ciphertext));
    ciphertext_long[HYBRID_CIPHERTEXT_BYTES] = 0;
    if (!decapsulation_failure_is_atomic(
            libctx, private_key, ciphertext,
            HYBRID_CIPHERTEXT_BYTES - 1U, HYBRID_SECRET_BYTES)
            || !decapsulation_failure_is_atomic(
                libctx, private_key, ciphertext_long,
                sizeof(ciphertext_long), HYBRID_SECRET_BYTES)
            || !decapsulation_failure_is_atomic(
                libctx, private_key, ciphertext,
                sizeof(ciphertext), HYBRID_SECRET_BYTES - 1U)) {
        fail("H2 server-share 1605/1607 and 69-byte output reject atomically");
        goto done;
    }
    pass("H2 server-share 1605/1607 and 69-byte output reject atomically");

    if (!hybrid_ciphertext_boundary_mutations_are_atomic(
            libctx, private_key, ciphertext)) {
        fail("H2 server-share delete/insert at offset 1568 reject atomically");
        goto done;
    }
    pass("H2 server-share delete/insert at offset 1568 reject atomically");

    if (!oversized_success_preserves_tail(libctx, public_key, private_key)) {
        fail("H2 successful KEM writes exact lengths and preserves canaries");
        goto done;
    }
    pass("H2 successful KEM writes exact lengths and preserves canaries");

    memcpy(mutated_ciphertext, ciphertext, sizeof(mutated_ciphertext));
    memset(mutated_ciphertext + MLKEM_CIPHERTEXT_BYTES, 0, X301_BYTES);
    if (!decapsulation_failure_is_atomic(
            libctx, private_key, mutated_ciphertext,
            sizeof(mutated_ciphertext), HYBRID_SECRET_BYTES)) {
        fail("T9 all-zero X301 contribution rejects the whole group atomically");
        goto done;
    }
    pass("T9 all-zero X301 contribution rejects the whole group atomically");

    memcpy(mutated_ciphertext, ciphertext, sizeof(mutated_ciphertext));
    mutated_ciphertext[0] ^= 1U;
    if (!decapsulate(
            libctx, private_key, mutated_ciphertext,
            sizeof(mutated_ciphertext), mutated_secret_a)
            || !decapsulate(
                libctx, private_key, mutated_ciphertext,
                sizeof(mutated_ciphertext), mutated_secret_b)
            || CRYPTO_memcmp(
                mutated_secret_a, mutated_secret_b,
                sizeof(mutated_secret_a)) != 0
            || CRYPTO_memcmp(
                mutated_secret_a, original_secret,
                MLKEM_SECRET_BYTES) == 0
            || CRYPTO_memcmp(
                mutated_secret_a + MLKEM_SECRET_BYTES,
                original_secret + MLKEM_SECRET_BYTES,
                X301_BYTES) != 0) {
        fail("T9 ML-KEM mutation uses deterministic implicit rejection");
        goto done;
    }
    pass("T9 ML-KEM mutation uses deterministic implicit rejection");

    if (structured_sweep) {
        if (!structured_hybrid_parser_sweep(
                libctx, private_key, public_bytes, ciphertext,
                original_secret, &sweep_cases)) {
            fail("F1-F3 hybrid client/server parser structured sweep");
            goto done;
        }
        {
            char label[192];

            snprintf(label, sizeof(label),
                "F1-F3 hybrid client/server parser structured sweep "
                "(%lu cases)", sweep_cases);
            pass(label);
        }
    }

    if (!hybrid_cross_thread_child_libctx_lifecycle(argv[1])) {
        fail("hybrid child-LIBCTX survives main-thread teardown before worker exit");
        goto done;
    }
    pass("hybrid child-LIBCTX survives main-thread teardown before worker exit");

    if (!hybrid_fails_cleanly_without_mlkem(argv[1])) {
        fail("hybrid keygen/import fail atomically without an ML-KEM provider");
        goto done;
    }
    pass("hybrid keygen/import fail atomically without an ML-KEM provider");

    if (!hybrid_honors_child_default_properties(argv[1])) {
        fail("hybrid ML-KEM fetch honors child default properties");
        goto done;
    }
    pass("hybrid ML-KEM fetch honors child default properties");

    success = 1;

done:
    OPENSSL_cleanse(mutated_secret_b, sizeof(mutated_secret_b));
    OPENSSL_cleanse(mutated_secret_a, sizeof(mutated_secret_a));
    OPENSSL_cleanse(decapsulated_secret, sizeof(decapsulated_secret));
    OPENSSL_cleanse(original_secret, sizeof(original_secret));
    EVP_PKEY_free(x_public);
    EVP_PKEY_free(ml_public);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    EVP_KEM_free(hybrid_kem);
    EVP_KEM_free(legacy_kem);
    EVP_KEYMGMT_free(hybrid_keymgmt);
    EVP_KEYMGMT_free(legacy_keymgmt);
    EVP_KEM_free(own_ml_kem);
    EVP_KEYMGMT_free(own_ml_keymgmt);
    EVP_KEM_free(ml_kem);
    EVP_KEYMGMT_free(ml_keymgmt);
    OSSL_PROVIDER_unload(x301);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    if (success && allocation_sweep) {
        unsigned long fail_at;
        unsigned long clean_failures = 0;
        unsigned long survivals = 0;

        for (fail_at = 1; fail_at <= 800; fail_at += 11) {
            allocation_countdown = fail_at;
            if (full_hybrid_cycle(argv[1]))
                survivals++;
            else
                clean_failures++;
            allocation_countdown = 0;
        }
        if (clean_failures == 0 || !full_hybrid_cycle(argv[1])) {
            fail("M6 hybrid allocation failures are clean and recoverable");
            success = 0;
        } else {
            char label[192];

            snprintf(label, sizeof(label),
                "M6 hybrid allocation sweep recovers "
                "(clean failures=%lu survivals=%lu)",
                clean_failures, survivals);
            pass(label);
        }
        printf("openssl_allocations_observed=%lu\n", allocation_total);
    }
    if (success)
        printf("provider_x301_hybrid_contract_pass=1 checks=%u\n", checks);
    return success ? 0 : 1;
}
