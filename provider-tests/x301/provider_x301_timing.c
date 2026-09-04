#define _POSIX_C_SOURCE 200809L

/*
 * Timing-leak detection for the final X301 provider module with dudect.
 *
 * Tool: vendored `third_party/dudect/dudect.h` (Reparaz, Balasch,
 * Verbauwhede, "Dude, is my code constant time?", DATE 2017).  dudect owns
 * the measurement loop, Welch's t-tests on raw, percentile-cropped and
 * second-order data, and the verdict (|t| > 10 is DUDECT_LEAKAGE_FOUND).
 * This file supplies only the two dudect callbacks: prepare_inputs() builds
 * the per-measurement EVP state for a randomly chosen input class, and
 * do_one_computation() runs exactly one EVP operation, so that the timed
 * interval is the operation alone.
 *
 * Tests (gating unless noted):
 *   T1 derive with fixed vs random local secret, fixed peer;
 *   T2 derive with fixed vs random peer u, fixed local secret;
 *   T3 raw private import (fixed-base public derivation), fixed vs random;
 *   T4 hybrid decapsulation, one fixed valid ciphertext vs fresh valid ones;
 *   T5 hybrid decapsulation, fixed valid vs one corrupted ML-KEM byte
 *      (informative: FIPS 203 implicit rejection is OpenSSL-owned);
 *   P0 positive control, a deliberately secret-dependent loop, which must be
 *      reported as leakage or the run is inconclusive.
 *
 * A pass is evidence for the measured classes on this machine, not a
 * constant-time proof.  Secret-dependent addresses and branches are covered
 * by the secret-taint lane, machine-code shape by the codegen gate.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#define DUDECT_IMPLEMENTATION
#include "third_party/dudect/dudect.h"

#define X301_BYTES 38U
#define X301_NAME "X301"
#define X301_PROPERTIES "provider=x301"
#define HYBRID_NAME "X301MLKEM1024"
#define HYBRID_CIPHERTEXT_BYTES (1568U + X301_BYTES)
#define HYBRID_SECRET_BYTES 70U

#define BATCH_MEASUREMENTS 2000U
#define CHUNK_SIZE sizeof(uint32_t)

enum {
    TEST_POSITIVE_CONTROL,
    TEST_DERIVE_SECRET,
    TEST_DERIVE_PEER,
    TEST_IMPORT_PRIVATE,
    TEST_HYBRID_DECAPS_CT,
    TEST_HYBRID_DECAPS_REJECT,
    TEST_COUNT
};

static const char *const TEST_LABELS[TEST_COUNT] = {
    "P0 positive-control",
    "T1 derive/secret",
    "T2 derive/peer",
    "T3 import-private",
    "T4 hybrid-decaps/ct",
    "T5 hybrid-decaps/reject"
};

static const unsigned char FIXED_SECRET[X301_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25
};
/* Independent-reference PUBLIC_B from the contract harness. */
static const unsigned char FIXED_PEER[X301_BYTES] = {
    0x86, 0xa7, 0xfa, 0x2c, 0xcb, 0x11, 0xa7, 0x6c,
    0x34, 0xfd, 0x7b, 0xca, 0x0f, 0x6e, 0x59, 0x2c,
    0x99, 0x91, 0xcb, 0x55, 0x4c, 0xd7, 0xb3, 0x26,
    0xa2, 0x17, 0x7d, 0xf7, 0xdb, 0xb0, 0xf4, 0xc5,
    0x14, 0x38, 0x15, 0x19, 0x92, 0x1d
};

/* Per-measurement state prepared outside the timed interval. */
typedef struct {
    EVP_PKEY *key;
    EVP_PKEY *peer;
    EVP_PKEY_CTX *ctx;
    unsigned char bytes[HYBRID_CIPHERTEXT_BYTES];
} SLOT;

static OSSL_LIB_CTX *libctx;
static int current_test;
static SLOT slots[BATCH_MEASUREMENTS];
static EVP_PKEY *shared_key;
static unsigned char fixed_ciphertext[HYBRID_CIPHERTEXT_BYTES];
static unsigned char corrupt_ciphertext[HYBRID_CIPHERTEXT_BYTES];
static unsigned char output[HYBRID_SECRET_BYTES];
static size_t operation_failures;
static size_t prepare_failures;
static volatile uint64_t sink;

static EVP_PKEY *raw_private(const unsigned char *bytes)
{
    return EVP_PKEY_new_raw_private_key_ex(
        libctx, X301_NAME, X301_PROPERTIES, bytes, X301_BYTES);
}

static EVP_PKEY *raw_public(const unsigned char *bytes)
{
    return EVP_PKEY_new_raw_public_key_ex(
        libctx, X301_NAME, X301_PROPERTIES, bytes, X301_BYTES);
}

static void slot_clear(SLOT *slot)
{
    EVP_PKEY_CTX_free(slot->ctx);
    EVP_PKEY_free(slot->peer);
    EVP_PKEY_free(slot->key);
    OPENSSL_cleanse(slot->bytes, sizeof(slot->bytes));
    slot->ctx = NULL;
    slot->peer = NULL;
    slot->key = NULL;
}

static int hybrid_encapsulate(EVP_PKEY *key, unsigned char *ciphertext)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, X301_PROPERTIES);
    unsigned char secret[HYBRID_SECRET_BYTES];
    size_t ct_len = HYBRID_CIPHERTEXT_BYTES, ss_len = sizeof(secret);
    int ok = ctx != NULL && EVP_PKEY_encapsulate_init(ctx, NULL) > 0
        && EVP_PKEY_encapsulate(ctx, ciphertext, &ct_len, secret, &ss_len) > 0
        && ct_len == HYBRID_CIPHERTEXT_BYTES;

    OPENSSL_cleanse(secret, sizeof(secret));
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int prepare_derive_slot(SLOT *slot, int class, int random_secret)
{
    unsigned char material[X301_BYTES];
    int ok = 0;

    if (class == 0)
        memcpy(material, random_secret ? FIXED_SECRET : FIXED_PEER,
            sizeof(material));
    else if (RAND_bytes(material, sizeof(material)) != 1)
        return 0;
    if (random_secret) {
        slot->key = raw_private(material);
        slot->peer = raw_public(FIXED_PEER);
    } else {
        slot->key = raw_private(FIXED_SECRET);
        slot->peer = raw_public(material);
    }
    OPENSSL_cleanse(material, sizeof(material));
    if (slot->key == NULL || slot->peer == NULL)
        return 0;
    slot->ctx = EVP_PKEY_CTX_new_from_pkey(libctx, slot->key, X301_PROPERTIES);
    ok = slot->ctx != NULL && EVP_PKEY_derive_init(slot->ctx) > 0
        && EVP_PKEY_derive_set_peer(slot->ctx, slot->peer) > 0;
    return ok;
}

static int prepare_slot(SLOT *slot, int class)
{
    switch (current_test) {
    case TEST_POSITIVE_CONTROL:
        if (class == 0)
            memset(slot->bytes, 0, X301_BYTES);
        else if (RAND_bytes(slot->bytes, X301_BYTES) != 1)
            return 0;
        return 1;
    case TEST_DERIVE_SECRET:
        return prepare_derive_slot(slot, class, 1);
    case TEST_DERIVE_PEER:
        return prepare_derive_slot(slot, class, 0);
    case TEST_IMPORT_PRIVATE:
        if (class == 0)
            memcpy(slot->bytes, FIXED_SECRET, X301_BYTES);
        else if (RAND_bytes(slot->bytes, X301_BYTES) != 1)
            return 0;
        return 1;
    case TEST_HYBRID_DECAPS_CT:
    case TEST_HYBRID_DECAPS_REJECT:
        if (class == 0)
            memcpy(slot->bytes, fixed_ciphertext, HYBRID_CIPHERTEXT_BYTES);
        else if (current_test == TEST_HYBRID_DECAPS_REJECT)
            memcpy(slot->bytes, corrupt_ciphertext, HYBRID_CIPHERTEXT_BYTES);
        else if (!hybrid_encapsulate(shared_key, slot->bytes))
            return 0;
        slot->ctx = EVP_PKEY_CTX_new_from_pkey(
            libctx, shared_key, X301_PROPERTIES);
        return slot->ctx != NULL && EVP_PKEY_decapsulate_init(slot->ctx, NULL) > 0;
    default:
        return 0;
    }
}

/* dudect callback: one batch of inputs, class chosen at random per slot. */
void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes)
{
    size_t i;

    for (i = 0; i < c->number_measurements; i++) {
        uint32_t index = (uint32_t)i;

        slot_clear(&slots[i]);
        classes[i] = randombit();
        memcpy(input_data + i * c->chunk_size, &index, sizeof(index));
        if (!prepare_slot(&slots[i], classes[i]))
            prepare_failures++;
    }
}

/* dudect callback: exactly one operation on the prepared slot. */
uint8_t do_one_computation(uint8_t *data)
{
    uint32_t index;
    SLOT *slot;
    size_t length = sizeof(output);
    int ok;

    memcpy(&index, data, sizeof(index));
    slot = &slots[index];
    switch (current_test) {
    case TEST_POSITIVE_CONTROL: {
        uint64_t acc = 0;
        size_t j;

        for (j = 0; j < 8 * X301_BYTES; j++) {
            if ((slot->bytes[j / 8] >> (j % 8)) & 1) {
                acc += (acc ^ j) * 0x9e3779b97f4a7c15ULL;
                acc = (acc << 13) | (acc >> 51);
            }
        }
        sink = acc;
        return 0;
    }
    case TEST_DERIVE_SECRET:
    case TEST_DERIVE_PEER:
        ok = slot->ctx != NULL && EVP_PKEY_derive(slot->ctx, output, &length) > 0;
        break;
    case TEST_IMPORT_PRIVATE:
        slot->key = raw_private(slot->bytes);
        ok = slot->key != NULL;
        break;
    case TEST_HYBRID_DECAPS_CT:
    case TEST_HYBRID_DECAPS_REJECT:
        ok = slot->ctx != NULL
            && EVP_PKEY_decapsulate(slot->ctx, output, &length, slot->bytes,
                   HYBRID_CIPHERTEXT_BYTES) > 0;
        break;
    default:
        ok = 0;
    }
    if (!ok)
        operation_failures++;
    return (uint8_t)ok;
}

/* dudect's own selection of the strongest test with enough measurements. */
static double max_abs_t(dudect_ctx_t *ctx)
{
    return fabs(t_compute(max_test(ctx)));
}

/* Returns dudect's final state; writes max |t| and failure counts. */
static dudect_state_t run_test(
    int test, size_t total_measurements, double *max_t)
{
    dudect_config_t config;
    dudect_ctx_t ctx;
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    size_t batches = total_measurements / BATCH_MEASUREMENTS + 1;
    size_t i;

    current_test = test;
    operation_failures = 0;
    prepare_failures = 0;
    config.chunk_size = CHUNK_SIZE;
    config.number_measurements = BATCH_MEASUREMENTS;
    if (dudect_init(&ctx, &config) != 0)
        return DUDECT_LEAKAGE_FOUND;
    printf("== %s: %zu batches of %u measurements\n", TEST_LABELS[test],
        batches, BATCH_MEASUREMENTS);
    /* The first dudect_main() call is discarded by dudect for warm-up. */
    for (i = 0; i < batches; i++)
        state = dudect_main(&ctx);
    *max_t = max_abs_t(&ctx);
    dudect_free(&ctx);
    for (i = 0; i < BATCH_MEASUREMENTS; i++)
        slot_clear(&slots[i]);
    printf("%-24s max_abs_t=%.2f prepare_failures=%zu "
        "operation_failures=%zu dudect=%s\n",
        TEST_LABELS[test], *max_t, prepare_failures, operation_failures,
        state == DUDECT_LEAKAGE_FOUND ? "LEAKAGE_FOUND" : "NO_LEAKAGE_EVIDENCE");
    return state;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *x301_provider = NULL;
    EVP_PKEY_CTX *gen = NULL;
    size_t total = 100000;
    dudect_state_t states[TEST_COUNT];
    double max_t[TEST_COUNT];
    int test, gating_leak = 0, status = 2;

    if (argc < 2 || argc > 3) {
        fprintf(stderr,
            "usage: %s PROVIDER_MODULE_DIRECTORY [MEASUREMENTS]\n", argv[0]);
        return 2;
    }
    if (argc == 3) {
        char *end = NULL;
        unsigned long long parsed = strtoull(argv[2], &end, 10);

        if (end == NULL || *end != '\0'
                || parsed < 2 * DUDECT_ENOUGH_MEASUREMENTS) {
            fprintf(stderr, "MEASUREMENTS must be an integer >= %d\n",
                2 * DUDECT_ENOUGH_MEASUREMENTS);
            return 2;
        }
        total = (size_t)parsed;
    }

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) <= 0
            || (default_provider = OSSL_PROVIDER_load(libctx, "default")) == NULL
            || (x301_provider = OSSL_PROVIDER_load(libctx, "x301")) == NULL) {
        fprintf(stderr, "cannot load default and x301 providers\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    gen = EVP_PKEY_CTX_new_from_name(libctx, HYBRID_NAME, X301_PROPERTIES);
    if (gen == NULL || EVP_PKEY_keygen_init(gen) <= 0
            || EVP_PKEY_generate(gen, &shared_key) <= 0
            || !hybrid_encapsulate(shared_key, fixed_ciphertext)) {
        fprintf(stderr, "cannot prepare the hybrid key pair\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    memcpy(corrupt_ciphertext, fixed_ciphertext, sizeof(corrupt_ciphertext));
    corrupt_ciphertext[17] ^= 0x40;

    printf("x301_timing_tool=dudect measurements_per_test=%zu "
        "leak_threshold_abs_t=%d\n", total, t_threshold_moderate);
    for (test = 0; test < TEST_COUNT; test++)
        states[test] = run_test(test, total, &max_t[test]);
    if (prepare_failures != 0) {
        fprintf(stderr, "x301_timing=ERROR input preparation failed\n");
        goto done;
    }
    if (states[TEST_POSITIVE_CONTROL] != DUDECT_LEAKAGE_FOUND) {
        printf("x301_timing=INCONCLUSIVE positive_control_max_t=%.2f\n",
            max_t[TEST_POSITIVE_CONTROL]);
        status = 3;
        goto done;
    }
    for (test = TEST_DERIVE_SECRET; test <= TEST_HYBRID_DECAPS_CT; test++)
        gating_leak |= states[test] == DUDECT_LEAKAGE_FOUND;
    printf("x301_timing=%s t1=%.2f t2=%.2f t3=%.2f t4=%.2f "
        "informative_t5=%.2f positive_control=%.2f\n",
        gating_leak ? "LEAK" : "PASS", max_t[TEST_DERIVE_SECRET],
        max_t[TEST_DERIVE_PEER], max_t[TEST_IMPORT_PRIVATE],
        max_t[TEST_HYBRID_DECAPS_CT], max_t[TEST_HYBRID_DECAPS_REJECT],
        max_t[TEST_POSITIVE_CONTROL]);
    status = gating_leak ? 1 : 0;

done:
    OPENSSL_cleanse(output, sizeof(output));
    EVP_PKEY_CTX_free(gen);
    EVP_PKEY_free(shared_key);
    OSSL_PROVIDER_unload(x301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return status;
}
