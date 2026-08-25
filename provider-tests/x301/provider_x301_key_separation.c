/*
 * X301 / Ed301-EdDSA key-domain separation contract tests (H5).
 *
 * Contract sources:
 *   - docs/X301_DRAFT.md section 10 (Ed301 and X301 keys are distinct);
 *   - OpenSSL EVP_PKEY provider matching: an operation is fetched for the
 *     key type and the caller's property query, never by reinterpreting raw
 *     key bytes as a different algorithm;
 *   - RAND_priv_bytes_ex(3): independent provider keygen operations obtain
 *     fresh private material from the application library context.
 *
 * The test intentionally loads only the ordinary Ed301 signature provider,
 * the X301 provider, and OpenSSL's default provider for RAND.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define KEY_BYTES 38U
#define X301_NAME "X301"
#define X301_PROVIDER "x301"
#define X301_PROPERTIES "provider=x301"
#define ED301_NAME "Ed301-EdDSA-draft-00"
#define ED301_PROVIDER "ed301_eddsa_draft00"
#define ED301_PROPERTIES "provider=ed301_eddsa_draft00"

static unsigned int checks;

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

static EVP_PKEY *generate_key(
    OSSL_LIB_CTX *libctx,
    const char *algorithm,
    const char *properties)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(
        libctx, algorithm, properties);
    EVP_PKEY *key = NULL;

    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0
            || EVP_PKEY_generate(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int export_keypair(
    EVP_PKEY *key,
    unsigned char private_bytes[KEY_BYTES],
    unsigned char public_bytes[KEY_BYTES])
{
    size_t private_length = KEY_BYTES;
    size_t public_length = KEY_BYTES;

    return key != NULL
        && EVP_PKEY_get_raw_private_key(
            key, private_bytes, &private_length) > 0
        && private_length == KEY_BYTES
        && EVP_PKEY_get_raw_public_key(
            key, public_bytes, &public_length) > 0
        && public_length == KEY_BYTES;
}

static int ed301_local_key_rejected_by_x301_keyexch(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *ed301_key)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, ed301_key, X301_PROPERTIES);
    int rejected;

    if (context == NULL) {
        ERR_clear_error();
        return 1;
    }
    rejected = EVP_PKEY_derive_init(context) <= 0;
    EVP_PKEY_CTX_free(context);
    ERR_clear_error();
    return rejected;
}

static int ed301_peer_rejected_by_x301_keyexch(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *x301_key,
    EVP_PKEY *ed301_peer)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(
        libctx, x301_key, X301_PROPERTIES);
    int rejected = context != NULL
        && EVP_PKEY_derive_init(context) > 0
        && EVP_PKEY_derive_set_peer(context, ed301_peer) <= 0;

    EVP_PKEY_CTX_free(context);
    ERR_clear_error();
    return rejected;
}

static int x301_key_rejected_by_ed301_signature(
    OSSL_LIB_CTX *libctx,
    EVP_PKEY *x301_key)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pkey_context = NULL;
    int rejected = context != NULL
        && EVP_DigestSignInit_ex(context, &pkey_context, NULL, libctx,
            ED301_PROPERTIES, x301_key, NULL) <= 0;

    EVP_MD_CTX_free(context);
    ERR_clear_error();
    return rejected;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *ed301_provider = NULL;
    OSSL_PROVIDER *x301_provider = NULL;
    EVP_PKEY *x301_a = NULL;
    EVP_PKEY *x301_b = NULL;
    EVP_PKEY *ed301_a = NULL;
    EVP_PKEY *ed301_b = NULL;
    unsigned char x301_a_private[KEY_BYTES];
    unsigned char x301_a_public[KEY_BYTES];
    unsigned char x301_b_private[KEY_BYTES];
    unsigned char x301_b_public[KEY_BYTES];
    unsigned char ed301_a_private[KEY_BYTES];
    unsigned char ed301_a_public[KEY_BYTES];
    unsigned char ed301_b_private[KEY_BYTES];
    unsigned char ed301_b_public[KEY_BYTES];
    int success = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s PROVIDER_MODULE_DIRECTORY\n", argv[0]);
        return 2;
    }

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) <= 0
            || (default_provider = OSSL_PROVIDER_load(
                    libctx, "default")) == NULL
            || (ed301_provider = OSSL_PROVIDER_load(
                    libctx, ED301_PROVIDER)) == NULL
            || (x301_provider = OSSL_PROVIDER_load(
                    libctx, X301_PROVIDER)) == NULL) {
        fail("H5 load default, ordinary Ed301 and X301 providers");
        goto done;
    }
    pass("H5 load default, ordinary Ed301 and X301 providers");

    x301_a = generate_key(libctx, X301_NAME, X301_PROPERTIES);
    x301_b = generate_key(libctx, X301_NAME, X301_PROPERTIES);
    ed301_a = generate_key(libctx, ED301_NAME, ED301_PROPERTIES);
    ed301_b = generate_key(libctx, ED301_NAME, ED301_PROPERTIES);
    if (x301_a == NULL || x301_b == NULL
            || ed301_a == NULL || ed301_b == NULL
            || !export_keypair(
                x301_a, x301_a_private, x301_a_public)
            || !export_keypair(
                x301_b, x301_b_private, x301_b_public)
            || !export_keypair(
                ed301_a, ed301_a_private, ed301_a_public)
            || !export_keypair(
                ed301_b, ed301_b_private, ed301_b_public)) {
        fail("H5 independent X301 and Ed301 keygens export 38-byte keypairs");
        goto done;
    }
    pass("H5 independent X301 and Ed301 keygens export 38-byte keypairs");

    if (memcmp(x301_a_private, x301_b_private, KEY_BYTES) == 0
            || memcmp(x301_a_public, x301_b_public, KEY_BYTES) == 0) {
        fail("H5 separate X301 keygens produce distinct keys");
        goto done;
    }
    pass("H5 separate X301 keygens produce distinct keys");

    if (memcmp(ed301_a_private, ed301_b_private, KEY_BYTES) == 0
            || memcmp(ed301_a_public, ed301_b_public, KEY_BYTES) == 0) {
        fail("H5 separate Ed301 keygens produce distinct keys");
        goto done;
    }
    pass("H5 separate Ed301 keygens produce distinct keys");

    if (memcmp(x301_a_private, ed301_a_private, KEY_BYTES) == 0
            || EVP_PKEY_eq(x301_a, ed301_a) == 1) {
        fail("H5 Ed301 and X301 key domains remain distinct");
        goto done;
    }
    pass("H5 Ed301 and X301 key domains remain distinct");

    if (!ed301_local_key_rejected_by_x301_keyexch(libctx, ed301_a)) {
        fail("H5 Ed301 local key is rejected by X301 KEYEXCH");
        goto done;
    }
    pass("H5 Ed301 local key is rejected by X301 KEYEXCH");

    if (!ed301_peer_rejected_by_x301_keyexch(
            libctx, x301_a, ed301_a)) {
        fail("H5 Ed301 peer key is rejected by X301 KEYEXCH");
        goto done;
    }
    pass("H5 Ed301 peer key is rejected by X301 KEYEXCH");

    if (!x301_key_rejected_by_ed301_signature(libctx, x301_a)) {
        fail("H5 X301 key is rejected by Ed301 SIGNATURE");
        goto done;
    }
    pass("H5 X301 key is rejected by Ed301 SIGNATURE");

    success = 1;
    printf("provider_x301_key_separation_pass=1 checks=%u\n", checks);

done:
    OPENSSL_cleanse(x301_a_private, sizeof(x301_a_private));
    OPENSSL_cleanse(x301_b_private, sizeof(x301_b_private));
    OPENSSL_cleanse(ed301_a_private, sizeof(ed301_a_private));
    OPENSSL_cleanse(ed301_b_private, sizeof(ed301_b_private));
    OPENSSL_cleanse(x301_a_public, sizeof(x301_a_public));
    OPENSSL_cleanse(x301_b_public, sizeof(x301_b_public));
    OPENSSL_cleanse(ed301_a_public, sizeof(ed301_a_public));
    OPENSSL_cleanse(ed301_b_public, sizeof(ed301_b_public));
    EVP_PKEY_free(ed301_b);
    EVP_PKEY_free(ed301_a);
    EVP_PKEY_free(x301_b);
    EVP_PKEY_free(x301_a);
    OSSL_PROVIDER_unload(x301_provider);
    OSSL_PROVIDER_unload(ed301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return success ? 0 : 1;
}
