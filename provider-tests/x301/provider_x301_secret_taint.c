/* Provider/FFI secret-taint regression. Test-only; run under Valgrind. */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define X301_BYTES 38U
#define MLKEM_BYTES 1568U
#define HYBRID_PUBLIC_BYTES (MLKEM_BYTES + X301_BYTES)
#define HYBRID_SECRET_BYTES 70U
#define X301_NAME "X301"
#define HYBRID_NAME "X301MLKEM1024"
#define X301_PROPERTIES "provider=x301"

extern unsigned int ed301_vg_running_on_valgrind(void);
extern unsigned int ed301_vg_get_vbits(
    const void *address, unsigned char *vbits, size_t length);
extern void ed301_vg_make_mem_defined(void *address, size_t length);

static const unsigned char secret_a[X301_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25
};

static const unsigned char public_b[X301_BYTES] = {
    0x86, 0xa7, 0xfa, 0x2c, 0xcb, 0x11, 0xa7, 0x6c,
    0x34, 0xfd, 0x7b, 0xca, 0x0f, 0x6e, 0x59, 0x2c,
    0x99, 0x91, 0xcb, 0x55, 0x4c, 0xd7, 0xb3, 0x26,
    0xa2, 0x17, 0x7d, 0xf7, 0xdb, 0xb0, 0xf4, 0xc5,
    0x14, 0x38, 0x15, 0x19, 0x92, 0x1d
};

static const unsigned char shared_ab[X301_BYTES] = {
    0x70, 0xa5, 0x4b, 0xeb, 0xec, 0xf4, 0xa6, 0xf6,
    0x8a, 0xa3, 0x0e, 0x6b, 0x08, 0x1d, 0x29, 0xfb,
    0x59, 0xda, 0x71, 0xeb, 0xd6, 0xfb, 0xf3, 0x4f,
    0x14, 0x78, 0x06, 0x50, 0xea, 0x2b, 0xaa, 0x07,
    0x6c, 0x3a, 0xfc, 0x7a, 0x41, 0x11
};

static int consume_tainted_secret(unsigned char *value, size_t length)
{
    unsigned char vbits[HYBRID_SECRET_BYTES] = { 0 };
    size_t index;
    int tainted = 0;

    if (length > sizeof(vbits)
            || ed301_vg_get_vbits(value, vbits, length) != 1U)
        return 0;
    ed301_vg_make_mem_defined(vbits, length);
    for (index = 0; index < length; index++)
        tainted |= vbits[index] != 0;
    ed301_vg_make_mem_defined(value, length);
    return tainted;
}

static EVP_PKEY *hybrid_public_key(
    OSSL_LIB_CTX *libctx, unsigned char public_key[HYBRID_PUBLIC_BYTES])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(
        libctx, HYBRID_NAME, X301_PROPERTIES);
    EVP_PKEY *key = NULL;

    if (ctx == NULL || EVP_PKEY_paramgen_init(ctx) <= 0
            || EVP_PKEY_generate(ctx, &key) <= 0
            || EVP_PKEY_set1_encoded_public_key(
                key, public_key, HYBRID_PUBLIC_BYTES) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL, *x301 = NULL;
    EVP_PKEY *private_key = NULL, *peer = NULL;
    EVP_PKEY *hybrid_private = NULL, *hybrid_public = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char raw_secret[X301_BYTES] = { 0 };
    unsigned char hybrid_public_bytes[HYBRID_PUBLIC_BYTES];
    unsigned char ciphertext[HYBRID_PUBLIC_BYTES];
    unsigned char hybrid_secret_a[HYBRID_SECRET_BYTES] = { 0 };
    unsigned char hybrid_secret_b[HYBRID_SECRET_BYTES] = { 0 };
    unsigned char *encoded_public = NULL;
    size_t length, ciphertext_length, secret_length;
    const char *stage = "arguments";
    int ok = 0;

    if (argc != 2 || ed301_vg_running_on_valgrind() == 0)
        goto done;
    stage = "provider load";
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || !OSSL_PROVIDER_set_default_search_path(libctx, argv[1])
            || (deflt = OSSL_PROVIDER_load(libctx, "default")) == NULL
            || (x301 = OSSL_PROVIDER_load(libctx, "x301")) == NULL)
        goto done;

    stage = "raw X301 derive";
    private_key = EVP_PKEY_new_raw_private_key_ex(
        libctx, X301_NAME, X301_PROPERTIES, secret_a, sizeof(secret_a));
    peer = EVP_PKEY_new_raw_public_key_ex(
        libctx, X301_NAME, X301_PROPERTIES, public_b, sizeof(public_b));
    ctx = private_key == NULL ? NULL
        : EVP_PKEY_CTX_new_from_pkey(libctx, private_key, X301_PROPERTIES);
    length = sizeof(raw_secret);
    if (ctx == NULL || peer == NULL || EVP_PKEY_derive_init(ctx) <= 0
            || EVP_PKEY_derive_set_peer(ctx, peer) <= 0
            || EVP_PKEY_derive(ctx, raw_secret, &length) <= 0
            || length != sizeof(raw_secret)
            || !consume_tainted_secret(raw_secret, length)
            || CRYPTO_memcmp(raw_secret, shared_ab, length) != 0)
        goto done;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    stage = "hybrid key generation";
    hybrid_private = EVP_PKEY_Q_keygen(
        libctx, X301_PROPERTIES, HYBRID_NAME);
    length = hybrid_private == NULL ? 0
        : EVP_PKEY_get1_encoded_public_key(hybrid_private, &encoded_public);
    if (length != HYBRID_PUBLIC_BYTES)
        goto done;
    memcpy(hybrid_public_bytes, encoded_public, length);
    hybrid_public = hybrid_public_key(libctx, hybrid_public_bytes);
    stage = "hybrid encapsulation";
    ctx = hybrid_public == NULL ? NULL
        : EVP_PKEY_CTX_new_from_pkey(libctx, hybrid_public, X301_PROPERTIES);
    ciphertext_length = sizeof(ciphertext);
    secret_length = sizeof(hybrid_secret_a);
    if (ctx == NULL || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0
            || EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_length,
                hybrid_secret_a, &secret_length) <= 0
            || ciphertext_length != sizeof(ciphertext)
            || secret_length != sizeof(hybrid_secret_a)
            || !consume_tainted_secret(hybrid_secret_a, secret_length))
        goto done;
    EVP_PKEY_CTX_free(ctx);
    stage = "hybrid decapsulation";
    ctx = EVP_PKEY_CTX_new_from_pkey(
        libctx, hybrid_private, X301_PROPERTIES);
    secret_length = sizeof(hybrid_secret_b);
    if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
            || EVP_PKEY_decapsulate(ctx, hybrid_secret_b, &secret_length,
                ciphertext, ciphertext_length) <= 0
            || secret_length != sizeof(hybrid_secret_b)
            || !consume_tainted_secret(hybrid_secret_b, secret_length)
            || CRYPTO_memcmp(hybrid_secret_a, hybrid_secret_b,
                secret_length) != 0)
        goto done;
    ok = 1;

done:
    OPENSSL_cleanse(hybrid_secret_b, sizeof(hybrid_secret_b));
    OPENSSL_cleanse(hybrid_secret_a, sizeof(hybrid_secret_a));
    OPENSSL_cleanse(raw_secret, sizeof(raw_secret));
    OPENSSL_free(encoded_public);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(hybrid_public);
    EVP_PKEY_free(hybrid_private);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(private_key);
    OSSL_PROVIDER_unload(x301);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok) {
        puts("provider_x301_secret_taint: PASS");
    } else {
        fprintf(stderr, "provider_x301_secret_taint: FAIL at %s\n", stage);
        ERR_print_errors_fp(stderr);
    }
    return ok ? 0 : 1;
}
