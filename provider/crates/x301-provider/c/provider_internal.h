/*
 * Rust/C provider ABI shared by the raw and TLS hybrid adapters.
 * Source: OpenSSL core_dispatch.h provider contracts; this is an internal,
 * versioned shim interface and not a public X301 key format.
 */

#ifndef X301_PROVIDER_INTERNAL_H
#define X301_PROVIDER_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>

#include "../../ed301-eddsa-provider/c/param_helpers.h"

#define x301_param_get_strict_octet_string ed301d00_param_get_strict_octet_string
#define x301_param_set_optional_int ed301d00_param_set_optional_int
#define x301_param_set_optional_octet_string ed301d00_param_set_optional_octet_string
#define x301_param_set_optional_utf8_ptr ed301d00_param_set_optional_utf8_ptr
#if defined(X301_ENABLE_HYBRID_MLKEM1024)
# include <openssl/evp.h>
#endif

typedef struct x301_rust_api_st {
    uint32_t abi_version;
    size_t struct_size;
    size_t secret_bytes;
    size_t public_bytes;
    size_t shared_bytes;
    void *(*key_new)(void);
    void (*key_free)(void *key);
    int (*key_import)(
        void *key,
        const unsigned char *private_key,
        size_t private_length,
        const unsigned char *public_key,
        size_t public_length);
    int (*key_set_encoded_public)(
        void *key,
        const unsigned char *public_key,
        size_t public_length);
    void *(*key_generate)(
        int (*fill_random)(
            void *callback_context,
            unsigned char *output,
            size_t output_length),
        void *callback_context);
    void *(*key_duplicate)(
        const void *source,
        int include_private,
        int include_public);
    int (*key_has)(
        const void *key,
        int require_private,
        int require_public);
    int (*key_validate)(
        const void *key,
        int validate_private,
        int validate_public);
    int (*key_match)(
        const void *first,
        const void *second,
        int match_private,
        int match_public);
    int (*key_get_private)(
        const void *key,
        unsigned char *output,
        size_t output_length);
    int (*key_get_public)(
        const void *key,
        unsigned char *output,
        size_t output_length);
    void *(*exchange_new)(void);
    void (*exchange_free)(void *exchange);
    void *(*exchange_duplicate)(const void *source);
    int (*exchange_init)(void *exchange, const void *key);
    int (*exchange_set_peer)(void *exchange, const void *peer);
    int (*exchange_derive)(
        const void *exchange,
        unsigned char *output,
        size_t output_length);
    void (*cleanse)(unsigned char *buffer, size_t length);
} X301_RUST_API;

typedef struct x301_provider_context_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    OSSL_FUNC_CRYPTO_zalloc_fn *zalloc;
    OSSL_FUNC_CRYPTO_clear_free_fn *clear_free;
    OSSL_FUNC_core_new_error_fn *new_error;
    OSSL_FUNC_core_set_error_debug_fn *set_error_debug;
    OSSL_FUNC_core_vset_error_fn *vset_error;
    const X301_RUST_API *rust;
} X301_PROVIDER_CONTEXT;

#if defined(X301_ENABLE_HYBRID_MLKEM1024)
extern const OSSL_DISPATCH X301_MLKEM1024_KEYMGMT_DISPATCH[];
extern const OSSL_DISPATCH X301_MLKEM1024_KEM_DISPATCH[];

void *x301_generate_raw_key(X301_PROVIDER_CONTEXT *provider);
#endif

#endif
