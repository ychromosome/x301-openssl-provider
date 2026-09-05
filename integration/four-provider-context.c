/* Cross-provider discovery regression. Public OpenSSL APIs only. */

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>

#define ED301_PROVIDER "ed301_eddsa_v1_tls_test"
#define ED301_SIGALG "ed301_eddsa_v1_test"
#define X301_GROUP "X301MLKEM1024"
#define G301_SUITE "G301-AES-256-GCM-V1"

static int has_cipher(const SSL_CTX *ctx, const char *name)
{
    STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ctx);
    int index;

    for (index = 0; index < sk_SSL_CIPHER_num(ciphers); index++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, index);

        if (strcmp(SSL_CIPHER_get_name(cipher), name) == 0)
            return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL, *ed301 = NULL, *x301 = NULL, *g301 = NULL;
    SSL_CTX *client = NULL, *server = NULL;
    int ok = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s MODULE_DIRECTORY\n", argv[0]);
        return 2;
    }
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
            || !OSSL_PROVIDER_set_default_search_path(libctx, argv[1])
            || (deflt = OSSL_PROVIDER_load(libctx, "default")) == NULL
            || (ed301 = OSSL_PROVIDER_load(libctx, ED301_PROVIDER)) == NULL
            || (x301 = OSSL_PROVIDER_load(libctx, "x301")) == NULL
            || (g301 = OSSL_PROVIDER_load(libctx, "g301")) == NULL
            || (client = SSL_CTX_new_ex(
                    libctx, NULL, TLS_client_method())) == NULL
            || (server = SSL_CTX_new_ex(
                    libctx, NULL, TLS_server_method())) == NULL
            || SSL_CTX_set_ciphersuites(client, G301_SUITE) != 1
            || SSL_CTX_set_ciphersuites(server, G301_SUITE) != 1
            || !has_cipher(client, G301_SUITE)
            || !has_cipher(server, G301_SUITE)
            || SSL_CTX_set1_groups_list(client, X301_GROUP) != 1
            || SSL_CTX_set1_groups_list(server, X301_GROUP) != 1
            || SSL_CTX_set1_sigalgs_list(client, ED301_SIGALG) != 1
            || SSL_CTX_set1_sigalgs_list(server, ED301_SIGALG) != 1)
        goto done;
    ok = 1;

done:
    if (!ok)
        ERR_print_errors_fp(stderr);
    SSL_CTX_free(server);
    SSL_CTX_free(client);
    OSSL_PROVIDER_unload(g301);
    OSSL_PROVIDER_unload(x301);
    OSSL_PROVIDER_unload(ed301);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok)
        puts("four_provider_context: PASS");
    return ok ? 0 : 1;
}
