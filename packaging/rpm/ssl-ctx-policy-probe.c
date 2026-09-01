#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/sslerr.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RECORDED_ERRORS 8

static char *
effective_groups(void)
{
    CONF *configuration = NULL;
    char *configuration_file = NULL;
    char *result = NULL;
    const char *groups;
    long error_line = 0;

    configuration_file = CONF_get1_default_config_file();
    if (configuration_file == NULL)
        goto end;
    configuration = NCONF_new(NULL);
    if (configuration == NULL ||
            NCONF_load(configuration, configuration_file, &error_line) <= 0)
        goto end;
    groups = NCONF_get_string(configuration, "crypto_policy", "Groups");
    if (groups == NULL)
        goto end;
    result = OPENSSL_strdup(groups);

end:
    if (result == NULL) {
        if (error_line > 0) {
            fprintf(stderr,
                    "ssl-ctx-policy-probe: cannot read effective Groups at line %ld\n",
                    error_line);
        } else {
            fputs("ssl-ctx-policy-probe: cannot read effective Groups\n",
                  stderr);
        }
    }
    NCONF_free(configuration);
    OPENSSL_free(configuration_file);
    return result;
}

static bool
is_expected_empty_error_stack(const int *libraries, const int *reasons,
                              size_t count, bool overflow)
{
    size_t bad_value_count;
    size_t index;

    if (overflow)
        return false;
    if (count == 1)
        return libraries[0] == ERR_LIB_SSL &&
               reasons[0] == SSL_R_NO_CIPHER_MATCH;

    /*
     * Stock Fedora 43/OpenSSL 3.5 wraps NO_CIPHER_MATCH in two BAD_VALUE
     * entries and ERROR_IN_SYSTEM_DEFAULT_CONFIG.  Fedora 45/OpenSSL 4.0
     * emits four BAD_VALUE entries because its EMPTY policy also supplies
     * empty DTLS protocol bounds.  Match the complete ordered stack: merely
     * accepting these generic reasons would hide malformed Groups or protocol
     * values, which add another BAD_VALUE entry.
     */
#if OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR == 5
    bad_value_count = 2;
#elif OPENSSL_VERSION_MAJOR == 4 && OPENSSL_VERSION_MINOR == 0
    bad_value_count = 4;
#else
    return false;
#endif

    if (count != bad_value_count + 2 || libraries[0] != ERR_LIB_SSL ||
            reasons[0] != SSL_R_NO_CIPHER_MATCH)
        return false;
    for (index = 1; index <= bad_value_count; index++) {
        if (libraries[index] != ERR_LIB_SSL ||
                reasons[index] != SSL_R_BAD_VALUE)
            return false;
    }
    return libraries[count - 1] == ERR_LIB_SSL &&
           reasons[count - 1] == SSL_R_ERROR_IN_SYSTEM_DEFAULT_CONFIG;
}

int
main(int argc, char **argv)
{
    bool allow_no_cipher = false;
    bool print_effective_groups = false;
    const char *expected_groups = NULL;
    char *groups = NULL;
    SSL_CTX *ctx;
    unsigned long error;
    int error_libraries[MAX_RECORDED_ERRORS];
    int error_reasons[MAX_RECORDED_ERRORS];
    size_t error_count = 0;
    bool saw_error = false;
    bool error_overflow = false;
    bool saw_unsupported_config = false;
    bool expected_empty_errors;

    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--allow-no-cipher") == 0) {
            if (allow_no_cipher)
                goto usage;
            allow_no_cipher = true;
        } else if (strcmp(argv[index], "--effective-groups") == 0) {
            if (print_effective_groups || expected_groups != NULL)
                goto usage;
            print_effective_groups = true;
        } else if (strcmp(argv[index], "--expect-groups") == 0) {
            if (expected_groups != NULL || print_effective_groups ||
                    index + 1 >= argc)
                goto usage;
            expected_groups = argv[++index];
        } else {
            goto usage;
        }
    }

    ERR_clear_error();
    ctx = SSL_CTX_new(TLS_method());
    while ((error = ERR_get_error()) != 0) {
        char message[256];
        const int library = ERR_GET_LIB(error);
        const int reason = ERR_GET_REASON(error);

        ERR_error_string_n(error, message, sizeof(message));
        fprintf(stderr, "ssl-ctx-policy-probe: %s\n", message);
        saw_error = true;
        if (error_count < MAX_RECORDED_ERRORS) {
            error_libraries[error_count] = library;
            error_reasons[error_count] = reason;
            error_count++;
        } else {
            error_overflow = true;
        }
        if (library == ERR_LIB_SSL &&
                reason == SSL_R_UNSUPPORTED_CONFIG_VALUE) {
            saw_unsupported_config = true;
        }
    }

    expected_empty_errors =
        allow_no_cipher &&
        is_expected_empty_error_stack(error_libraries, error_reasons,
                                      error_count, error_overflow);

    if (saw_unsupported_config) {
        SSL_CTX_free(ctx);
        fputs("ssl-ctx-policy-probe: unsupported configuration value\n",
              stderr);
        return 3;
    }
    if (OSSL_PROVIDER_available(NULL, "default") != 1 ||
            OSSL_PROVIDER_available(NULL, "x301") != 1) {
        SSL_CTX_free(ctx);
        fputs("ssl-ctx-policy-probe: required provider is unavailable\n",
              stderr);
        return 4;
    }

    if (print_effective_groups || expected_groups != NULL) {
        groups = effective_groups();
        if (groups == NULL) {
            SSL_CTX_free(ctx);
            ERR_clear_error();
            return 5;
        }
        if (expected_groups != NULL && strcmp(groups, expected_groups) != 0) {
            fprintf(stderr,
                    "ssl-ctx-policy-probe: effective Groups mismatch\nexpected: %s\nactual:   %s\n",
                    expected_groups, groups);
            OPENSSL_free(groups);
            SSL_CTX_free(ctx);
            ERR_clear_error();
            return 6;
        }
    }
    if (ctx == NULL) {
        if (expected_empty_errors) {
            if (print_effective_groups)
                printf("effective_groups=%s\n", groups);
            OPENSSL_free(groups);
            fputs("ssl_ctx=NO_CIPHER_MATCH_EXPECTED\n", stdout);
            return EXIT_SUCCESS;
        }
        OPENSSL_free(groups);
        fputs("ssl-ctx-policy-probe: SSL_CTX_new returned NULL\n", stderr);
        return EXIT_FAILURE;
    }
    SSL_CTX_free(ctx);

    if (expected_empty_errors) {
        if (print_effective_groups)
            printf("effective_groups=%s\n", groups);
        OPENSSL_free(groups);
        fputs("ssl_ctx=NO_CIPHER_MATCH_EXPECTED\n", stdout);
        return EXIT_SUCCESS;
    }
    if (saw_error) {
        OPENSSL_free(groups);
        fputs("ssl-ctx-policy-probe: unexpected OpenSSL error queue\n",
              stderr);
        return EXIT_FAILURE;
    }
    if (print_effective_groups)
        printf("effective_groups=%s\n", groups);
    OPENSSL_free(groups);
    fputs("ssl_ctx=PASS\n", stdout);
    return EXIT_SUCCESS;

usage:
    fprintf(stderr,
            "usage: %s [--allow-no-cipher] [--effective-groups | --expect-groups VALUE]\n",
            argv[0]);
    return 2;
}
