#define _POSIX_C_SOURCE 200809L
#include "tg_tls.h"

#include <arpa/inet.h>
#include <openssl/x509v3.h>
#include <string.h>

SSL_CTX *tg_tls_client_context(const char *ca_bundle) {
    SSL_CTX *ctx;
    if (!ca_bundle || !*ca_bundle) return NULL;
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1 ||
        SSL_CTX_load_verify_locations(ctx, ca_bundle, NULL) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    return ctx;
}

SSL *tg_tls_connect_fd(SSL_CTX *ctx, int fd, const char *hostname) {
    return tg_tls_connect_fd_sni(ctx, fd, hostname, hostname);
}

SSL *tg_tls_prepare_client_fd(SSL_CTX *ctx, int fd, const char *hostname,
                              const char *sni) {
    struct in_addr v4;
    struct in6_addr v6;
    int is_ip, ok;
    SSL *ssl;
    X509_VERIFY_PARAM *param;
    if (!ctx || fd < 0 || !hostname || !*hostname || !sni || !*sni) return NULL;
    is_ip = inet_pton(AF_INET, hostname, &v4) == 1 ||
            inet_pton(AF_INET6, hostname, &v6) == 1;
    ssl = SSL_new(ctx);
    if (!ssl) return NULL;
    param = SSL_get0_param(ssl);
    ok = param && (is_ip ? X509_VERIFY_PARAM_set1_ip_asc(param, hostname) == 1
                         : X509_VERIFY_PARAM_set1_host(param, hostname, 0) == 1);
    if (ok && !is_ip) ok = SSL_set_tlsext_host_name(ssl, sni) == 1;
    if (ok) ok = SSL_set_fd(ssl, fd) == 1;
    if (ok) {
        SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE |
                          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        SSL_set_connect_state(ssl);
        return ssl;
    }
    SSL_free(ssl);
    return NULL;
}

SSL *tg_tls_connect_fd_sni(SSL_CTX *ctx, int fd, const char *hostname,
                           const char *sni) {
    SSL *ssl = tg_tls_prepare_client_fd(ctx, fd, hostname, sni);
    int ok = ssl && SSL_connect(ssl) == 1 &&
             SSL_get_verify_result(ssl) == X509_V_OK;
    if (!ok) { SSL_free(ssl); return NULL; }
    return ssl;
}
