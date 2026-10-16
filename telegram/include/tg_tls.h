#ifndef D2K_TG_TLS_H
#define D2K_TG_TLS_H

#include <openssl/ssl.h>

SSL_CTX *tg_tls_client_context(const char *ca_bundle);
/* Подготавливает проверенный TLS-клиент без выполнения handshake. */
SSL *tg_tls_prepare_client_fd(SSL_CTX *ctx, int fd, const char *hostname,
                              const char *sni);
/* The fd must already be connected to the chosen direct or resolved IP.
 * hostname is still used for SNI and certificate verification. */
SSL *tg_tls_connect_fd(SSL_CTX *ctx, int fd, const char *hostname);
/* Diagnostic control: authenticate hostname even when the wire SNI differs. */
SSL *tg_tls_connect_fd_sni(SSL_CTX *ctx, int fd, const char *hostname, const char *sni);

#endif
