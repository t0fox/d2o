#ifndef D2K_TG_ROUTE_DNS_H
#define D2K_TG_ROUTE_DNS_H

#include "tg_listener.h"

#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>

#define TG_ROUTE_DNS_CACHE_MAX 256u
#define TG_ROUTE_DNS_ADDRESS_MAX 8u
#define TG_ROUTE_DNS_DOMAIN_MAX 254u
#define TG_ROUTE_HTTPS_BODY_MAX 49152u

typedef struct tg_route_dns tg_route_dns;
typedef struct tg_cf_domain_pool tg_cf_domain_pool;

typedef int (*tg_route_dns_lookup_fn)(
    void *context, const char *domain,
    tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX],
    size_t *count);

tg_route_dns *tg_route_dns_create(SSL_CTX *tls_context, uint32_t socket_mark,
                                  tg_cf_domain_pool *domain_pool,
                                  tg_route_dns_lookup_fn lookup,
                                  void *context);
void tg_route_dns_destroy(tg_route_dns *cache);
int tg_route_dns_prefetch(tg_route_dns *cache, const char *domain);
/* Prefetch real kwsN / kwsN-1 Cloudflare hosts, not bare base domains. */
void tg_route_dns_prefetch_cf_pool(tg_route_dns *cache,
                                   tg_cf_domain_pool *pool);
int tg_route_dns_resolve(tg_route_dns *cache, const char *domain,
                         tg_listener_destination *out);
int tg_route_dns_parse_response(const uint8_t *response, size_t length,
                                uint16_t expected_id,
                                tg_listener_destination addresses[
                                    TG_ROUTE_DNS_ADDRESS_MAX],
                                size_t *count);
int tg_route_dns_parse_http_response(const uint8_t *response, size_t length,
                                     uint8_t *body, size_t body_capacity,
                                     size_t *body_length);
int tg_route_dns_lookup_now(tg_route_dns *cache, const char *domain,
                            tg_listener_destination addresses[
                                TG_ROUTE_DNS_ADDRESS_MAX],
                            size_t *count);
int tg_route_dns_https_request(
    tg_route_dns *cache, const char *hostname,
    const tg_listener_destination *target, const char *method,
    const char *path, const char *accept, const char *content_type,
    const uint8_t *request_body, size_t request_body_len,
    uint8_t *response_body, size_t response_body_cap,
    size_t *response_body_len);

#endif
