#ifndef D2K_DNS_CONFIG_H
#define D2K_DNS_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define D2K_DNS_SERVICE_MAX 32u
#define D2K_DNS_HOST_MAX 256u
#define D2K_DNS_PATH_MAX 1024u
#define D2K_DNS_BOOTSTRAP_MAX 256u
#define D2K_DNS_SOURCE_MAX 32u
#define D2K_DNS_CONFIG_MAX 65536u

typedef struct {
    char protocol[4]; /* doh, dot, doq */
    char host[D2K_DNS_HOST_MAX];
    char sni[D2K_DNS_HOST_MAX];
    char path[D2K_DNS_PATH_MAX]; /* DoH request target; may contain a private query token */
    char bootstrap_dns[D2K_DNS_BOOTSTRAP_MAX]; /* numeric resolver IPs, comma-separated */
    char source[D2K_DNS_SOURCE_MAX];
    uint16_t port;
} d2k_dns_service;

/* Parses https://, tls:// and quic:// URLs without resolving their hostnames. */
int d2k_dns_uri_parse(const char *uri, const char *source, d2k_dns_service *out);

/* Match only an observed encrypted-DNS endpoint. The caller must establish
 * that the flow originates on the router before using this for a search. */
const d2k_dns_service *d2k_dns_service_match(const d2k_dns_service *items,
                                             size_t count, const char *name,
                                             const char *ip, uint16_t port,
                                             uint8_t transport);

/* Read-only discovery shared by d2kc and the panel. */
int d2k_dns_services_read(const char *https_dns_proxy_path,
                          const char *dnsproxy_path,
                          const char *doqd_config_path,
                          const char *doqd_source,
                          const char *keenetic_dns_proxy_status,
                          d2k_dns_service *items, size_t cap, size_t *count);

/* Read the active router's OpenWrt files or bounded Keenetic ndmc output. */
int d2k_dns_services_read_system(d2k_dns_service *items, size_t cap, size_t *count);

/* Resolve a configured endpoint only through its numeric bootstrap DNS list.
 * This never calls the system resolver, so an endpoint cannot depend on itself. */
int d2k_dns_resolve_bootstrap(const char *host, const char *servers,
                              uint32_t mark, char *ip, size_t ip_cap);

#endif
