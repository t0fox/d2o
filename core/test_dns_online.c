#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "../runtime/d2k_dns_config.h"
#include "include/d2k_verify.h"

static const char *endpoints[] = {
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://dns.adguard-dns.com/dns-query",
    "https://security.cloudflare-dns.com/dns-query",
    "tls://one.one.one.one",
    "tls://dns.google",
    "tls://dns.quad9.net",
    "quic://dns.adguard-dns.com",
    "quic://p0.freedns.controld.com",
};

static int verify(const d2k_dns_service *service, const char *ip,
                  char *reason, size_t reason_cap) {
    d2k_ver_result r;
    if (!strcmp(service->protocol, "doh"))
        r = d2k_verify_doh_on(-1, ip, service->port, service->sni,
                              service->path, 4000, 0);
    else
        r = d2k_verify_dns_on(-1, ip, service->port, service->sni, 4000, 0,
                              !strcmp(service->protocol, "doq") ? 17 : 6,
                              0, NULL, 0);
    int valid = r.level == D2K_VER_APPLICATION && r.dns_reply;
    if (!valid && reason && reason_cap)
        snprintf(reason, reason_cap, "%s (HTTP %d, TLS 0x%04x)", r.reason,
                 r.status, r.negotiated_tls);
    if (r.fd >= 0) d2k_verify_close(&r);
    return valid;
}

int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "--bootstrap")) {
        char ip[INET6_ADDRSTRLEN];
        if (!d2k_dns_resolve_bootstrap(argv[2], argv[3], 0, ip, sizeof ip)) {
            fprintf(stderr, "FAIL bootstrap %s via configured numeric DNS servers\n", argv[2]);
            return 1;
        }
        printf("PASS bootstrap %s -> %s (direct numeric DNS servers)\n", argv[2], ip);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "--ip")) {
        d2k_dns_service service;
        char reason[256] = "DNS response was not confirmed";
        if (!d2k_dns_uri_parse(argv[2], "pinned-online-test", &service) ||
            (inet_pton(AF_INET, argv[3], &(struct in_addr){0}) != 1 &&
             inet_pton(AF_INET6, argv[3], &(struct in6_addr){0}) != 1)) {
            fprintf(stderr, "usage: %s --ip https://host/path IPv4-or-IPv6\n", argv[0]);
            return 2;
        }
        int ok = verify(&service, argv[3], reason, sizeof reason);
        printf("%s %s via %s: %s\n", ok ? "PASS" : "FAIL", service.protocol,
               argv[3], ok ? "actual DNS answer confirmed" : reason);
        return ok ? 0 : 1;
    }
    unsigned passed = 0;
    for (size_t i = 0; i < sizeof endpoints / sizeof endpoints[0]; i++) {
        d2k_dns_service service;
        assert(d2k_dns_uri_parse(endpoints[i], "online-test", &service));
        struct addrinfo hints, *list = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = !strcmp(service.protocol, "doq") ? SOCK_DGRAM : SOCK_STREAM;
        char port[8]; snprintf(port, sizeof port, "%u", service.port);
        if (getaddrinfo(service.host, port, &hints, &list) != 0) {
            fprintf(stderr, "FAIL %s: endpoint name did not resolve\n", service.protocol);
            continue;
        }
        int ok = 0;
        char failure[256] = "no resolved endpoint answered";
        for (struct addrinfo *a = list; a && !ok; a = a->ai_next) {
            char ip[INET6_ADDRSTRLEN];
            const void *src = a->ai_family == AF_INET
                ? (const void *)&((struct sockaddr_in *)a->ai_addr)->sin_addr
                : (const void *)&((struct sockaddr_in6 *)a->ai_addr)->sin6_addr;
            if (!inet_ntop(a->ai_family, src, ip, sizeof ip)) continue;
            ok = verify(&service, ip, failure, sizeof failure);
        }
        freeaddrinfo(list);
        if (ok) {
            passed++;
            printf("PASS %-3s %s: actual DNS answer confirmed\n", service.protocol, service.host);
        } else {
            fprintf(stderr, "FAIL %-3s %s: %s\n", service.protocol, service.host, failure);
        }
    }
    printf("%u/%zu live encrypted-DNS endpoints answered correctly\n", passed,
           sizeof endpoints / sizeof endpoints[0]);
    return passed == sizeof endpoints / sizeof endpoints[0] ? 0 : 1;
}
