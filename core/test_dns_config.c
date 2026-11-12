#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../runtime/d2k_dns_config.h"

static void write_file(char path[], const char *text) {
    int fd = mkstemp(path);
    assert(fd >= 0);
    size_t n = strlen(text), off = 0;
    while (off < n) {
        ssize_t w = write(fd, text + off, n - off);
        assert(w > 0);
        off += (size_t)w;
    }
    assert(close(fd) == 0);
}

static void test_ten_provider_schemes(void) {
    static const struct { const char *uri, *protocol, *host, *path; unsigned port; } cases[] = {
        {"https://cloudflare-dns.com/dns-query", "doh", "cloudflare-dns.com", "/dns-query", 443},
        {"https://dns.google/dns-query", "doh", "dns.google", "/dns-query", 443},
        {"https://dns.quad9.net/dns-query", "doh", "dns.quad9.net", "/dns-query", 443},
        {"https://dns.adguard-dns.com/dns-query", "doh", "dns.adguard-dns.com", "/dns-query", 443},
        {"https://security.cloudflare-dns.com/dns-query", "doh", "security.cloudflare-dns.com", "/dns-query", 443},
        {"tls://one.one.one.one", "dot", "one.one.one.one", "/", 853},
        {"tls://dns.google", "dot", "dns.google", "/", 853},
        {"tls://dns.quad9.net", "dot", "dns.quad9.net", "/", 853},
        {"quic://dns.adguard-dns.com", "doq", "dns.adguard-dns.com", "/", 853},
        {"quic://p0.freedns.controld.com", "doq", "p0.freedns.controld.com", "/", 853},
    };
    unsigned counts[3] = {0, 0, 0};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        d2k_dns_service s;
        assert(d2k_dns_uri_parse(cases[i].uri, "fixture", &s));
        assert(!strcmp(s.protocol, cases[i].protocol));
        assert(!strcmp(s.host, cases[i].host));
        assert(!strcmp(s.sni, cases[i].host));
        assert(!strcmp(s.path, cases[i].path));
        assert(s.port == cases[i].port);
        counts[s.protocol[2] == 'h' ? 0 : s.protocol[2] == 't' ? 1 : 2]++;
    }
    assert(counts[0] == 5 && counts[1] == 3 && counts[2] == 2);
    d2k_dns_service s;
    assert(d2k_dns_uri_parse("https://resolver.example/custom/path?token=secret", "fixture", &s));
    assert(!strcmp(s.path, "/custom/path?token=secret"));
    assert(d2k_dns_uri_parse("https://[2001:db8::1]:8443/dns", "fixture", &s));
    assert(!strcmp(s.host, "2001:db8::1") && !s.sni[0] && s.port == 8443);
    assert(!d2k_dns_uri_parse("http://plain.example/dns-query", "fixture", &s));
    assert(!d2k_dns_uri_parse("https://bad.example:0/dns-query", "fixture", &s));
    d2k_dns_service mixed[3];
    assert(d2k_dns_uri_parse("https://same.example/dns-query", "fixture", &mixed[0]));
    assert(d2k_dns_uri_parse("tls://same.example:8853", "fixture", &mixed[1]));
    assert(d2k_dns_uri_parse("quic://same.example:8853", "fixture", &mixed[2]));
    assert(d2k_dns_service_match(mixed, 3, "same.example", "192.0.2.1", 443, 6) == &mixed[0]);
    assert(d2k_dns_service_match(mixed, 3, "same.example", "192.0.2.1", 8853, 6) == &mixed[1]);
    assert(d2k_dns_service_match(mixed, 3, "same.example", "192.0.2.1", 8853, 17) == &mixed[2]);
    assert(!d2k_dns_service_match(mixed, 3, "same.example", "192.0.2.1", 443, 17));
}

static void test_router_config_sources(void) {
    char https[] = "/tmp/d2k-dns-https.XXXXXX";
    char proxy[] = "/tmp/d2k-dns-proxy.XXXXXX";
    char doqd[] = "/tmp/d2k-dns-doqd.XXXXXX";
    write_file(https,
        "config https-dns-proxy\n"
        " option bootstrap_dns '1.1.1.1,8.8.8.8'\n"
        " option resolver_url 'https://zero.example/dns-query'\n"
        " option enabled '1'\n"
        "config https-dns-proxy\n"
        " option enabled '0'\n"
        " option resolver_url 'https://disabled.example/dns-query'\n");
    write_file(proxy,
        "config dnsproxy 'global'\n"
        " option enabled '1'\n"
        "config dnsproxy 'servers'\n"
        " list upstream 'tls://dot.example'\n"
        " list upstream 'quic://quic.example'\n");
    write_file(doqd,
        "upstream quic://doqd.example\n"
        "fallback tls://fallback.example\n");
    const char keenetic[] =
        "proxy-tls:\n"
        "  server-tls:\n"
        "    address: 162.159.36.20\n"
        "    port: 853\n"
        "    sni: cloudflare-dns.com\n"
        "proxy-tls-filters:\n"
        "proxy-https:\n"
        "  server-https:\n"
        "    uri: https://gateway.example/dns-query?token=private\n"
        "proxy-https-filters:\n";
    d2k_dns_service items[D2K_DNS_SERVICE_MAX];
    size_t n = 0;
    assert(d2k_dns_services_read(https, proxy, doqd, "keenetic-doq-web",
                                 keenetic, items, D2K_DNS_SERVICE_MAX, &n) == 0);
    assert(n == 7);
    int found_ip_sni = 0, found_path = 0, found_hidden = 0;
    for (size_t i = 0; i < n; i++) {
        if (!strcmp(items[i].host, "162.159.36.20"))
            found_ip_sni = !strcmp(items[i].protocol, "dot") && items[i].port == 853 &&
                           !strcmp(items[i].sni, "cloudflare-dns.com");
        if (!strcmp(items[i].host, "gateway.example"))
            found_path = !strcmp(items[i].path, "/dns-query?token=private");
        if (!strcmp(items[i].host, "zero.example"))
            assert(!strcmp(items[i].bootstrap_dns, "1.1.1.1,8.8.8.8"));
        if (!strcmp(items[i].host, "doqd.example"))
            found_hidden = !strcmp(items[i].source, "keenetic-doq-web");
    }
    assert(found_ip_sni && found_path && found_hidden);
    unlink(https); unlink(proxy); unlink(doqd);
}

static void test_dnsproxy_active_parallel_upstreams(void) {
    char proxy[] = "/tmp/d2k-dns-parallel.XXXXXX";
    write_file(proxy,
        "config dnsproxy 'global'\n"
        " option enabled '1'\n"
        " option upstream_mode 'parallel'\n"
        "config dnsproxy 'servers'\n"
        " list bootstrap '1.1.1.1:53'\n"
        " list bootstrap '1.0.0.1:53'\n"
        " list upstream 'tls://gateway.example'\n"
        " list upstream 'https://gateway.example/dns-query'\n"
        "config profile 'unused'\n"
        " list upstream 'https://inactive.example/dns-query'\n");
    d2k_dns_service items[D2K_DNS_SERVICE_MAX];
    size_t n = 0;
    assert(d2k_dns_services_read(NULL, proxy, NULL, NULL, NULL,
                                 items, D2K_DNS_SERVICE_MAX, &n) == 0);
    assert(n == 2);
    int found_dot = 0, found_doh = 0;
    for (size_t i = 0; i < n; i++) {
        if (!strcmp(items[i].host, "gateway.example")) {
            found_dot |= !strcmp(items[i].protocol, "dot") && items[i].port == 853;
            found_doh |= !strcmp(items[i].protocol, "doh") && items[i].port == 443 &&
                         !strcmp(items[i].path, "/dns-query");
            assert(!strcmp(items[i].bootstrap_dns, "1.1.1.1,1.0.0.1"));
        }
        assert(strcmp(items[i].host, "inactive.example"));
    }
    assert(found_dot && found_doh);
    unlink(proxy);
}

int main(void) {
    test_ten_provider_schemes();
    test_router_config_sources();
    test_dnsproxy_active_parallel_upstreams();
    puts("DNS endpoint discovery: 10 providers and router config sources passed");
    return 0;
}
