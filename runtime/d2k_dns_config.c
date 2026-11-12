#define _POSIX_C_SOURCE 200809L
#include "d2k_dns_config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *skip_space(const char *p) {
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static int safe_host(char *out, size_t cap, const char *in, size_t len) {
    if (!len || len >= cap) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (!(isalnum(c) || c == '.' || c == '-' || c == ':' || c == '%')) return 0;
        out[i] = (char)tolower(c);
    }
    out[len] = '\0';
    return 1;
}

static int host_is_ip(const char *host) {
    uint8_t addr[16];
    if (inet_pton(AF_INET, host, addr) == 1) return 1;
    /* getaddrinfo accepts scoped IPv6 literals; SNI must still be omitted. */
    char copy[D2K_DNS_HOST_MAX];
    snprintf(copy, sizeof copy, "%s", host);
    char *zone = strchr(copy, '%');
    if (zone) *zone = '\0';
    return inet_pton(AF_INET6, copy, addr) == 1;
}

int d2k_dns_uri_parse(const char *uri, const char *source, d2k_dns_service *out) {
    if (!uri || !out) return 0;
    const char *sep = strstr(uri, "://"), *authority, *end, *host, *port_at = NULL;
    unsigned port;
    size_t host_len;
    d2k_dns_service parsed;
    memset(&parsed, 0, sizeof parsed);
    if (!sep) return 0;
    size_t scheme_len = (size_t)(sep - uri);
    if (scheme_len == 5 && !strncasecmp(uri, "https", 5)) {
        memcpy(parsed.protocol, "doh", 4); port = 443;
    } else if (scheme_len == 3 && !strncasecmp(uri, "tls", 3)) {
        memcpy(parsed.protocol, "dot", 4); port = 853;
    } else if (scheme_len == 4 && !strncasecmp(uri, "quic", 4)) {
        memcpy(parsed.protocol, "doq", 4); port = 853;
    } else return 0;
    authority = sep + 3;
    end = strpbrk(authority, "/?#");
    if (!end) end = authority + strlen(authority);
    host = authority;
    for (const char *p = authority; p < end; p++) if (*p == '@') host = p + 1;
    if (host >= end) return 0;
    if (*host == '[') {
        const char *close = memchr(host + 1, ']', (size_t)(end - host - 1));
        if (!close) return 0;
        host++;
        host_len = (size_t)(close - host);
        if (close + 1 < end) {
            if (close[1] != ':') return 0;
            port_at = close + 2;
        }
    } else {
        const char *colon = NULL;
        for (const char *p = host; p < end; p++) if (*p == ':') {
            if (colon) return 0;
            colon = p;
        }
        host_len = (size_t)((colon ? colon : end) - host);
        if (colon) port_at = colon + 1;
    }
    if (!safe_host(parsed.host, sizeof parsed.host, host, host_len)) return 0;
    if (port_at) {
        char *tail = NULL;
        unsigned long v = strtoul(port_at, &tail, 10);
        if (tail == port_at || tail != end || !v || v > 65535) return 0;
        port = (unsigned)v;
    }
    parsed.port = (uint16_t)port;
    if (!host_is_ip(parsed.host)) snprintf(parsed.sni, sizeof parsed.sni, "%s", parsed.host);
    if (parsed.protocol[1] == 'o' && parsed.protocol[2] == 'h') {
        const char *target = end;
        const char *fragment = strchr(target, '#');
        const char *target_end = fragment ? fragment : uri + strlen(uri);
        if (target == target_end) {
            snprintf(parsed.path, sizeof parsed.path, "/");
        } else {
            if (*target == '?') {
                if ((size_t)(target_end - target) + 1 >= sizeof parsed.path) return 0;
                parsed.path[0] = '/';
                memcpy(parsed.path + 1, target, (size_t)(target_end - target));
                parsed.path[target_end - target + 1] = '\0';
            } else {
                size_t n = (size_t)(target_end - target);
                if (!n || n >= sizeof parsed.path || *target != '/') return 0;
                for (size_t i = 0; i < n; i++)
                    if ((unsigned char)target[i] <= 32 || target[i] == '\\' || target[i] == '"') return 0;
                memcpy(parsed.path, target, n);
                parsed.path[n] = '\0';
            }
        }
    } else {
        snprintf(parsed.path, sizeof parsed.path, "/");
    }
    if (source) snprintf(parsed.source, sizeof parsed.source, "%s", source);
    *out = parsed;
    return 1;
}

const d2k_dns_service *d2k_dns_service_match(const d2k_dns_service *items,
                                             size_t count, const char *name,
                                             const char *ip, uint16_t port,
                                             uint8_t transport) {
    if (!items || !port || (transport != 6 && transport != 17)) return NULL;
    for (size_t i = 0; i < count; i++) {
        const d2k_dns_service *s = &items[i];
        int protocol_ok = transport == 17 ? !strcmp(s->protocol, "doq") :
                          !strcmp(s->protocol, "doh") || !strcmp(s->protocol, "dot");
        if (!protocol_ok || s->port != port) continue;
        if ((name && name[0] &&
             ((!strcasecmp(name, s->sni) && s->sni[0]) ||
              (!strcasecmp(name, s->host) && s->host[0]))) ||
            (ip && ip[0] && !strcasecmp(ip, s->host))) return s;
    }
    return NULL;
}

static int config_line(const char *line, char *type, size_t type_cap,
                       char *name, size_t name_cap) {
    const char *p = skip_space(line);
    if (strncmp(p, "config", 6) || (p[6] != ' ' && p[6] != '\t')) return 0;
    p = skip_space(p + 6);
    size_t n = strcspn(p, " \t\r\n");
    if (!n || n >= type_cap) return 0;
    memcpy(type, p, n); type[n] = '\0';
    p = skip_space(p + n);
    if (*p == '\'' || *p == '"') {
        char quote = *p++;
        n = strcspn(p, (char[]){quote, '\0'});
    } else n = strcspn(p, " \t\r\n#");
    if (n >= name_cap) return 0;
    memcpy(name, p, n); name[n] = '\0';
    return 1;
}

static int uci_value(const char *line, const char *verb, const char *key,
                     char *out, size_t cap) {
    const char *p = skip_space(line), *q;
    size_t n = 0;
    if (*p == '#' || !*p) return 0;
    q = p;
    while (*q && *q != ' ' && *q != '\t' && *q != '\r' && *q != '\n') q++;
    if ((size_t)(q - p) != strlen(verb) || strncmp(p, verb, (size_t)(q - p))) return 0;
    p = skip_space(q); q = p;
    while (*q && *q != ' ' && *q != '\t' && *q != '\r' && *q != '\n') q++;
    if ((size_t)(q - p) != strlen(key) || strncmp(p, key, (size_t)(q - p))) return 0;
    p = skip_space(q);
    if (*p == '\'' || *p == '"') {
        char quote = *p++;
        while (*p && *p != quote && *p != '\r' && *p != '\n') {
            if (*p == '\\' && p[1]) p++;
            if (n + 1 >= cap) return 0;
            out[n++] = *p++;
        }
        if (*p != quote) return 0;
    } else {
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n' && *p != '#') {
            if (n + 1 >= cap) return 0;
            out[n++] = *p++;
        }
    }
    out[n] = '\0';
    return n != 0;
}

static void add(d2k_dns_service *items, size_t cap, size_t *count,
                const char *uri, const char *source, const char *bootstrap_dns) {
    d2k_dns_service candidate;
    if (*count >= cap || !d2k_dns_uri_parse(uri, source, &candidate)) return;
    if (bootstrap_dns && strlen(bootstrap_dns) < sizeof candidate.bootstrap_dns)
        snprintf(candidate.bootstrap_dns, sizeof candidate.bootstrap_dns, "%s", bootstrap_dns);
    for (size_t i = 0; i < *count; i++)
        if (!strcmp(items[i].protocol, candidate.protocol) &&
            !strcmp(items[i].host, candidate.host) && items[i].port == candidate.port &&
            !strcmp(items[i].sni, candidate.sni) && !strcmp(items[i].path, candidate.path)) {
            if (!items[i].bootstrap_dns[0] && candidate.bootstrap_dns[0])
                snprintf(items[i].bootstrap_dns, sizeof items[i].bootstrap_dns, "%s", candidate.bootstrap_dns);
            return;
        }
    items[(*count)++] = candidate;
}

static int dns_name_encode(const char *name, uint8_t *out, size_t cap, size_t *used) {
    size_t n = strlen(name), at = 0;
    if (!n || n > 253) return 0;
    for (size_t i = 0; i < n;) {
        size_t end = i;
        while (end < n && name[end] != '.') end++;
        size_t len = end - i;
        if (!len || len > 63 || at + len + 1 >= cap) return 0;
        out[at++] = (uint8_t)len;
        for (size_t j = i; j < end; j++) {
            unsigned char c = (unsigned char)name[j];
            if (!(isalnum(c) || c == '-')) return 0;
            out[at++] = (uint8_t)tolower(c);
        }
        i = end + 1;
        if (end == n) break;
    }
    if (at >= cap) return 0;
    out[at++] = 0;
    *used = at;
    return 1;
}

static int dns_skip_name(const uint8_t *packet, size_t len, size_t *offset) {
    size_t at = *offset, jumps = 0;
    int jumped = 0;
    while (at < len) {
        uint8_t n = packet[at++];
        if (!n) { if (!jumped) *offset = at; return 1; }
        if ((n & 0xc0) == 0xc0) {
            if (at >= len || ++jumps > 16) return 0;
            size_t target = ((size_t)(n & 0x3f) << 8) | packet[at++];
            if (target >= len) return 0;
            if (!jumped) { *offset = at; jumped = 1; }
            at = target;
        } else {
            if ((n & 0xc0) || n > 63 || at + n > len) return 0;
            at += n;
            if (!jumped) *offset = at;
        }
    }
    return 0;
}

static int dns_response_address(const uint8_t *packet, size_t len,
                                uint16_t id, const uint8_t *qname, size_t qname_len,
                                uint16_t qtype, char *ip, size_t ip_cap) {
    if (len < 12 || packet[0] != (uint8_t)(id >> 8) || packet[1] != (uint8_t)id ||
        !(packet[2] & 0x80) || (packet[2] & 0x78) || (packet[2] & 0x02) ||
        (packet[3] & 0x0f) || ((unsigned)packet[4] << 8 | packet[5]) != 1) return 0;
    size_t at = 12;
    if (at + qname_len + 4 > len || memcmp(packet + at, qname, qname_len) ||
        packet[at + qname_len] != (uint8_t)(qtype >> 8) ||
        packet[at + qname_len + 1] != (uint8_t)qtype ||
        packet[at + qname_len + 2] != 0 || packet[at + qname_len + 3] != 1) return 0;
    at += qname_len + 4;
    unsigned answers = (unsigned)packet[6] << 8 | packet[7];
    if (!answers || answers > 128) return 0;
    for (unsigned i = 0; i < answers; i++) {
        if (!dns_skip_name(packet, len, &at) || at + 10 > len) return 0;
        uint16_t type = (uint16_t)((packet[at] << 8) | packet[at + 1]);
        uint16_t klass = (uint16_t)((packet[at + 2] << 8) | packet[at + 3]);
        uint16_t rdlen = (uint16_t)((packet[at + 8] << 8) | packet[at + 9]);
        at += 10;
        if (at + rdlen > len) return 0;
        if (klass == 1 && type == qtype &&
            ((qtype == 1 && rdlen == 4) || (qtype == 28 && rdlen == 16)) &&
            inet_ntop(qtype == 1 ? AF_INET : AF_INET6, packet + at, ip, (socklen_t)ip_cap))
            return 1;
        at += rdlen;
    }
    return 0;
}

static int dns_query_one(const char *host, const char *server, uint16_t qtype,
                         uint32_t mark, char *ip, size_t ip_cap) {
    uint8_t packet[1024] = {0}, qname[256];
    size_t qname_len = 0;
    if (!dns_name_encode(host, qname, sizeof qname, &qname_len)) return 0;
    int family = strchr(server, ':') ? AF_INET6 : AF_INET;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    memset(&peer, 0, sizeof peer);
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&peer;
        v4->sin_family = AF_INET; v4->sin_port = htons(53);
        if (inet_pton(AF_INET, server, &v4->sin_addr) != 1) return 0;
        peer_len = sizeof *v4;
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&peer;
        v6->sin6_family = AF_INET6; v6->sin6_port = htons(53);
        if (inet_pton(AF_INET6, server, &v6->sin6_addr) != 1) return 0;
        peer_len = sizeof *v6;
    }
    uint16_t id = (uint16_t)getpid() ^ (uint16_t)time(NULL) ^ (uint16_t)(uintptr_t)packet;
    packet[0] = (uint8_t)(id >> 8); packet[1] = (uint8_t)id;
    packet[2] = 1; packet[5] = 1;
    memcpy(packet + 12, qname, qname_len);
    size_t qlen = 12 + qname_len;
    packet[qlen++] = (uint8_t)(qtype >> 8); packet[qlen++] = (uint8_t)qtype;
    packet[qlen++] = 0; packet[qlen++] = 1;

    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
#ifdef SO_MARK
    if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof mark) != 0) { close(fd); return 0; }
#else
    if (mark) { close(fd); return 0; }
#endif
    struct timeval timeout = { .tv_sec = 0, .tv_usec = 400000 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) != 0 ||
        connect(fd, (struct sockaddr *)&peer, peer_len) != 0 ||
        send(fd, packet, qlen, 0) != (ssize_t)qlen) { close(fd); return 0; }
    ssize_t got = recv(fd, packet, sizeof packet, 0);
    close(fd);
    return got > 0 && dns_response_address(packet, (size_t)got, id, qname,
                                             qname_len, qtype, ip, ip_cap);
}

int d2k_dns_resolve_bootstrap(const char *host, const char *servers,
                              uint32_t mark, char *ip, size_t ip_cap) {
    if (!host || !*host || !servers || !*servers || !ip || ip_cap < INET_ADDRSTRLEN) return 0;
    ip[0] = '\0';
    uint8_t raw[16];
    if (inet_pton(AF_INET, host, raw) == 1 || inet_pton(AF_INET6, host, raw) == 1)
        return snprintf(ip, ip_cap, "%s", host) < (int)ip_cap;
    char list[D2K_DNS_BOOTSTRAP_MAX];
    if (strlen(servers) >= sizeof list) return 0;
    snprintf(list, sizeof list, "%s", servers);
    char *save = NULL;
    unsigned tried = 0;
    for (char *server = strtok_r(list, ",", &save); server && tried < 2;
         server = strtok_r(NULL, ",", &save), tried++) {
        while (*server == ' ' || *server == '\t') server++;
        char *end = server + strlen(server);
        while (end > server && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) *--end = '\0';
        if (!*server) continue;
        if (dns_query_one(host, server, 1, mark, ip, ip_cap) ||
            dns_query_one(host, server, 28, mark, ip, ip_cap)) return 1;
    }
    return 0;
}

static int file_size_ok(FILE *f) {
    struct stat st;
    return fstat(fileno(f), &st) != 0 || (st.st_size >= 0 && (uint64_t)st.st_size <= D2K_DNS_CONFIG_MAX);
}

static void read_https(const char *path, d2k_dns_service *items, size_t cap, size_t *count) {
    FILE *f = path ? fopen(path, "r") : NULL;
    char line[2048], type[80], name[80], urls[8][1024], value[1024];
    char bootstrap_dns[D2K_DNS_BOOTSTRAP_MAX] = "";
    size_t n_urls = 0;
    int in_section = 0, enabled = 1;
    if (!f) return;
    if (!file_size_ok(f)) { fclose(f); return; }
    while (fgets(line, sizeof line, f)) {
        if (config_line(line, type, sizeof type, name, sizeof name)) {
            if (in_section && enabled)
                for (size_t i = 0; i < n_urls; i++) add(items, cap, count, urls[i], "https-dns-proxy", bootstrap_dns);
            in_section = !strcmp(type, "https-dns-proxy");
            enabled = 1; n_urls = 0; bootstrap_dns[0] = '\0';
        } else if (in_section) {
            if (uci_value(line, "option", "enabled", value, sizeof value)) enabled = strcmp(value, "0") != 0;
            else if (uci_value(line, "option", "bootstrap_dns", value, sizeof value) &&
                     strlen(value) < sizeof bootstrap_dns)
                snprintf(bootstrap_dns, sizeof bootstrap_dns, "%s", value);
            else if (n_urls < sizeof urls / sizeof urls[0] &&
                     uci_value(line, "option", "resolver_url", value, sizeof value))
                snprintf(urls[n_urls++], sizeof urls[0], "%s", value);
        }
    }
    if (in_section && enabled)
        for (size_t i = 0; i < n_urls; i++) add(items, cap, count, urls[i], "https-dns-proxy", bootstrap_dns);
    fclose(f);
}

static int dnsproxy_global(const char *line) {
    char type[80], name[80];
    return config_line(line, type, sizeof type, name, sizeof name) &&
           !strcmp(type, "dnsproxy") && !strcmp(name, "global");
}

static void dnsproxy_bootstrap_add(char *out, size_t cap, const char *value) {
    char host[INET6_ADDRSTRLEN];
    const char *start = value;
    size_t len = strlen(value);
    if (!len) return;
    if (*start == '[') {
        const char *end = strchr(start + 1, ']');
        if (!end || (end[1] && strcmp(end + 1, ":53"))) return;
        start++;
        len = (size_t)(end - start);
    } else {
        const char *colon = strrchr(start, ':');
        if (colon && strchr(start, '.') && !strcmp(colon + 1, "53"))
            len = (size_t)(colon - start);
    }
    if (!len || len >= sizeof host) return;
    memcpy(host, start, len);
    host[len] = '\0';
    uint8_t address[16];
    if (inet_pton(AF_INET, host, address) != 1 &&
        inet_pton(AF_INET6, host, address) != 1) return;
    for (const char *p = out; *p;) {
        const char *end = strchr(p, ',');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (n == len && !memcmp(p, host, len)) return;
        if (!end) break;
        p = end + 1;
    }
    size_t used = strlen(out);
    if (used + (used != 0) + len >= cap) return;
    if (used) out[used++] = ',';
    memcpy(out + used, host, len + 1);
}

static void read_dnsproxy(const char *path, d2k_dns_service *items, size_t cap, size_t *count) {
    FILE *f = path ? fopen(path, "r") : NULL;
    char line[2048], type[80], name[80], value[1024];
    char bootstrap[D2K_DNS_BOOTSTRAP_MAX] = "";
    int enabled = 1, global = 0, servers = 0;
    if (!f) return;
    if (!file_size_ok(f)) { fclose(f); return; }
    while (fgets(line, sizeof line, f)) {
        if (dnsproxy_global(line)) global = 1;
        else if (!strncmp(skip_space(line), "config", 6) && (skip_space(line)[6] == ' ' || skip_space(line)[6] == '\t')) global = 0;
        else if (global && uci_value(line, "option", "enabled", value, sizeof value)) enabled = strcmp(value, "0") != 0;
    }
    if (!enabled) { fclose(f); return; }
    rewind(f);
    while (fgets(line, sizeof line, f)) {
        if (config_line(line, type, sizeof type, name, sizeof name)) {
            servers = !strcmp(type, "dnsproxy") && !strcmp(name, "servers");
            continue;
        }
        if (servers && uci_value(line, "list", "bootstrap", value, sizeof value))
            dnsproxy_bootstrap_add(bootstrap, sizeof bootstrap, value);
    }
    rewind(f);
    while (fgets(line, sizeof line, f)) {
        if (config_line(line, type, sizeof type, name, sizeof name)) {
            servers = !strcmp(type, "dnsproxy") && !strcmp(name, "servers");
            continue;
        }
        if (servers && uci_value(line, "list", "upstream", value, sizeof value))
            add(items, cap, count, value, "dnsproxy", bootstrap);
    }
    fclose(f);
}

static void read_doqd(const char *path, const char *source,
                      d2k_dns_service *items, size_t cap, size_t *count) {
    FILE *f = path ? fopen(path, "r") : NULL;
    char line[2048], uri[1024];
    if (!f) return;
    if (!file_size_ok(f)) { fclose(f); return; }
    while (fgets(line, sizeof line, f)) {
        const char *p = skip_space(line);
        if (strncmp(p, "upstream", 8) && strncmp(p, "fallback", 8)) continue;
        if (p[8] != ' ' && p[8] != '\t') continue;
        p = skip_space(p + 8);
        size_t n = strcspn(p, " \t\r\n#");
        if (!n || n >= sizeof uri) continue;
        memcpy(uri, p, n); uri[n] = '\0';
        if (uri[0] == '\'' || uri[0] == '"') {
            size_t len = strlen(uri);
            if (len < 2 || uri[len - 1] != uri[0]) continue;
            memmove(uri, uri + 1, len - 2); uri[len - 2] = '\0';
        }
        add(items, cap, count, uri, source, NULL);
    }
    fclose(f);
}

static unsigned port_value(const char *s) {
    char *end = NULL;
    unsigned long n = strtoul(s, &end, 10);
    return s[0] && end && *end == '\0' && n > 0 && n <= 65535 ? (unsigned)n : 0;
}

static void add_candidate(d2k_dns_service *items, size_t cap, size_t *count,
                         const d2k_dns_service *candidate) {
    if (!candidate->host[0] || !candidate->port) return;
    for (size_t i = 0; i < *count; i++)
        if (!strcmp(items[i].protocol, candidate->protocol) &&
            !strcmp(items[i].host, candidate->host) && items[i].port == candidate->port &&
            !strcmp(items[i].sni, candidate->sni) && !strcmp(items[i].path, candidate->path)) return;
    if (*count < cap) items[(*count)++] = *candidate;
}

static void read_keenetic(const char *status, d2k_dns_service *items, size_t cap, size_t *count) {
    enum { NONE, TLS, HTTPS } section = NONE, server = NONE;
    d2k_dns_service current;
    char copy[D2K_DNS_CONFIG_MAX + 1], *save = NULL, *line;
    size_t len = status ? strnlen(status, sizeof copy) : 0;
    if (!len || len >= sizeof copy) return;
    memcpy(copy, status, len + 1);
    memset(&current, 0, sizeof current);
#define FLUSH() do { add_candidate(items, cap, count, &current); memset(&current, 0, sizeof current); } while (0)
    for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *p = (char *)skip_space(line), *end;
        size_t n = strlen(p); while (n && (p[n - 1] == ' ' || p[n - 1] == '\t' || p[n - 1] == '\r')) p[--n] = '\0';
        if (!strcmp(p, "proxy-tls:")) { FLUSH(); section = TLS; server = NONE; continue; }
        if (!strcmp(p, "proxy-https:")) { FLUSH(); section = HTTPS; server = NONE; continue; }
        if (!strcmp(p, "proxy-tls-filters:") || !strcmp(p, "proxy-https-filters:")) { FLUSH(); section = NONE; server = NONE; continue; }
        if (!strcmp(p, "server-tls:") && section == TLS) { FLUSH(); strcpy(current.protocol, "dot"); current.port = 853; strcpy(current.path, "/"); strcpy(current.source, "keenetic-system"); server = TLS; continue; }
        if (!strcmp(p, "server-https:") && section == HTTPS) { FLUSH(); strcpy(current.protocol, "doh"); current.port = 443; strcpy(current.path, "/"); strcpy(current.source, "keenetic-system"); server = HTTPS; continue; }
        if (server == NONE) continue;
        if (server == TLS && !strncmp(p, "address:", 8)) {
            p = (char *)skip_space(p + 8); end = p; while (*end && *end != ' ' && *end != '\t') end++;
            if (safe_host(current.host, sizeof current.host, p, (size_t)(end - p))) { if (!host_is_ip(current.host)) strcpy(current.sni, current.host); }
        } else if (server == TLS && !strncmp(p, "port:", 5)) {
            p = (char *)skip_space(p + 5); end = p; while (*end && *end != ' ' && *end != '\t') end++;
            char value[8]; size_t z = (size_t)(end-p); if (z < sizeof value) { memcpy(value,p,z);value[z]='\0';current.port=(uint16_t)port_value(value); }
        } else if (server == TLS && !strncmp(p, "sni:", 4)) {
            p = (char *)skip_space(p + 4); end = p; while (*end && *end != ' ' && *end != '\t') end++;
            (void)safe_host(current.sni, sizeof current.sni, p, (size_t)(end-p));
        } else if (server == HTTPS && !strncmp(p, "uri:", 4)) {
            d2k_dns_service parsed;
            p = (char *)skip_space(p + 4); end = p;
            if (*p == '"' || *p == '\'') { char quote = *p++; end = p; while (*end && *end != quote && *end != '\r' && *end != '\n') end++; }
            else { while (*end && *end != ' ' && *end != '\t' && *end != '\r') end++; }
            char uri[D2K_DNS_PATH_MAX + D2K_DNS_HOST_MAX + 32]; size_t z = (size_t)(end-p);
            if (z && z < sizeof uri) { memcpy(uri,p,z);uri[z]='\0';if(d2k_dns_uri_parse(uri,"keenetic-system",&parsed)) current=parsed; }
        }
    }
    FLUSH();
#undef FLUSH
}

int d2k_dns_services_read(const char *https_dns_proxy_path,
                          const char *dnsproxy_path,
                          const char *doqd_config_path,
                          const char *doqd_source,
                          const char *keenetic_dns_proxy_status,
                          d2k_dns_service *items, size_t cap, size_t *count) {
    if (!items || !count || !cap) return -1;
    *count = 0;
    memset(items, 0, cap * sizeof *items);
    read_https(https_dns_proxy_path, items, cap, count);
    read_dnsproxy(dnsproxy_path, items, cap, count);
    read_doqd(doqd_config_path,
        doqd_source && !strcmp(doqd_source, "keenetic-doq-web") ? "keenetic-doq-web" : "doqd",
        items, cap, count);
    read_keenetic(keenetic_dns_proxy_status, items, cap, count);
    return 0;
}

static int64_t dns_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static const char *ndmc_path(void) {
    static const char *paths[] = { "/usr/bin/ndmc", "/usr/sbin/ndmc",
                                   "/opt/bin/ndmc", "/opt/sbin/ndmc" };
    for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++)
        if (access(paths[i], X_OK) == 0) return paths[i];
    return NULL;
}

static int read_ndmc_status(char *out, size_t cap) {
    const char *path = ndmc_path();
    int pipes[2], flags, eof = 0, done = 0, status = 0;
    size_t used = 0;
    int64_t deadline;
    pid_t pid;
    if (!path || !out || cap < 2 || pipe(pipes) != 0) return -1;
    pid = fork();
    if (pid < 0) { close(pipes[0]); close(pipes[1]); return -1; }
    if (pid == 0) {
        int nullfd;
        close(pipes[0]);
        if (dup2(pipes[1], STDOUT_FILENO) < 0) _exit(126);
        close(pipes[1]);
        nullfd = open("/dev/null", O_WRONLY);
        if (nullfd >= 0) { (void)dup2(nullfd, STDERR_FILENO); if (nullfd > 2) close(nullfd); }
        (void)setenv("LD_LIBRARY_PATH", "", 1);
        execl(path, path, "-c", "show dns-proxy", (char *)NULL);
        _exit(127);
    }
    close(pipes[1]);
    flags = fcntl(pipes[0], F_GETFL, 0);
    if (flags >= 0) (void)fcntl(pipes[0], F_SETFL, flags | O_NONBLOCK);
    deadline = dns_now_ms() + 250;
    while ((!eof || !done) && dns_now_ms() < deadline) {
        struct pollfd pfd = { .fd = pipes[0], .events = POLLIN | POLLHUP };
        (void)poll(&pfd, 1, 20);
        if (pfd.revents & (POLLIN | POLLHUP | POLLERR)) {
            for (;;) {
                if (used + 1 >= cap) { close(pipes[0]); (void)kill(pid, SIGKILL); break; }
                ssize_t n = read(pipes[0], out + used, cap - used - 1);
                if (n > 0) used += (size_t)n;
                else if (n == 0) { eof = 1; break; }
                else if (errno == EINTR) continue;
                else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                else { eof = 1; break; }
            }
            if (used + 1 >= cap) break;
        }
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) done = 1;
        else if (waited < 0 && errno != EINTR) { done = 1; status = 1; }
    }
    close(pipes[0]);
    if (!done) { (void)kill(pid, SIGKILL); while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {} }
    if (!done || !eof || !used || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return -1;
    out[used] = '\0';
    return 0;
}

int d2k_dns_services_read_system(d2k_dns_service *items, size_t cap, size_t *count) {
    char status[D2K_DNS_CONFIG_MAX + 1];
    const char *doqd = access("/etc/openwrt_release", F_OK) == 0
                     ? "/etc/doqd.conf" : "/opt/etc/doqd.conf";
    const char *source = access("/usr/sbin/doq-web", X_OK) == 0 ||
                         access("/opt/sbin/doq-web", X_OK) == 0
                       ? "keenetic-doq-web" : "doqd";
    status[0] = '\0';
    if (ndmc_path() && read_ndmc_status(status, sizeof status) != 0) return -1;
    return d2k_dns_services_read("/etc/config/https-dns-proxy", "/etc/config/dnsproxy",
                                 doqd, source, status, items, cap, count);
}
