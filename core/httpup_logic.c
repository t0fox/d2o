#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "d2k_httpup.h"
#include "d2k_http_reply.h"

typedef struct {
    char host[256];
    char target[2048];
    size_t target_len;
    int safe_method;
} http_request;

static int ascii_alnum(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static int dns_host(const char *s, size_t n) {
    if (!s || n == 0 || n > 253 || s[0] == '.' || s[n - 1] == '.') { return 0; }
    size_t label = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '.') {
            if (label == 0 || label > 63 || s[i - 1] == '-') { return 0; }
            label = 0;
        } else {
            if (!(ascii_alnum(c) || c == '-') || (label == 0 && c == '-')) { return 0; }
            label++;
        }
    }
    return label > 0 && label <= 63 && s[n - 1] != '-';
}

static int host_equal(const char *a, const char *b) {
    size_t an, bn;
    if (!a || !b) { return 0; }
    an = strlen(a); bn = strlen(b);
    if (an && a[an - 1] == '.') { an--; }
    if (bn && b[bn - 1] == '.') { bn--; }
    return an == bn && an != 0 && strncasecmp(a, b, an) == 0;
}

static int known_portal_host(const char *host) {
    for (size_t i = 0; i < 6; i++) {
        if (host_equal(host, d2k_http_portal(i))) { return 1; }
    }
    return 0;
}

static const char *find_crlf(const char *p, const char *end) {
    for (; p + 1 < end; p++) {
        if (p[0] == '\r' && p[1] == '\n') { return p; }
    }
    return NULL;
}

static int parse_request(const char *request, size_t request_len, http_request *out) {
    if (!request || !out || request_len < 16) { return 0; }
    memset(out, 0, sizeof *out);
    const char *end = request + request_len;
    const char *line_end = find_crlf(request, end);
    if (!line_end) { return 0; }

    const char *sp1 = memchr(request, ' ', (size_t)(line_end - request));
    if (!sp1) { return 0; }
    size_t method_len = (size_t)(sp1 - request);
    out->safe_method = (method_len == 3 && memcmp(request, "GET", 3) == 0) ||
                       (method_len == 4 && memcmp(request, "HEAD", 4) == 0);
    if (!out->safe_method) { return 0; }

    const char *target = sp1 + 1;
    const char *sp2 = memchr(target, ' ', (size_t)(line_end - target));
    if (!sp2 || target >= sp2 || *target != '/') { return 0; }
    const char *version = sp2 + 1;
    size_t version_len = (size_t)(line_end - version);
    if (!((version_len == 8 && memcmp(version, "HTTP/1.0", 8) == 0) ||
          (version_len == 8 && memcmp(version, "HTTP/1.1", 8) == 0))) { return 0; }
    out->target_len = (size_t)(sp2 - target);
    if (out->target_len >= sizeof out->target) { return 0; }
    for (size_t i = 0; i < out->target_len; i++) {
        unsigned char c = (unsigned char)target[i];
        if (c <= 0x20 || c == 0x7f || c == '#') { return 0; }
    }
    memcpy(out->target, target, out->target_len);
    out->target[out->target_len] = '\0';

    int host_seen = 0, content_length_seen = 0;
    const char *p = line_end + 2;
    while ((line_end = find_crlf(p, end)) != NULL && line_end != p) {
        const char *colon = memchr(p, ':', (size_t)(line_end - p));
        if (colon && (size_t)(colon - p) == 4 && strncasecmp(p, "Host", 4) == 0) {
            if (host_seen++) { return 0; }
            const char *v = colon + 1;
            while (v < line_end && (*v == ' ' || *v == '\t')) { v++; }
            const char *ve = line_end;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) { ve--; }
            size_t host_len = (size_t)(ve - v);
            if (host_len == 0 || host_len >= sizeof out->host) { return 0; }
            memcpy(out->host, v, host_len);
            out->host[host_len] = '\0';
        } else if (colon && (size_t)(colon - p) == 14 &&
                   strncasecmp(p, "Content-Length", 14) == 0) {
            if (content_length_seen++) { return 0; }
            const char *v = colon + 1;
            while (v < line_end && (*v == ' ' || *v == '\t')) { v++; }
            const char *ve = line_end;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) { ve--; }
            if (ve - v != 1 || *v != '0') { return 0; }
        } else if (colon && (size_t)(colon - p) == 17 &&
                   strncasecmp(p, "Transfer-Encoding", 17) == 0) {
            return 0;
        }
        p = line_end + 2;
    }
    if (!host_seen || !line_end || line_end != p || p + 2 != end) { return 0; }

    /* Only ordinary cleartext port 80 can be safely upgraded. IPv6 literals
       are not keys in the learned name catalog. */
    char *port = strchr(out->host, ':');
    if (port) {
        if (strcmp(port, ":80") != 0) { return 0; }
        *port = '\0';
    }
    size_t host_len = strlen(out->host);
    if (host_len && out->host[host_len - 1] == '.') { out->host[--host_len] = '\0'; }
    return dns_host(out->host, host_len);
}

int d2k_httpup_request_safe(const char *request, size_t request_len) {
    http_request req;
    return parse_request(request, request_len, &req);
}

static int build_redirect(const http_request *req, const char *reason,
                          char *response, size_t response_cap) {
    int written = snprintf(response, response_cap,
        "HTTP/1.1 307 Temporary Redirect\r\n"
        "Location: https://%s%.*s\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "Content-Length: 0\r\n"
        "X-D2K-HTTP-Upgrade: %s\r\n\r\n",
        req->host, (int)req->target_len, req->target, reason);
    if (written < 0 || (size_t)written >= response_cap) { response[0] = '\0'; return 0; }
    return 1;
}

static int portal_marker(const char *host) {
    static const char *const markers[] = {
        "lawfilter", "blockpage", "blocked", "censorship", "access-denied",
        "provider-filter", "megafonpro", "blackhole"
    };
    const char *start = host;
    for (const char *p = host;; p++) {
        if (*p == '.' || *p == '\0') {
            size_t n = (size_t)(p - start);
            for (size_t i = 0; i < sizeof markers / sizeof markers[0]; i++) {
                if (strlen(markers[i]) == n && strncasecmp(start, markers[i], n) == 0) {
                    return 1;
                }
            }
            if (*p == '\0') { break; }
            start = p + 1;
        }
    }
    return 0;
}

static int redirect_location_host(const char *value, size_t len, char *host, size_t cap) {
    const char *scheme = NULL;
    size_t scheme_len = 0;
    if (len >= 7 && strncasecmp(value, "http://", 7) == 0) {
        scheme = value + 7; scheme_len = 7;
    } else if (len >= 8 && strncasecmp(value, "https://", 8) == 0) {
        scheme = value + 8; scheme_len = 8;
    } else { return 0; }
    (void)scheme_len;
    const char *end = value + len;
    const char *authority_end = scheme;
    while (authority_end < end && *authority_end != '/' && *authority_end != '?' &&
           *authority_end != '#' && *authority_end != ':') { authority_end++; }
    size_t n = (size_t)(authority_end - scheme);
    if (n == 0 || n >= cap) { return 0; }
    memcpy(host, scheme, n); host[n] = '\0';
    if (!dns_host(host, n)) { return 0; }
    return 1;
}

/* 1 when the response head is a cross-host 30x to a host with a portal label. */
static int portal_answer(const char *req_host, const char *upstream, size_t upstream_len,
                         char *location_host, size_t location_cap) {
    if (!upstream || upstream_len < 16) { return 0; }
    const char *end = upstream + upstream_len;
    const char *line_end = find_crlf(upstream, end);
    if (!line_end || (size_t)(line_end - upstream) < 13 ||
        memcmp(upstream, "HTTP/1.", 7) != 0 ||
        (upstream[7] != '0' && upstream[7] != '1') || upstream[8] != ' ' ||
        upstream[9] != '3' || upstream[10] != '0' || upstream[12] != ' ' ||
        (upstream[11] != '1' && upstream[11] != '2' && upstream[11] != '3' &&
         upstream[11] != '7' && upstream[11] != '8')) { return 0; }

    int location_seen = 0;
    int known_portal = 0;
    const char *p = line_end + 2;
    while ((line_end = find_crlf(p, end)) != NULL && line_end != p) {
        const char *colon = memchr(p, ':', (size_t)(line_end - p));
        if (colon && (size_t)(colon - p) == 8 && strncasecmp(p, "Location", 8) == 0) {
            if (location_seen++) { return 0; }
            const char *v = colon + 1;
            while (v < line_end && (*v == ' ' || *v == '\t')) { v++; }
            const char *ve = line_end;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) { ve--; }
            if (!redirect_location_host(v, (size_t)(ve - v), location_host,
                                        location_cap)) { return 0; }
            known_portal = known_portal_host(location_host);
        }
        p = line_end + 2;
    }
    return location_seen && line_end && line_end == p &&
           !host_equal(req_host, location_host) &&
           (known_portal || portal_marker(location_host));
}

int d2k_httpup_portal_response(const char *request, size_t request_len,
                               const char *upstream, size_t upstream_len,
                               char *response, size_t response_cap) {
    http_request req;
    char location_host[256];
    if (!response || response_cap == 0) { return 0; }
    response[0] = '\0';
    if (!parse_request(request, request_len, &req) ||
        !portal_answer(req.host, upstream, upstream_len, location_host,
                       sizeof location_host)) { return 0; }
    return build_redirect(&req, "provider-portal", response, response_cap);
}

int d2k_httpup_request_target(const char *request, size_t request_len,
                              char *host, size_t host_cap,
                              char *target, size_t target_cap) {
    http_request req;
    if (!host || !target || host_cap == 0 || target_cap == 0) { return 0; }
    host[0] = target[0] = '\0';
    if (!parse_request(request, request_len, &req) ||
        strlen(req.host) >= host_cap || req.target_len >= target_cap) { return 0; }
    memcpy(host, req.host, strlen(req.host) + 1);
    memcpy(target, req.target, req.target_len + 1);
    return 1;
}

int d2k_httpup_portal_location(const char *host, const char *response, size_t response_len,
                               char *portal, size_t portal_cap) {
    char location_host[256];
    if (!host || !portal || portal_cap == 0) { return 0; }
    portal[0] = '\0';
    if (!portal_answer(host, response, response_len, location_host, sizeof location_host) ||
        strlen(location_host) >= portal_cap) { return 0; }
    memcpy(portal, location_host, strlen(location_host) + 1);
    return 1;
}

size_t d2k_httpup_redirect_https(const char *host, const char *target,
                                 char *response, size_t response_cap) {
    http_request req;
    if (!response || response_cap == 0) { return 0; }
    response[0] = '\0';
    if (!host || !target || strlen(host) >= sizeof req.host ||
        strlen(target) >= sizeof req.target || target[0] != '/') { return 0; }
    memset(&req, 0, sizeof req);
    memcpy(req.host, host, strlen(host) + 1);
    req.target_len = strlen(target);
    memcpy(req.target, target, req.target_len + 1);
    if (!build_redirect(&req, "provider-portal", response, response_cap)) { return 0; }
    return strlen(response);
}
