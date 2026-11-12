/* dnsprobe.c — DoH/DoT/DoQ с проверкой ответа и обходом блокировки имени.
 *
 * Почему именно так:
 *  - запрос собирается по RFC 1035, id случайный, вопрос проверяется обратно;
 *  - ответ обязан быть на НАШ вопрос, а не «любой пакет с порта»;
 *  - имя можно предъявить тремя способами: как есть, с точкой на конце и
 *    вовсе без SNI. Точка — законная форма FQDN, и сервер, нормализующий имя,
 *    принимает её; пословный фильтр при этом видит другое имя;
 *  - без SNI сервер отдаёт сертификат по умолчанию, а ответ всё равно
 *    проверяется по id/вопросу. Это не проверка цепочки доверия, а измерение.
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_dnsprobe.h"
#include "d2k_tls12.h"
#include "d2k_tls13.h"
#include "d2k_tls13core.h"
#ifdef D2K_DNS_HAVE_DOQ
#include "d2k_quicconn.h"
#endif

#define DNS_HDR 12
#define DNS_MAX_MSG 65535
#define DNS_HTTP_MAX (256 * 1024)

static int64_t mono_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

const char *d2k_dns_status_name(d2k_dns_status s)
{
    switch (s) {
    case D2K_DNS_OK: return "ok";
    case D2K_DNS_NXDOMAIN: return "nxdomain";
    case D2K_DNS_SPOOF: return "spoof";
    case D2K_DNS_MALFORMED: return "malformed";
    case D2K_DNS_IO: return "io";
    case D2K_DNS_SUBSTITUTED: return "substituted";
    default: return "unknown";
    }
}

int d2k_dns_result_has(const d2k_dns_result *r, const char *addr)
{
    if (!r || !addr) { return 0; }
    for (int i = 0; i < r->answers && i < D2K_DNS_ADDR_MAX; i++) {
        if (strcmp(r->addr[i], addr) == 0) { return 1; }
    }
    return 0;
}

const char *d2k_dns_sni_name(d2k_dns_sni s)
{
    switch (s) {
    case D2K_DNS_SNI_CANON: return "canon";
    case D2K_DNS_SNI_DOT: return "dot";
    case D2K_DNS_SNI_NONE: return "none";
    default: return "?";
    }
}

const char *d2k_dns_proto_name(d2k_dns_proto p)
{
    switch (p) {
    case D2K_DNS_PROTO_DOH: return "doh";
    case D2K_DNS_PROTO_DOT: return "dot";
    case D2K_DNS_PROTO_DOQ: return "doq";
    case D2K_DNS_PROTO_PLAIN: return "plain";
    default: return "?";
    }
}

static int label_ok(const char *p, size_t n)
{
    if (n == 0 || n > 63) { return 0; }
    if (p[0] == '-' || p[n - 1] == '-') { return 0; }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-')) { return 0; }
    }
    return 1;
}

size_t d2k_dns_query_build(uint8_t *out, size_t cap, uint16_t id,
                           const char *name, uint16_t type)
{
    if (!out || !name || !name[0]) { return 0; }
    if (cap < DNS_HDR + 1 + 4) { return 0; }
    size_t n = strlen(name);
    while (n > 0 && name[n - 1] == '.') { n--; }
    if (n == 0 || n > 253) { return 0; }

    memset(out, 0, DNS_HDR);
    out[0] = (uint8_t)(id >> 8);
    out[1] = (uint8_t)id;
    out[2] = 0x01; /* RD */
    out[4] = 0x00; out[5] = 0x01; /* QDCOUNT=1 */
    size_t o = DNS_HDR;

    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && name[j] != '.') { j++; }
        size_t l = j - i;
        if (!label_ok(name + i, l)) { return 0; }
        if (o + 1 + l + 5 > cap) { return 0; }
        out[o++] = (uint8_t)l;
        memcpy(out + o, name + i, l);
        o += l;
        i = j;
        if (i < n) { i++; } /* точка */
    }
    if (o + 5 > cap) { return 0; }
    out[o++] = 0;
    out[o++] = (uint8_t)(type >> 8);
    out[o++] = (uint8_t)type;
    out[o++] = 0x00; out[o++] = 0x01; /* IN */
    return o;
}

static int read_name(const uint8_t *msg, size_t len, size_t *off, char *out, size_t cap,
                     int *compressed)
{
    size_t o = *off;
    size_t w = 0;
    int jumped = 0;
    size_t hops = 0;
    while (o < len) {
        uint8_t l = msg[o];
        if ((l & 0xC0) == 0xC0) {
            if (o + 1 >= len) { return -1; }
            size_t p = ((size_t)(l & 0x3F) << 8) | msg[o + 1];
            if (!jumped) { *off = o + 2; }
            jumped = 1;
            if (p >= len || ++hops > 32) { return -1; }
            o = p;
            continue;
        }
        if (l & 0xC0) { return -1; }
        o++;
        if (l == 0) {
            if (!jumped) { *off = o; }
            if (w == 0) { out[0] = '\0'; return 0; }
            out[w - 1] = '\0';
            if (compressed) { *compressed = jumped; }
            return 0;
        }
        if (o + l > len || w + l + 2 > cap) { return -1; }
        memcpy(out + w, msg + o, l);
        w += l;
        out[w++] = '.';
        o += l;
    }
    return -1;
}

static int name_eq(const char *a, const char *b, int exact)
{
    size_t na = strlen(a), nb = strlen(b);
    while (na > 0 && a[na - 1] == '.') { na--; }
    while (nb > 0 && b[nb - 1] == '.') { nb--; }
    if (na != nb) { return 0; }
    if (exact) { return memcmp(a, b, na) == 0; }
    return strncasecmp(a, b, na) == 0;
}

d2k_dns_status d2k_dns_answer_check(const uint8_t *msg, size_t len,
                                    uint16_t id, const char *name, uint16_t type,
                                    int exact_case, d2k_dns_result *res)
{
    if (res) {
        res->id = id;
        res->status = D2K_DNS_MALFORMED;
        res->rcode = 0;
        res->answers = 0;
        res->err[0] = '\0';
        for (int i = 0; i < D2K_DNS_ADDR_MAX; i++) { res->addr[i][0] = '\0'; }
    }
    if (!msg || len < DNS_HDR || !name) { return D2K_DNS_MALFORMED; }
    if (((uint16_t)msg[0] << 8 | msg[1]) != id) {
        if (res) { res->status = D2K_DNS_SPOOF; snprintf(res->err, sizeof res->err, "чужой id"); }
        return D2K_DNS_SPOOF;
    }
    if (!(msg[2] & 0x80)) { /* QR */
        if (res) { snprintf(res->err, sizeof res->err, "не ответ (QR=0)"); }
        return D2K_DNS_MALFORMED;
    }
    if (msg[2] & 0x02) { /* TC */
        if (res) { snprintf(res->err, sizeof res->err, "ответ усечён (TC)"); }
        return D2K_DNS_MALFORMED;
    }
    int rcode = msg[3] & 0x0F;
    if (rcode == 3) {
        if (res) { res->status = D2K_DNS_NXDOMAIN; res->rcode = 3; }
        return D2K_DNS_NXDOMAIN;
    }
    if (rcode != 0) {
        if (res) { res->rcode = rcode; snprintf(res->err, sizeof res->err, "rcode=%d", rcode); }
        return D2K_DNS_MALFORMED;
    }
    int qd = ((int)msg[4] << 8) | msg[5];
    int an = ((int)msg[6] << 8) | msg[7];
    if (qd < 1) {
        if (res) { snprintf(res->err, sizeof res->err, "нет вопроса"); }
        return D2K_DNS_MALFORMED;
    }
    size_t off = DNS_HDR;
    char qname[D2K_DNS_NAME_MAX];
    if (read_name(msg, len, &off, qname, sizeof qname, NULL) != 0) {
        if (res) { snprintf(res->err, sizeof res->err, "вопрос не разобрался"); }
        return D2K_DNS_MALFORMED;
    }
    if (off + 4 > len) {
        if (res) { snprintf(res->err, sizeof res->err, "вопрос обрезан"); }
        return D2K_DNS_MALFORMED;
    }
    uint16_t qt = (uint16_t)((msg[off] << 8) | msg[off + 1]);
    uint16_t qc = (uint16_t)((msg[off + 2] << 8) | msg[off + 3]);
    off += 4;
    if (!name_eq(qname, name, exact_case) || qt != type || qc != 1) {
        if (res) {
            res->status = D2K_DNS_SPOOF;
            snprintf(res->err, sizeof res->err, "чужой вопрос: %.180s type=%u class=%u",
                     qname, (unsigned)qt, (unsigned)qc);
        }
        return D2K_DNS_SPOOF;
    }

    int found = 0;
    for (int k = 0; k < an && off < len; k++) {
        char owner[D2K_DNS_NAME_MAX];
        if (read_name(msg, len, &off, owner, sizeof owner, NULL) != 0) { break; }
        if (off + 10 > len) { break; }
        uint16_t at = (uint16_t)((msg[off] << 8) | msg[off + 1]);
        uint16_t ac = (uint16_t)((msg[off + 2] << 8) | msg[off + 3]);
        uint16_t rdlen = (uint16_t)((msg[off + 8] << 8) | msg[off + 9]);
        off += 10;
        if (off + rdlen > len) { break; }
        if (ac == 1 && at == 1 && rdlen == 4) {
            char ip[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, msg + off, ip, sizeof ip)) {
                if (res && found < D2K_DNS_ADDR_MAX) {
                    snprintf(res->addr[found], sizeof res->addr[0], "%s", ip);
                }
                found++;
            }
        } else if (ac == 1 && at == 28 && rdlen == 16) {
            char ip[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, msg + off, ip, sizeof ip)) {
                if (res && found < D2K_DNS_ADDR_MAX) {
                    snprintf(res->addr[found], sizeof res->addr[0], "%s", ip);
                }
                found++;
            }
        }
        off += rdlen;
    }
    if (res) { res->answers = found; }
    if (found == 0) {
        if (res) { snprintf(res->err, sizeof res->err, "нет A/AAAA в ответе"); }
        return D2K_DNS_NXDOMAIN;
    }
    if (res) { res->status = D2K_DNS_OK; }
    return D2K_DNS_OK;
}

static int tcp_connect(const char *host, const char *ip, uint16_t port, int timeout_ms,
                       uint32_t mark, char *err, size_t cap)
{
    struct addrinfo hints, *ai = NULL, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;
    char port_s[8];
    snprintf(port_s, sizeof port_s, "%u", (unsigned)port);
    const char *node = ip ? ip : host;
    if (!node) { snprintf(err, cap, "нет адреса"); return -1; }
    if (getaddrinfo(node, port_s, &hints, &ai) != 0) {
        hints.ai_flags = 0;
        if (getaddrinfo(node, port_s, &hints, &ai) != 0) {
            snprintf(err, cap, "адрес %s не разобрался", node);
            return -1;
        }
    }
    int fd = -1;
    for (p = ai; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) { continue; }
#ifdef SO_MARK
        if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof mark) != 0) {
            snprintf(err, cap, "SO_MARK: %s", strerror(errno));
            close(fd); fd = -1; continue;
        }
#else
        (void)mark;
#endif
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) { (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK); }
        int rc = connect(fd, p->ai_addr, p->ai_addrlen);
        if (rc != 0 && errno == EINPROGRESS) {
            struct pollfd pp = {fd, POLLOUT, 0};
            int pr;
            do { pr = poll(&pp, 1, timeout_ms); } while (pr < 0 && errno == EINTR);
            if (pr == 0) { snprintf(err, cap, "connect timeout"); close(fd); fd = -1; continue; }
            int so = 0; socklen_t sl = sizeof so;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so, &sl) != 0 || so != 0) {
                snprintf(err, cap, "connect: %s", strerror(so ? so : errno));
                close(fd); fd = -1; continue;
            }
        } else if (rc != 0) {
            snprintf(err, cap, "connect: %s", strerror(errno));
            close(fd); fd = -1; continue;
        }
        if (fl >= 0) { (void)fcntl(fd, F_SETFL, fl); }
        break;
    }
    freeaddrinfo(ai);
    return fd;
}

static const char *sni_for(const d2k_dns_opts *o, char *buf, size_t cap)
{
    if (o->sni == D2K_DNS_SNI_NONE) { return ""; }
    if (o->sni == D2K_DNS_SNI_DOT) {
        snprintf(buf, cap, "%s.", o->host);
        return buf;
    }
    return o->host;
}

static int tls_open(int fd, const char *sni, int timeout_ms, void **out,
                    int *v13, int *peer_name, char *err, size_t cap)
{
    *v13 = 1;
    d2k_tls *t13 = NULL;
    if (d2k_tls_connect(fd, sni, timeout_ms, 0, &t13, err, cap) == 0) {
        *out = t13;
        *peer_name = d2k_tls_peer_name(t13);
        return 0;
    }
    *v13 = 0;
    d2k_tls12 *t12 = NULL;
    char e2[160];
    if (d2k_tls12_connect(fd, sni, timeout_ms, 0, &t12, e2, sizeof e2) == 0) {
        *out = t12;
        *peer_name = d2k_tls12_peer_name(t12);
        return 0;
    }
    char e1[160];
    snprintf(e1, sizeof e1, "%.150s", err);
    snprintf(err, cap, "TLS 1.3: %s; TLS 1.2: %s", e1, e2);
    return -1;
}

static int tls_write(void *t, int v13, const uint8_t *b, size_t n, char *err, size_t cap)
{
    return v13 ? d2k_tls_write((d2k_tls *)t, b, n, err, cap)
               : d2k_tls12_write((d2k_tls12 *)t, b, n, err, cap);
}

static long tls_read(void *t, int v13, uint8_t *b, size_t n, int wait_ms, char *err, size_t cap)
{
    return v13 ? d2k_tls_read((d2k_tls *)t, b, n, wait_ms, err, cap)
               : d2k_tls12_read((d2k_tls12 *)t, b, n, wait_ms, err, cap);
}

/* Читает ровно n байт прикладных данных. */
static int tls_read_exact(void *t, int v13, uint8_t *b, size_t n, int timeout_ms,
                          char *err, size_t cap)
{
    size_t got = 0;
    int64_t deadline = mono_ms() + timeout_ms;
    while (got < n) {
        int left = (int)(deadline - mono_ms());
        if (left <= 0) { snprintf(err, cap, "read timeout"); return -1; }
        long r = tls_read(t, v13, b + got, n - got, left, err, cap);
        if (r <= 0) { snprintf(err, cap, "read: %s", r == 0 ? "eof" : err); return -1; }
        got += (size_t)r;
    }
    return 0;
}

static int http_response_body(char *buf, size_t len, const uint8_t **body, size_t *blen,
                              char *err, size_t cap)
{
    char *h = strstr(buf, "\r\n\r\n");
    if (!h) { snprintf(err, cap, "нет конца заголовков"); return -1; }
    size_t hlen = (size_t)(h - buf) + 4;
    if (strncmp(buf, "HTTP/1.", 7) != 0) { snprintf(err, cap, "не HTTP-ответ"); return -1; }
    char *sp = strchr(buf, ' ');
    int status = sp ? atoi(sp + 1) : 0;
    if (status != 200) { snprintf(err, cap, "HTTP %d", status); return -1; }
    const char *cl = strcasestr(buf, "\r\nContent-Length:");
    if (cl && (size_t)(cl - buf) < hlen) {
        size_t n = (size_t)strtoul(cl + 17, NULL, 10);
        if (hlen + n <= len) { *body = (const uint8_t *)buf + hlen; *blen = n; return 0; }
        snprintf(err, cap, "тело короче Content-Length");
        return -1;
    }
    *body = (const uint8_t *)buf + hlen;
    *blen = len - hlen;
    return 0;
}

static d2k_dns_status fetch_doh(const d2k_dns_opts *o, const uint8_t *q, size_t qlen,
                                uint16_t id, d2k_dns_result *res)
{
    char err[240] = "";
    uint16_t port = o->port ? o->port : 443;
    int fd = tcp_connect(o->host, o->ip, port, o->timeout_ms ? o->timeout_ms : 6000,
                         o->mark, err, sizeof err);
    if (fd < 0) { snprintf(res->err, sizeof res->err, "%s", err); return D2K_DNS_IO; }
    char snibuf[D2K_DNS_NAME_MAX + 2];
    const char *sni = sni_for(o, snibuf, sizeof snibuf);
    void *t = NULL;
    int v13 = 1;
    if (tls_open(fd, sni, o->timeout_ms ? o->timeout_ms : 6000, &t, &v13,
                 &res->tls_peer_name, err, sizeof err) != 0) {
        snprintf(res->err, sizeof res->err, "%s", err);
        close(fd);
        return D2K_DNS_IO;
    }
    const char *path = o->path && o->path[0] ? o->path : "/dns-query";
    char head[512];
    int hl = snprintf(head, sizeof head,
        "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/dns-message\r\n"
        "Accept: application/dns-message\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        path, o->host, qlen);
    if (hl <= 0 || (size_t)hl + qlen > 2048) {
        snprintf(res->err, sizeof res->err, "запрос не собрался");
        if (v13) { d2k_tls_free((d2k_tls *)t); } else { d2k_tls12_free((d2k_tls12 *)t); }
        close(fd);
        return D2K_DNS_IO;
    }
    uint8_t req[2048];
    memcpy(req, head, (size_t)hl);
    memcpy(req + hl, q, qlen);
    if (tls_write(t, v13, req, (size_t)hl + qlen, err, sizeof err) != 0) {
        snprintf(res->err, sizeof res->err, "%s", err);
        if (v13) { d2k_tls_free((d2k_tls *)t); } else { d2k_tls12_free((d2k_tls12 *)t); }
        close(fd);
        return D2K_DNS_IO;
    }
    char *buf = malloc(DNS_HTTP_MAX);
    if (!buf) {
        snprintf(res->err, sizeof res->err, "нет памяти");
        if (v13) { d2k_tls_free((d2k_tls *)t); } else { d2k_tls12_free((d2k_tls12 *)t); }
        close(fd);
        return D2K_DNS_IO;
    }
    size_t len = 0;
    for (;;) {
        if (len == DNS_HTTP_MAX) { break; }
        long r = tls_read(t, v13, (uint8_t *)buf + len, DNS_HTTP_MAX - len,
                          o->timeout_ms ? o->timeout_ms : 6000, err, sizeof err);
        if (r < 0) { snprintf(res->err, sizeof res->err, "%s", err); break; }
        if (r == 0) { break; }
        len += (size_t)r;
        if (strstr(buf, "\r\n\r\n") && len > 4096) {
            /* Content-Length known: stop early if complete. */
            const uint8_t *b; size_t bl;
            if (http_response_body(buf, len, &b, &bl, err, sizeof err) == 0) {
                if (bl > 0) { break; }
            }
        }
    }
    const uint8_t *body = NULL;
    size_t blen = 0;
    int hr = http_response_body(buf, len, &body, &blen, err, sizeof err);
    d2k_dns_status st;
    if (hr != 0) {
        snprintf(res->err, sizeof res->err, "%s", err);
        st = D2K_DNS_IO;
    } else {
        st = d2k_dns_answer_check(body, blen, id, o->query, 1, o->case_check, res);
        if (st != D2K_DNS_OK && !res->err[0]) {
            snprintf(res->err, sizeof res->err, "%s", d2k_dns_status_name(st));
        }
    }
    free(buf);
    if (v13) { d2k_tls_free((d2k_tls *)t); } else { d2k_tls12_free((d2k_tls12 *)t); }
    close(fd);
    return st;
}

static d2k_dns_status fetch_dot(const d2k_dns_opts *o, const uint8_t *q, size_t qlen,
                                uint16_t id, d2k_dns_result *res)
{
    char err[240] = "";
    uint16_t port = o->port ? o->port : 853;
    int fd = tcp_connect(o->host, o->ip, port, o->timeout_ms ? o->timeout_ms : 6000,
                         o->mark, err, sizeof err);
    if (fd < 0) { snprintf(res->err, sizeof res->err, "%s", err); return D2K_DNS_IO; }
    char snibuf[D2K_DNS_NAME_MAX + 2];
    const char *sni = sni_for(o, snibuf, sizeof snibuf);
    void *t = NULL;
    int v13 = 1;
    if (tls_open(fd, sni, o->timeout_ms ? o->timeout_ms : 6000, &t, &v13,
                 &res->tls_peer_name, err, sizeof err) != 0) {
        snprintf(res->err, sizeof res->err, "%s", err);
        close(fd);
        return D2K_DNS_IO;
    }
    uint8_t framed[2 + DNS_MAX_MSG];
    if (qlen > DNS_MAX_MSG) {
        snprintf(res->err, sizeof res->err, "запрос велик");
        if (v13) { d2k_tls_free((d2k_tls *)t); } else { d2k_tls12_free((d2k_tls12 *)t); }
        close(fd);
        return D2K_DNS_IO;
    }
    framed[0] = (uint8_t)(qlen >> 8);
    framed[1] = (uint8_t)qlen;
    memcpy(framed + 2, q, qlen);
    if (tls_write(t, v13, framed, qlen + 2, err, sizeof err) != 0) {
        snprintf(res->err, sizeof res->err, "%s", err);
        if (v13) { d2k_tls_free((d2k_tls *)t); } else { d2k_tls12_free((d2k_tls12 *)t); }
        close(fd);
        return D2K_DNS_IO;
    }
    uint8_t hdr[2];
    if (tls_read_exact(t, v13, hdr, 2, o->timeout_ms ? o->timeout_ms : 6000,
                       err, sizeof err) != 0) {
        snprintf(res->err, sizeof res->err, "%s", err);
        if (v13) { d2k_tls_free((d2k_tls *)t); } else { d2k_tls12_free((d2k_tls12 *)t); }
        close(fd);
        return D2K_DNS_IO;
    }
    size_t n = ((size_t)hdr[0] << 8) | hdr[1];
    uint8_t *body = malloc(n ? n : 1);
    if (!body) {
        snprintf(res->err, sizeof res->err, "нет памяти");
        if (v13) { d2k_tls_free((d2k_tls *)t); } else { d2k_tls12_free((d2k_tls12 *)t); }
        close(fd);
        return D2K_DNS_IO;
    }
    d2k_dns_status st;
    if (tls_read_exact(t, v13, body, n, o->timeout_ms ? o->timeout_ms : 6000,
                       err, sizeof err) != 0) {
        snprintf(res->err, sizeof res->err, "%s", err);
        st = D2K_DNS_IO;
    } else {
        st = d2k_dns_answer_check(body, n, id, o->query, 1, o->case_check, res);
    }
    free(body);
    if (v13) { d2k_tls_free((d2k_tls *)t); } else { d2k_tls12_free((d2k_tls12 *)t); }
    close(fd);
    return st;
}

static d2k_dns_status fetch_plain(const d2k_dns_opts *o, const uint8_t *q, size_t qlen,
                                  uint16_t id, d2k_dns_result *res)
{
    uint16_t port = o->port ? o->port : 53;
    struct addrinfo hints, *ai = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST;
    char port_s[8];
    snprintf(port_s, sizeof port_s, "%u", (unsigned)port);
    const char *node = o->ip ? o->ip : o->host;
    if (!node || getaddrinfo(node, port_s, &hints, &ai) != 0) {
        snprintf(res->err, sizeof res->err, "адрес %s не разобрался", node ? node : "?");
        return D2K_DNS_IO;
    }
    int fd = socket(ai->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        snprintf(res->err, sizeof res->err, "socket: %s", strerror(errno));
        freeaddrinfo(ai);
        return D2K_DNS_IO;
    }
#ifdef SO_MARK
    if (o->mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &o->mark, sizeof o->mark) != 0) {
        snprintf(res->err, sizeof res->err, "SO_MARK: %s", strerror(errno));
        close(fd); freeaddrinfo(ai);
        return D2K_DNS_IO;
    }
#else
    (void)o->mark;
#endif
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        snprintf(res->err, sizeof res->err, "connect: %s", strerror(errno));
        close(fd); freeaddrinfo(ai);
        return D2K_DNS_IO;
    }
    freeaddrinfo(ai);
    if (send(fd, q, qlen, 0) != (ssize_t)qlen) {
        snprintf(res->err, sizeof res->err, "send: %s", strerror(errno));
        close(fd);
        return D2K_DNS_IO;
    }
    struct pollfd p = {fd, POLLIN, 0};
    int pr;
    int timeout = o->timeout_ms ? o->timeout_ms : 6000;
    do { pr = poll(&p, 1, timeout); } while (pr < 0 && errno == EINTR);
    if (pr == 0) {
        snprintf(res->err, sizeof res->err, "UDP timeout");
        close(fd);
        return D2K_DNS_IO;
    }
    uint8_t buf[DNS_MAX_MSG];
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    close(fd);
    if (n < 0) {
        snprintf(res->err, sizeof res->err, "recv: %s", strerror(errno));
        return D2K_DNS_IO;
    }
    d2k_dns_status st = d2k_dns_answer_check(buf, (size_t)n, id, o->query, 1,
                                             o->case_check, res);
    if (st != D2K_DNS_OK && !res->err[0]) {
        snprintf(res->err, sizeof res->err, "%s", d2k_dns_status_name(st));
    }
    return st;
}

#ifdef D2K_DNS_HAVE_DOQ
static d2k_dns_status fetch_doq(const d2k_dns_opts *o, const uint8_t *q, size_t qlen,
                                uint16_t id, d2k_dns_result *res)
{
    char err[240] = "";
    char snibuf[D2K_DNS_NAME_MAX + 2];
    const char *sni = sni_for(o, snibuf, sizeof snibuf);
    d2k_qc_opts qo;
    memset(&qo, 0, sizeof qo);
    qo.ip = o->ip ? o->ip : o->host;
    qo.port = o->port ? o->port : 853;
    qo.sni = sni;
    qo.alpn = "doq";
    qo.deadline_ms = o->timeout_ms ? o->timeout_ms : 6000;
    qo.mark = o->mark;
    d2k_qc *c = NULL;
    if (d2k_qc_connect(&qo, &c, err, sizeof err) != 0) {
        snprintf(res->err, sizeof res->err, "%s", err);
        return D2K_DNS_IO;
    }
    res->tls_peer_name = d2k_qc_peer_name(c);

    uint8_t *framed = malloc(2 + qlen);
    if (!framed) {
        snprintf(res->err, sizeof res->err, "нет памяти");
        d2k_qc_close(c);
        return D2K_DNS_IO;
    }
    framed[0] = (uint8_t)(qlen >> 8);
    framed[1] = (uint8_t)qlen;
    memcpy(framed + 2, q, qlen);
    if (d2k_qc_stream_send(c, 0, framed, qlen + 2, 1, err, sizeof err) != 0) {
        snprintf(res->err, sizeof res->err, "%s", err);
        free(framed);
        d2k_qc_close(c);
        return D2K_DNS_IO;
    }
    free(framed);

    size_t cap = 2 + DNS_MAX_MSG;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        snprintf(res->err, sizeof res->err, "нет памяти");
        d2k_qc_close(c);
        return D2K_DNS_IO;
    }
    size_t got = 0;
    int64_t deadline = mono_ms() + (o->timeout_ms ? o->timeout_ms : 6000);
    d2k_dns_status st = D2K_DNS_IO;
    for (;;) {
        if (got >= 2) {
            size_t n = ((size_t)buf[0] << 8) | buf[1];
            if (got >= 2 + n) {
                st = d2k_dns_answer_check(buf + 2, n, id, o->query, 1,
                                          o->case_check, res);
                break;
            }
        }
        int left = (int)(deadline - mono_ms());
        if (left <= 0) { snprintf(res->err, sizeof res->err, "DoQ timeout"); break; }
        uint64_t sid = 0;
        long r = d2k_qc_stream_recv(c, &sid, buf + got, cap - got, left, err, sizeof err);
        if (r <= 0) {
            snprintf(res->err, sizeof res->err, "DoQ: %s", r == 0 ? "нет данных" : err);
            break;
        }
        got += (size_t)r;
    }
    free(buf);
    d2k_qc_close(c);
    return st;
}
#endif

d2k_dns_status d2k_dns_fetch(const d2k_dns_opts *o, d2k_dns_result *res)
{
    if (!o || !o->host || !o->query || !res) { return D2K_DNS_IO; }
    memset(res, 0, sizeof *res);
    snprintf(res->host, sizeof res->host, "%s", o->query);
    snprintf(res->ip, sizeof res->ip, "%s", o->ip ? o->ip : "?");
    res->port = o->port ? o->port : (o->proto == D2K_DNS_PROTO_DOH ? 443 : 853);
    res->tls_peer_name = -1;
    res->rtt_ms = -1;
    if (o->proto == D2K_DNS_PROTO_PLAIN) {
        res->port = o->port ? o->port : 53;
    }
    uint8_t idb[2];
    if (d2k_t13_random(idb, sizeof idb) != 0) {
        snprintf(res->err, sizeof res->err, "нет случайности");
        return D2K_DNS_IO;
    }
    uint16_t id = (uint16_t)((idb[0] << 8) | idb[1]);
    res->id = id;
    uint8_t q[512];
    size_t qlen = d2k_dns_query_build(q, sizeof q, id, o->query, 1);
    if (qlen == 0) {
        snprintf(res->err, sizeof res->err, "имя запроса негодно");
        return D2K_DNS_IO;
    }
    int64_t t0 = mono_ms();
    d2k_dns_status st;
    if (o->proto == D2K_DNS_PROTO_DOQ) {
#ifdef D2K_DNS_HAVE_DOQ
        st = fetch_doq(o, q, qlen, id, res);
#else
        snprintf(res->err, sizeof res->err, "DoQ: модуль не подключён в этой сборке");
        st = D2K_DNS_IO;
#endif
    } else if (o->proto == D2K_DNS_PROTO_DOH) {
        st = fetch_doh(o, q, qlen, id, res);
    } else if (o->proto == D2K_DNS_PROTO_DOT) {
        st = fetch_dot(o, q, qlen, id, res);
    } else {
        st = fetch_plain(o, q, qlen, id, res);
    }
    res->rtt_ms = mono_ms() - t0;
    if (st == D2K_DNS_OK && o->expect && !d2k_dns_result_has(res, o->expect)) {
        snprintf(res->err, sizeof res->err, "нет ожидаемого адреса %s", o->expect);
        res->status = D2K_DNS_SUBSTITUTED;
        return D2K_DNS_SUBSTITUTED;
    }
    return st;
}
