#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "tg_route_dns.h"

#include "tg_cf_domains.h"
#include "tg_tls.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TG_ROUTE_DNS_TTL_MS 60000u
#define TG_ROUTE_DNS_RETRY_MS 10000u
#define TG_ROUTE_DOH_TIMEOUT_MS 2000u
#define TG_ROUTE_HTTPS_RESPONSE_MAX 65536u

typedef struct {
    char domain[TG_ROUTE_DNS_DOMAIN_MAX];
    tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX];
    size_t address_count;
    size_t next_address;
    uint64_t expires_at_ms;
    uint64_t retry_at_ms;
    int pending;
    int used;
} route_dns_entry;

struct tg_route_dns {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    pthread_t worker;
    route_dns_entry entries[TG_ROUTE_DNS_CACHE_MAX];
    size_t queue[TG_ROUTE_DNS_CACHE_MAX];
    size_t queue_head;
    size_t queue_len;
    int stopping;
    int worker_started;
    tg_route_dns_lookup_fn lookup;
    void *lookup_context;
    SSL_CTX *tls_context;
    tg_cf_domain_pool *domain_pool;
    uint32_t socket_mark;
};

typedef struct {
    const char *host;
    uint8_t address[4];
    int http2;
} doh_endpoint;

static const doh_endpoint doh_endpoints[] = {
    {.host = "d.webshiftvpn.ru", .address = {31, 31, 207, 68}, .http2 = 1},
    {.host = "cloudflare-dns.com", .address = {1, 1, 1, 1}},
    {.host = "dns.google", .address = {8, 8, 8, 8}},
    {.host = "dns.sb", .address = {185, 222, 222, 222}, .http2 = 1}
};

#ifdef TG_ROUTE_DNS_TESTING
size_t tg_route_dns_test_doh_endpoint_count(void) {
    return sizeof(doh_endpoints) / sizeof(doh_endpoints[0]);
}

int tg_route_dns_test_doh_endpoint(size_t index, const char **host,
                                   uint8_t address[4], int *http2) {
    if (index >= sizeof(doh_endpoints) / sizeof(doh_endpoints[0]) || !host ||
        !address || !http2) return -1;
    *host = doh_endpoints[index].host;
    memcpy(address, doh_endpoints[index].address, 4);
    *http2 = doh_endpoints[index].http2;
    return 0;
}
#endif

static int valid_domain(const char *domain);

static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static int ipv4_public(const uint8_t ip[4]) {
    return ip[0] != 0 && ip[0] != 10 && ip[0] != 127 && ip[0] < 224 &&
           !(ip[0] == 100 && (ip[1] & 0xc0u) == 0x40u) &&
           !(ip[0] == 169 && ip[1] == 254) &&
           !(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) &&
           !(ip[0] == 192 && ip[1] == 168) &&
           !(ip[0] == 192 && ip[1] == 0 && ip[2] == 0) &&
           !(ip[0] == 192 && ip[1] == 0 && ip[2] == 2) &&
           !(ip[0] == 192 && ip[1] == 88 && ip[2] == 99) &&
           !(ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)) &&
           !(ip[0] == 198 && ip[1] == 51 && ip[2] == 100) &&
           !(ip[0] == 203 && ip[1] == 0 && ip[2] == 113);
}

static int public_target(const tg_listener_destination *target) {
    if (target->family == AF_INET) return ipv4_public(target->address);
    if (target->family != AF_INET6) return 0;
    static const uint8_t mapped_prefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
    };
    if (memcmp(target->address, mapped_prefix, sizeof(mapped_prefix)) == 0)
        return ipv4_public(target->address + 12);
    static const uint8_t zero[16] = {0};
    return (target->address[0] & 0xe0u) == 0x20u &&
           memcmp(target->address, zero, sizeof(zero)) != 0 &&
           !(memcmp(target->address, zero, 15) == 0 && target->address[15] == 1) &&
           (target->address[0] & 0xfeu) != 0xfcu &&
           target->address[0] != 0xffu &&
           !(target->address[0] == 0xfeu &&
             (target->address[1] & 0xc0u) == 0x80u) &&
           !(target->address[0] == 0x20u && target->address[1] == 0x01u &&
             target->address[2] <= 0x01u) &&
           !(target->address[0] == 0x20u && target->address[1] == 0x02u) &&
           !(target->address[0] == 0x20u && target->address[1] == 0x01u &&
             target->address[2] == 0x0du && target->address[3] == 0xb8u);
}

static int system_lookup(void *context, const char *domain,
                         tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX],
                         size_t *count) {
    (void)context;
    struct addrinfo hints = {.ai_family = AF_UNSPEC,
                             .ai_socktype = SOCK_STREAM,
                             .ai_protocol = IPPROTO_TCP};
    struct addrinfo *results = NULL;
    if (!domain || !count || getaddrinfo(domain, "443", &hints, &results) != 0)
        return -1;
    *count = 0;
    for (struct addrinfo *item = results; item &&
         *count < TG_ROUTE_DNS_ADDRESS_MAX; item = item->ai_next) {
        tg_listener_destination target = {.port = 443};
        if (item->ai_family == AF_INET &&
            item->ai_addrlen >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *address =
                (const struct sockaddr_in *)item->ai_addr;
            target.family = AF_INET;
            memcpy(target.address, &address->sin_addr, sizeof(address->sin_addr));
        } else if (item->ai_family == AF_INET6 &&
                   item->ai_addrlen >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *address =
                (const struct sockaddr_in6 *)item->ai_addr;
            target.family = AF_INET6;
            memcpy(target.address, &address->sin6_addr, sizeof(address->sin6_addr));
        } else {
            continue;
        }
        if (!public_target(&target)) continue;
        int duplicate = 0;
        for (size_t i = 0; i < *count; ++i)
            if (addresses[i].family == target.family &&
                memcmp(addresses[i].address, target.address,
                       target.family == AF_INET ? 4u : 16u) == 0)
                duplicate = 1;
        if (!duplicate) addresses[(*count)++] = target;
    }
    freeaddrinfo(results);
    return *count ? 0 : -1;
}

static int dns_skip_name(const uint8_t *packet, size_t length, size_t *offset) {
    size_t cursor = *offset;
    size_t next = cursor;
    int jumped = 0;
    size_t steps = 0;
    while (cursor < length && steps++ < length) {
        uint8_t label = packet[cursor++];
        if ((label & 0xc0u) == 0xc0u) {
            if (cursor >= length) return -1;
            size_t pointer = ((size_t)(label & 0x3fu) << 8) | packet[cursor++];
            if (pointer >= length) return -1;
            if (!jumped) next = cursor;
            cursor = pointer;
            jumped = 1;
            continue;
        }
        if (label & 0xc0u) return -1;
        if (!label) {
            if (!jumped) next = cursor;
            *offset = next;
            return 0;
        }
        if (label > 63 || label > length - cursor) return -1;
        cursor += label;
        if (!jumped) next = cursor;
    }
    return -1;
}

int tg_route_dns_parse_response(const uint8_t *packet, size_t length,
                                uint16_t expected_id,
                                tg_listener_destination addresses[
                                    TG_ROUTE_DNS_ADDRESS_MAX],
                                size_t *count) {
    if (!packet || length < 12 || !addresses || !count) return -1;
    *count = 0;
    uint16_t id = (uint16_t)(((uint16_t)packet[0] << 8) | packet[1]);
    uint16_t flags = (uint16_t)(((uint16_t)packet[2] << 8) | packet[3]);
    uint16_t questions = (uint16_t)(((uint16_t)packet[4] << 8) | packet[5]);
    uint16_t answers = (uint16_t)(((uint16_t)packet[6] << 8) | packet[7]);
    if (id != expected_id || !(flags & 0x8000u) || (flags & 0x0200u) ||
        (flags & 0x000fu) != 0 || questions > 16 || answers > 256)
        return -1;
    size_t offset = 12;
    for (uint16_t i = 0; i < questions; ++i) {
        if (dns_skip_name(packet, length, &offset) != 0 ||
            length - offset < 4) return -1;
        offset += 4;
    }
    for (uint16_t i = 0; i < answers; ++i) {
        if (dns_skip_name(packet, length, &offset) != 0 ||
            length - offset < 10) return -1;
        uint16_t type = (uint16_t)(((uint16_t)packet[offset] << 8) |
                                   packet[offset + 1]);
        uint16_t klass = (uint16_t)(((uint16_t)packet[offset + 2] << 8) |
                                    packet[offset + 3]);
        uint16_t data_len = (uint16_t)(((uint16_t)packet[offset + 8] << 8) |
                                       packet[offset + 9]);
        offset += 10;
        if (data_len > length - offset) return -1;
        tg_listener_destination target = {.port = 443};
        if (klass == 1 && type == 1 && data_len == 4) {
            target.family = AF_INET;
            memcpy(target.address, packet + offset, 4);
        } else if (klass == 1 && type == 28 && data_len == 16) {
            target.family = AF_INET6;
            memcpy(target.address, packet + offset, 16);
        }
        if (target.family && public_target(&target)) {
            int duplicate = 0;
            for (size_t j = 0; j < *count; ++j)
                if (addresses[j].family == target.family &&
                    memcmp(addresses[j].address, target.address,
                           target.family == AF_INET ? 4u : 16u) == 0)
                    duplicate = 1;
            if (!duplicate && *count < TG_ROUTE_DNS_ADDRESS_MAX)
                addresses[(*count)++] = target;
        }
        offset += data_len;
    }
    return *count ? 0 : -1;
}

static int wait_socket(int fd, short events, uint64_t deadline) {
    for (;;) {
        uint64_t now = monotonic_ms();
        if (now >= deadline) return -1;
        uint64_t remaining = deadline - now;
        struct pollfd wait = {.fd = fd, .events = events};
        int rc = poll(&wait, 1, remaining > INT32_MAX ? INT32_MAX : (int)remaining);
        if (rc > 0) return wait.revents & (events | POLLERR | POLLHUP) ? 0 : -1;
        if (rc == 0) return -1;
        if (errno != EINTR) return -1;
    }
}

static int set_route_socket_mark(int fd, uint32_t mark) {
    if (!mark) return 0;
#ifdef SO_MARK
    return setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
#else
    (void)fd;
    errno = ENOTSUP;
    return -1;
#endif
}

static int https_connect(tg_route_dns *cache, const char *hostname,
                         const tg_listener_destination *target,
                         int http2, int *fd_out, SSL **ssl_out) {
    struct sockaddr_storage address;
    socklen_t address_len;
    memset(&address, 0, sizeof(address));
    if (!target || !public_target(target) || target->port != 443) return -1;
    if (target->family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(target->port);
        memcpy(&v4->sin_addr, target->address, sizeof(v4->sin_addr));
        address_len = sizeof(*v4);
    } else if (target->family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(target->port);
        memcpy(&v6->sin6_addr, target->address, sizeof(v6->sin6_addr));
        address_len = sizeof(*v6);
    } else {
        return -1;
    }
    int fd = socket(target->family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (set_route_socket_mark(fd, cache->socket_mark) != 0) {
        close(fd);
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    uint64_t deadline = monotonic_ms() + TG_ROUTE_DOH_TIMEOUT_MS;
    int rc = connect(fd, (struct sockaddr *)&address, address_len);
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (rc != 0 && wait_socket(fd, POLLOUT, deadline) != 0) {
        close(fd);
        return -1;
    }
    int socket_error = 0;
    socklen_t error_len = sizeof(socket_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) != 0 ||
        socket_error != 0) {
        close(fd);
        return -1;
    }
    SSL *ssl = tg_tls_prepare_client_fd(cache->tls_context, fd,
                                        hostname, hostname);
    if (!ssl ||
        (http2 && SSL_set_alpn_protos(ssl,
            (const unsigned char[]){2, 'h', '2'}, 3) != 0)) {
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    for (;;) {
        rc = SSL_connect(ssl);
        if (rc == 1) break;
        int error = SSL_get_error(ssl, rc);
        short events = error == SSL_ERROR_WANT_READ ? POLLIN :
                       error == SSL_ERROR_WANT_WRITE ? POLLOUT : 0;
        if (!events || wait_socket(fd, events, deadline) != 0) {
            SSL_free(ssl);
            close(fd);
            return -1;
        }
    }
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    if (http2) {
        const unsigned char *selected = NULL;
        unsigned int selected_len = 0;
        SSL_get0_alpn_selected(ssl, &selected, &selected_len);
        if (selected_len != 2 || memcmp(selected, "h2", 2) != 0) {
            SSL_free(ssl);
            close(fd);
            return -1;
        }
    }
    *fd_out = fd;
    *ssl_out = ssl;
    return 0;
}

static int dns_encode_question(const char *domain, uint16_t type,
                               uint8_t packet[512], size_t *length,
                               uint16_t *id_out) {
    if (!domain || !packet || !length || !id_out) return -1;
    uint16_t id;
    if (RAND_bytes((unsigned char *)&id, sizeof(id)) != 1) {
        id = (uint16_t)(monotonic_ms() ^ (uintptr_t)packet);
    }
    packet[0] = (uint8_t)(id >> 8);
    packet[1] = (uint8_t)id;
    packet[2] = 0x01;
    packet[3] = 0x00;
    packet[4] = 0;
    packet[5] = 1;
    memset(packet + 6, 0, 6);
    size_t offset = 12;
    const char *label = domain;
    while (*label) {
        const char *dot = strchr(label, '.');
        size_t label_len = dot ? (size_t)(dot - label) : strlen(label);
        if (!label_len || label_len > 63 || offset + label_len + 6 > 512)
            return -1;
        packet[offset++] = (uint8_t)label_len;
        memcpy(packet + offset, label, label_len);
        offset += label_len;
        if (!dot) break;
        label = dot + 1;
    }
    packet[offset++] = 0;
    packet[offset++] = (uint8_t)(type >> 8);
    packet[offset++] = (uint8_t)type;
    packet[offset++] = 0;
    packet[offset++] = 1;
    *length = offset;
    *id_out = id;
    return 0;
}

static int ssl_write_all(SSL *ssl, int fd, const uint8_t *data, size_t length,
                         uint64_t deadline) {
    size_t offset = 0;
    while (offset < length) {
        size_t written = 0;
        int rc = SSL_write_ex(ssl, data + offset, length - offset, &written);
        if (rc == 1) {
            if (!written) return -1;
            offset += written;
            continue;
        }
        int error = SSL_get_error(ssl, rc);
        short events = error == SSL_ERROR_WANT_READ ? POLLIN :
                       error == SSL_ERROR_WANT_WRITE ? POLLOUT : 0;
        if (!events || wait_socket(fd, events, deadline) != 0) return -1;
    }
    return 0;
}

static int ssl_read_exact(SSL *ssl, int fd, uint8_t *data, size_t length,
                          uint64_t deadline) {
    size_t offset = 0;
    while (offset < length) {
        size_t received = 0;
        int rc = SSL_read_ex(ssl, data + offset, length - offset, &received);
        if (rc == 1) {
            if (!received) return -1;
            offset += received;
            continue;
        }
        int error = SSL_get_error(ssl, rc);
        short events = error == SSL_ERROR_WANT_READ ? POLLIN :
                       error == SSL_ERROR_WANT_WRITE ? POLLOUT : 0;
        if (!events || wait_socket(fd, events, deadline) != 0) return -1;
    }
    return 0;
}

#define TG_H2_FRAME_MAX 65536u
#define TG_H2_HEADER_BLOCK_MAX 8192u

static int h2_write_frame(SSL *ssl, int fd, uint8_t type, uint8_t flags,
                          uint32_t stream_id, const uint8_t *payload,
                          size_t payload_len, uint64_t deadline) {
    if (payload_len > 0xffffffu || (payload_len && !payload)) return -1;
    uint8_t header[9] = {
        (uint8_t)(payload_len >> 16), (uint8_t)(payload_len >> 8),
        (uint8_t)payload_len, type, flags,
        (uint8_t)(stream_id >> 24), (uint8_t)(stream_id >> 16),
        (uint8_t)(stream_id >> 8), (uint8_t)stream_id
    };
    header[5] &= 0x7fu;
    if (ssl_write_all(ssl, fd, header, sizeof(header), deadline) != 0)
        return -1;
    return payload_len ? ssl_write_all(ssl, fd, payload, payload_len,
                                       deadline) : 0;
}

static int h2_read_frame(SSL *ssl, int fd, uint8_t *type, uint8_t *flags,
                         uint32_t *stream_id, uint8_t *payload,
                         size_t payload_cap, size_t *payload_len,
                         uint64_t deadline) {
    uint8_t header[9];
    if (ssl_read_exact(ssl, fd, header, sizeof(header), deadline) != 0)
        return -1;
    size_t length = ((size_t)header[0] << 16) |
                    ((size_t)header[1] << 8) | header[2];
    if (length > payload_cap || length > TG_H2_FRAME_MAX) return -1;
    *type = header[3];
    *flags = header[4];
    *stream_id = ((uint32_t)(header[5] & 0x7fu) << 24) |
                 ((uint32_t)header[6] << 16) |
                 ((uint32_t)header[7] << 8) | header[8];
    *payload_len = length;
    return length ? ssl_read_exact(ssl, fd, payload, length, deadline) : 0;
}

static int hpack_encode_integer(uint8_t *out, size_t cap, size_t *length,
                                unsigned prefix_bits, uint8_t marker,
                                size_t value) {
    if (!out || !length || prefix_bits == 0 || prefix_bits > 7) return -1;
    size_t prefix_max = ((size_t)1u << prefix_bits) - 1u;
    if (*length >= cap) return -1;
    if (value < prefix_max) {
        out[(*length)++] = (uint8_t)(marker | value);
        return 0;
    }
    out[(*length)++] = (uint8_t)(marker | prefix_max);
    value -= prefix_max;
    while (value >= 128u) {
        if (*length >= cap) return -1;
        out[(*length)++] = (uint8_t)((value & 0x7fu) | 0x80u);
        value >>= 7;
    }
    if (*length >= cap) return -1;
    out[(*length)++] = (uint8_t)value;
    return 0;
}

static int hpack_encode_string(uint8_t *out, size_t cap, size_t *length,
                               const char *value) {
    size_t value_len = strlen(value);
    if (hpack_encode_integer(out, cap, length, 7, 0, value_len) != 0 ||
        value_len > cap - *length) return -1;
    memcpy(out + *length, value, value_len);
    *length += value_len;
    return 0;
}

static int hpack_encode_header(uint8_t *out, size_t cap, size_t *length,
                               size_t static_name_index, const char *value) {
    if (hpack_encode_integer(out, cap, length, 4, 0,
                             static_name_index) != 0)
        return -1;
    return hpack_encode_string(out, cap, length, value);
}

static int h2_encode_doh_headers(const char *hostname, size_t body_len,
                                 uint8_t *headers, size_t headers_cap,
                                 size_t *headers_len) {
    if (!hostname || !headers || !headers_len || body_len > 65535u)
        return -1;
    *headers_len = 0;
    if (headers_cap < 2u) return -1;
    headers[(*headers_len)++] = 0x83u;
    headers[(*headers_len)++] = 0x87u;
    headers[(*headers_len)++] = 0x04u;
    if (hpack_encode_string(headers, headers_cap, headers_len,
                            "/dns-query") != 0 ||
        hpack_encode_header(headers, headers_cap, headers_len, 1, hostname) != 0 ||
        hpack_encode_header(headers, headers_cap, headers_len, 19,
                            "application/dns-message") != 0 ||
        hpack_encode_header(headers, headers_cap, headers_len, 31,
                            "application/dns-message") != 0)
        return -1;
    char content_length[8];
    int printed = snprintf(content_length, sizeof(content_length), "%zu",
                           body_len);
    if (printed < 0 || (size_t)printed >= sizeof(content_length)) return -1;
    return hpack_encode_header(headers, headers_cap, headers_len, 28,
                               content_length);
}

#ifdef TG_ROUTE_DNS_TESTING
int tg_route_dns_test_h2_encode_headers(const char *hostname, size_t body_len,
                                        uint8_t *headers, size_t headers_cap,
                                        size_t *headers_len) {
    return h2_encode_doh_headers(hostname, body_len, headers, headers_cap,
                                 headers_len);
}
#endif

static int hpack_read_integer(const uint8_t *block, size_t block_len,
                              size_t *offset, unsigned prefix_bits,
                              size_t *value) {
    if (!block || !offset || !value || *offset >= block_len ||
        prefix_bits == 0 || prefix_bits > 7) return -1;
    size_t prefix_max = ((size_t)1u << prefix_bits) - 1u;
    size_t result = block[*offset] & prefix_max;
    ++*offset;
    if (result < prefix_max) {
        *value = result;
        return 0;
    }
    unsigned shift = 0;
    for (;;) {
        if (*offset >= block_len || shift >= sizeof(size_t) * 8u) return -1;
        uint8_t byte = block[(*offset)++];
        size_t part = byte & 0x7fu;
        if (part > (SIZE_MAX - result) >> shift) return -1;
        result += part << shift;
        if (!(byte & 0x80u)) break;
        shift += 7u;
    }
    *value = result;
    return 0;
}

static int hpack_skip_string(const uint8_t *block, size_t block_len,
                             size_t *offset, const uint8_t **value,
                             size_t *value_len, int *huffman) {
    if (!block || !offset || *offset >= block_len) return -1;
    *huffman = (block[*offset] & 0x80u) != 0;
    size_t length;
    if (hpack_read_integer(block, block_len, offset, 7, &length) != 0 ||
        length > block_len - *offset) return -1;
    *value = block + *offset;
    *value_len = length;
    *offset += length;
    return 0;
}

static int h2_response_is_ok(const uint8_t *block, size_t block_len) {
    size_t offset = 0;
    int status_seen = 0;
    while (offset < block_len) {
        uint8_t first = block[offset];
        size_t index;
        if (first & 0x80u) {
            if (hpack_read_integer(block, block_len, &offset, 7, &index) != 0 ||
                index == 0) return 0;
            if (index == 8u) status_seen = 1;
            else if (index >= 9u && index <= 14u) return 0;
            continue;
        }
        if ((first & 0xe0u) == 0x20u) {
            if (hpack_read_integer(block, block_len, &offset, 5, &index) != 0)
                return 0;
            continue;
        }
        int literal = (first & 0x40u) != 0;
        unsigned prefix = literal ? 6u : 4u;
        if (hpack_read_integer(block, block_len, &offset, prefix, &index) != 0)
            return 0;
        int status_name = index == 8u;
        if (index == 0) {
            const uint8_t *name;
            size_t name_len;
            int name_huffman;
            if (hpack_skip_string(block, block_len, &offset, &name,
                                  &name_len, &name_huffman) != 0) return 0;
            status_name = !name_huffman && name_len == 7u &&
                          memcmp(name, ":status", 7) == 0;
        }
        const uint8_t *value;
        size_t value_len;
        int value_huffman;
        if (hpack_skip_string(block, block_len, &offset, &value,
                              &value_len, &value_huffman) != 0) return 0;
        if (status_name) {
            if (value_huffman || value_len != 3u ||
                memcmp(value, "200", 3) != 0) return 0;
            status_seen = 1;
        }
    }
    return status_seen;
}

#ifdef TG_ROUTE_DNS_TESTING
int tg_route_dns_test_h2_response_is_ok(const uint8_t *block,
                                        size_t block_len) {
    return h2_response_is_ok(block, block_len);
}
#endif

static int h2_response_body(SSL *ssl, int fd, uint8_t *body, size_t body_cap,
                            size_t *body_len, uint64_t deadline) {
    uint8_t payload[TG_H2_FRAME_MAX];
    uint8_t headers[TG_H2_HEADER_BLOCK_MAX];
    size_t headers_len = 0;
    *body_len = 0;
    int status_ok = 0;
    int headers_seen = 0;
    int stream_done = 0;
    while (!stream_done) {
        uint8_t type, flags;
        uint32_t stream_id;
        size_t payload_len;
        if (h2_read_frame(ssl, fd, &type, &flags, &stream_id, payload,
                          sizeof(payload), &payload_len, deadline) != 0)
            return -1;
        if (type == 4u && stream_id == 0u) {
            if (!(flags & 1u) && h2_write_frame(ssl, fd, 4u, 1u, 0u,
                                                 NULL, 0, deadline) != 0)
                return -1;
            continue;
        }
        if (type == 6u && stream_id == 0u) {
            if (payload_len != 8u) return -1;
            if (!(flags & 1u) && h2_write_frame(ssl, fd, 6u, 1u, 0u,
                                                 payload, payload_len,
                                                 deadline) != 0)
                return -1;
            continue;
        }
        if (type == 7u || (type == 3u && stream_id == 1u)) return -1;
        if (stream_id != 1u) continue;
        if (type == 1u && !headers_seen) {
            int headers_end_stream = (flags & 1u) != 0;
            size_t offset = 0;
            size_t end = payload_len;
            if (flags & 0x08u) {
                if (!payload_len) return -1;
                size_t padding = payload[offset++];
                if (padding > end - offset) return -1;
                end -= padding;
            }
            if (flags & 0x20u) {
                if (end - offset < 5u) return -1;
                offset += 5u;
            }
            size_t fragment_len = end - offset;
            if (fragment_len > sizeof(headers) - headers_len) return -1;
            memcpy(headers + headers_len, payload + offset, fragment_len);
            headers_len += fragment_len;
            while (!(flags & 0x04u)) {
                if (h2_read_frame(ssl, fd, &type, &flags, &stream_id, payload,
                                  sizeof(payload), &payload_len,
                                  deadline) != 0 || type != 9u ||
                    stream_id != 1u ||
                    payload_len > sizeof(headers) - headers_len) return -1;
                memcpy(headers + headers_len, payload, payload_len);
                headers_len += payload_len;
            }
            headers_seen = 1;
            status_ok = h2_response_is_ok(headers, headers_len);
            if (!status_ok) return -1;
            if (headers_end_stream) stream_done = 1;
        } else if (type == 0u) {
            if (!headers_seen || !status_ok) return -1;
            size_t offset = 0;
            size_t end = payload_len;
            if (flags & 0x08u) {
                if (!payload_len) return -1;
                size_t padding = payload[offset++];
                if (padding > end - offset) return -1;
                end -= padding;
            }
            size_t data_len = end - offset;
            if (data_len > body_cap - *body_len) return -1;
            memcpy(body + *body_len, payload + offset, data_len);
            *body_len += data_len;
            if (flags & 1u) stream_done = 1;
        }
    }
    return 0;
}

static int tg_route_dns_https2_request(
    tg_route_dns *cache, const char *hostname,
    const tg_listener_destination *target, const char *path,
    const uint8_t *request_body, size_t request_body_len,
    uint8_t *response_body, size_t response_body_cap,
    size_t *response_body_len) {
    if (!cache || !cache->tls_context || !valid_domain(hostname) || !path ||
        strcmp(path, "/dns-query") != 0 || !request_body ||
        request_body_len > 65535u || !response_body || !response_body_len ||
        response_body_cap > TG_ROUTE_HTTPS_BODY_MAX) return -1;
    int fd = -1;
    SSL *ssl = NULL;
    if (https_connect(cache, hostname, target, 1, &fd, &ssl) != 0) return -1;
    uint64_t deadline = monotonic_ms() + TG_ROUTE_DOH_TIMEOUT_MS;
    static const uint8_t preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    uint8_t headers[512];
    size_t headers_len = 0;
    int rc = ssl_write_all(ssl, fd, preface, sizeof(preface) - 1u,
                           deadline);
    if (rc == 0)
        rc = h2_write_frame(ssl, fd, 4u, 0u, 0u, NULL, 0, deadline);
    if (rc == 0)
        rc = h2_encode_doh_headers(hostname, request_body_len, headers,
                                   sizeof(headers), &headers_len);
    if (rc == 0)
        rc = h2_write_frame(ssl, fd, 1u, 0x04u, 1u, headers, headers_len,
                            deadline);
    if (rc == 0)
        rc = h2_write_frame(ssl, fd, 0u, 0x01u, 1u, request_body,
                            request_body_len, deadline);
    if (rc == 0)
        rc = h2_response_body(ssl, fd, response_body, response_body_cap,
                              response_body_len, deadline);
    SSL_free(ssl);
    close(fd);
    return rc;
}

static int http_response_has_explicit_framing(const uint8_t *response,
                                              size_t length) {
    const uint8_t *separator = NULL;
    for (size_t i = 0; i + 3u < length; ++i)
        if (memcmp(response + i, "\r\n\r\n", 4) == 0) {
            separator = response + i;
            break;
        }
    if (!separator) return 0;
    size_t header_len = (size_t)(separator - response);
    if (header_len > 4096u) return 0;
    char headers[4097];
    memcpy(headers, response, header_len);
    headers[header_len] = '\0';
    char *line = strstr(headers, "\r\n");
    while (line) {
        line += 2;
        if (!*line) break;
        char *end = strstr(line, "\r\n");
        if (end) *end = '\0';
        if (strncasecmp(line, "Content-Length:", 15) == 0 ||
            (strncasecmp(line, "Transfer-Encoding:", 18) == 0 &&
             strcasestr(line + 18, "chunked"))) return 1;
        if (!end) break;
        line = end;
    }
    return 0;
}

static int ssl_read_response(SSL *ssl, int fd,
                             uint8_t response[TG_ROUTE_HTTPS_RESPONSE_MAX],
                             size_t *length, uint64_t deadline) {
    *length = 0;
    while (*length < TG_ROUTE_HTTPS_RESPONSE_MAX) {
        size_t received = 0;
        int rc = SSL_read_ex(ssl, response + *length,
                             TG_ROUTE_HTTPS_RESPONSE_MAX - *length, &received);
        if (rc == 1) {
            if (!received) return -1;
            *length += received;
            if (http_response_has_explicit_framing(response, *length)) {
                uint8_t body[TG_ROUTE_HTTPS_BODY_MAX];
                size_t body_len = 0;
                if (tg_route_dns_parse_http_response(
                        response, *length, body, sizeof(body), &body_len) == 0)
                    return 0;
            }
            continue;
        }
        int error = SSL_get_error(ssl, rc);
        if (error == SSL_ERROR_ZERO_RETURN) return 0;
        short events = error == SSL_ERROR_WANT_READ ? POLLIN :
                       error == SSL_ERROR_WANT_WRITE ? POLLOUT : 0;
        if (!events || wait_socket(fd, events, deadline) != 0) return -1;
    }
    return -1;
}

static int decode_chunked_body(const uint8_t *source, size_t source_len,
                               uint8_t *body, size_t body_cap,
                               size_t *body_len) {
    size_t offset = 0;
    *body_len = 0;
    for (;;) {
        size_t line_end = offset;
        while (line_end + 1u < source_len &&
               !(source[line_end] == '\r' && source[line_end + 1u] == '\n'))
            ++line_end;
        if (line_end + 1u >= source_len || line_end - offset > 32u) return -1;
        size_t digits_end = offset;
        while (digits_end < line_end && source[digits_end] != ';') ++digits_end;
        if (digits_end == offset) return -1;
        size_t chunk_len = 0;
        for (size_t i = offset; i < digits_end; ++i) {
            unsigned char ch = source[i];
            unsigned digit = ch >= '0' && ch <= '9'
                ? (unsigned)(ch - '0')
                : ch >= 'a' && ch <= 'f'
                    ? (unsigned)(ch - 'a') + 10u
                    : ch >= 'A' && ch <= 'F'
                        ? (unsigned)(ch - 'A') + 10u : 16u;
            if (digit > 15u || chunk_len > (SIZE_MAX - digit) / 16u) return -1;
            chunk_len = chunk_len * 16u + digit;
        }
        offset = line_end + 2u;
        if (chunk_len == 0) {
            if (offset + 2u <= source_len && source[offset] == '\r' &&
                source[offset + 1u] == '\n') return 0;
            for (size_t i = offset; i + 3u < source_len; ++i)
                if (memcmp(source + i, "\r\n\r\n", 4) == 0) return 0;
            return -1;
        }
        if (chunk_len > body_cap - *body_len ||
            chunk_len > source_len - offset ||
            source_len - offset - chunk_len < 2u ||
            source[offset + chunk_len] != '\r' ||
            source[offset + chunk_len + 1u] != '\n') return -1;
        memcpy(body + *body_len, source + offset, chunk_len);
        *body_len += chunk_len;
        offset += chunk_len + 2u;
    }
}

int tg_route_dns_parse_http_response(const uint8_t *response, size_t length,
                                     uint8_t *body, size_t body_cap,
                                     size_t *body_len) {
    if (!response || !body || !body_len) return -1;
    const uint8_t *separator = NULL;
    for (size_t i = 0; i + 3 < length; ++i)
        if (memcmp(response + i, "\r\n\r\n", 4) == 0) {
            separator = response + i;
            break;
        }
    if (!separator || length < 13 || memcmp(response, "HTTP/1.", 7) != 0 ||
        memcmp(response + 9, "200 ", 4) != 0) return -1;
    size_t header_len = (size_t)(separator - response);
    if (header_len > 4096) return -1;
    char headers[4097];
    memcpy(headers, response, header_len);
    headers[header_len] = '\0';
    const char *content_length = NULL;
    int chunked = 0;
    for (char *line = strstr(headers, "\r\n"); line;) {
        line += 2;
        if (!*line) break;
        char *end = strstr(line, "\r\n");
        if (end) *end = '\0';
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            content_length = line + 15;
            while (*content_length == ' ' || *content_length == '\t')
                ++content_length;
        }
        if (strncasecmp(line, "Transfer-Encoding:", 18) == 0 &&
            strcasestr(line + 18, "chunked")) chunked = 1;
        if (!end) break;
        line = end;
    }
    size_t available = length - (size_t)(separator + 4 - response);
    const uint8_t *source_body = separator + 4;
    if (chunked) {
        if (content_length) return -1;
        return decode_chunked_body(source_body, available, body, body_cap,
                                   body_len);
    }
    if (content_length) {
        char *endptr = NULL;
        unsigned long declared = strtoul(content_length, &endptr, 10);
        if (endptr == content_length || *endptr || declared > body_cap ||
            available < declared) return -1;
        memcpy(body, source_body, (size_t)declared);
        *body_len = (size_t)declared;
        return 0;
    }
    if (available > body_cap) return -1;
    memcpy(body, source_body, available);
    *body_len = available;
    return 0;
}

static int contains_http_control(const char *value) {
    if (!value) return 1;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (*p < 0x20u || *p == 0x7fu) return 1;
    return 0;
}

int tg_route_dns_https_request(
    tg_route_dns *cache, const char *hostname,
    const tg_listener_destination *target, const char *method,
    const char *path, const char *accept, const char *content_type,
    const uint8_t *request_body, size_t request_body_len,
    uint8_t *response_body, size_t response_body_cap,
    size_t *response_body_len) {
    if (!cache || !cache->tls_context || !valid_domain(hostname) ||
        !method || (strcmp(method, "GET") != 0 &&
                    strcmp(method, "POST") != 0) || !path || path[0] != '/' ||
        !accept || !response_body || !response_body_len ||
        (request_body_len && (!request_body || !content_type)) ||
        response_body_cap > TG_ROUTE_HTTPS_BODY_MAX ||
        contains_http_control(hostname) || contains_http_control(method) ||
        contains_http_control(path) || contains_http_control(accept) ||
        (content_type && contains_http_control(content_type))) return -1;
    int fd = -1;
    SSL *ssl = NULL;
    if (https_connect(cache, hostname, target, 0, &fd, &ssl) != 0) return -1;
    uint64_t deadline = monotonic_ms() + TG_ROUTE_DOH_TIMEOUT_MS;
    char request[2048];
    int request_len = snprintf(request, sizeof(request),
        "%s %s HTTP/1.1\r\nHost: %s\r\nAccept: %s\r\n%s%s%s"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n",
        method, path, hostname, accept,
        content_type ? "Content-Type: " : "",
        content_type ? content_type : "",
        content_type ? "\r\n" : "",
        request_body_len);
    int rc = request_len > 0 && (size_t)request_len < sizeof(request) &&
             ssl_write_all(ssl, fd, (const uint8_t *)request,
                           (size_t)request_len, deadline) == 0 ? 0 : -1;
    if (rc == 0 && request_body_len)
        rc = ssl_write_all(ssl, fd, request_body, request_body_len,
                           deadline);
    uint8_t response[TG_ROUTE_HTTPS_RESPONSE_MAX];
    size_t response_len = 0;
    if (rc == 0)
        rc = ssl_read_response(ssl, fd, response, &response_len, deadline);
    SSL_free(ssl);
    close(fd);
    if (rc != 0) return -1;
    return tg_route_dns_parse_http_response(response, response_len,
                                            response_body,
                                            response_body_cap,
                                            response_body_len);
}

static int doh_query_endpoint(tg_route_dns *cache,
                              const doh_endpoint *endpoint,
                              const char *domain, uint16_t type,
                              tg_listener_destination addresses[
                                  TG_ROUTE_DNS_ADDRESS_MAX], size_t *count) {
    uint8_t query[512];
    size_t query_len = 0;
    uint16_t query_id = 0;
    if (dns_encode_question(domain, type, query, &query_len, &query_id) != 0)
        return -1;
    tg_listener_destination target = {.family = AF_INET, .port = 443};
    memcpy(target.address, endpoint->address, sizeof(endpoint->address));
    uint8_t body[TG_ROUTE_HTTPS_BODY_MAX];
    size_t body_len = 0;
    int request_rc = endpoint->http2
        ? tg_route_dns_https2_request(cache, endpoint->host, &target,
                                      "/dns-query", query, query_len, body,
                                      sizeof(body), &body_len)
        : tg_route_dns_https_request(
              cache, endpoint->host, &target, "POST", "/dns-query",
              "application/dns-message", "application/dns-message", query,
              query_len, body, sizeof(body), &body_len);
    if (request_rc != 0)
        return -1;
    return tg_route_dns_parse_response(body, body_len, query_id, addresses,
                                       count);
}

static int doh_lookup(tg_route_dns *cache, const char *domain,
                      tg_listener_destination addresses[
                          TG_ROUTE_DNS_ADDRESS_MAX], size_t *count) {
    if (!cache->tls_context) return -1;
    *count = 0;
    for (size_t endpoint = 0;
         endpoint < sizeof(doh_endpoints) / sizeof(doh_endpoints[0]);
         ++endpoint) {
        for (size_t type_index = 0; type_index < 2; ++type_index) {
            uint16_t type = type_index == 0 ? 1u : 28u;
            tg_listener_destination found[TG_ROUTE_DNS_ADDRESS_MAX] = {{0}};
            size_t found_count = 0;
            if (doh_query_endpoint(cache, &doh_endpoints[endpoint], domain,
                                   type, found, &found_count) != 0)
                continue;
            for (size_t i = 0; i < found_count &&
                 *count < TG_ROUTE_DNS_ADDRESS_MAX; ++i) {
                int duplicate = 0;
                for (size_t j = 0; j < *count; ++j)
                    if (addresses[j].family == found[i].family &&
                        memcmp(addresses[j].address, found[i].address,
                               found[i].family == AF_INET ? 4u : 16u) == 0)
                        duplicate = 1;
                if (!duplicate) addresses[(*count)++] = found[i];
            }
        }
        if (*count) return 0;
    }
    return -1;
}

static int system_then_doh_lookup(void *opaque, const char *domain,
                                  tg_listener_destination addresses[
                                      TG_ROUTE_DNS_ADDRESS_MAX],
                                  size_t *count) {
    tg_route_dns *cache = opaque;
    if (system_lookup(NULL, domain, addresses, count) == 0) return 0;
    return doh_lookup(cache, domain, addresses, count);
}

int tg_route_dns_lookup_now(tg_route_dns *cache, const char *domain,
                            tg_listener_destination addresses[
                                TG_ROUTE_DNS_ADDRESS_MAX],
                            size_t *count) {
    if (!cache || !valid_domain(domain) || !addresses || !count) return -1;
    return cache->lookup(cache->lookup_context, domain, addresses, count);
}

static size_t find_entry(tg_route_dns *cache, const char *domain) {
    for (size_t i = 0; i < TG_ROUTE_DNS_CACHE_MAX; ++i)
        if (cache->entries[i].used &&
            strcmp(cache->entries[i].domain, domain) == 0) return i;
    return TG_ROUTE_DNS_CACHE_MAX;
}

static size_t get_entry(tg_route_dns *cache, const char *domain) {
    size_t index = find_entry(cache, domain);
    if (index != TG_ROUTE_DNS_CACHE_MAX) return index;
    size_t oldest = TG_ROUTE_DNS_CACHE_MAX;
    for (size_t i = 0; i < TG_ROUTE_DNS_CACHE_MAX; ++i) {
        if (!cache->entries[i].used) {
            oldest = i;
            break;
        }
        if (!cache->entries[i].pending &&
            (oldest == TG_ROUTE_DNS_CACHE_MAX ||
             cache->entries[i].expires_at_ms <
                 cache->entries[oldest].expires_at_ms))
            oldest = i;
    }
    if (oldest == TG_ROUTE_DNS_CACHE_MAX) return oldest;
    route_dns_entry *entry = &cache->entries[oldest];
    memset(entry, 0, sizeof(*entry));
    memcpy(entry->domain, domain, strlen(domain) + 1u);
    entry->used = 1;
    return oldest;
}

static int enqueue(tg_route_dns *cache, size_t index, uint64_t now) {
    route_dns_entry *entry = &cache->entries[index];
    if (entry->pending || (entry->retry_at_ms && now < entry->retry_at_ms))
        return 0;
    if (cache->queue_len == TG_ROUTE_DNS_CACHE_MAX) return -1;
    size_t tail = (cache->queue_head + cache->queue_len) % TG_ROUTE_DNS_CACHE_MAX;
    cache->queue[tail] = index;
    ++cache->queue_len;
    entry->pending = 1;
    pthread_cond_signal(&cache->condition);
    return 0;
}

static void *resolver_worker(void *opaque) {
    tg_route_dns *cache = opaque;
    for (;;) {
        pthread_mutex_lock(&cache->mutex);
        while (!cache->stopping && cache->queue_len == 0) {
            pthread_mutex_unlock(&cache->mutex);
            if (cache->domain_pool && tg_cf_domain_pool_refresh_due(
                    cache->domain_pool, (uint64_t)time(NULL))) {
                if (tg_cf_domain_pool_refresh(cache->domain_pool, cache) == 0) {
                    tg_route_dns_prefetch_cf_pool(cache,
                                                  cache->domain_pool);
                }
                pthread_mutex_lock(&cache->mutex);
                continue;
            }
            pthread_mutex_lock(&cache->mutex);
            if (!cache->stopping && cache->queue_len == 0) {
                struct timespec wake_at;
                if (clock_gettime(CLOCK_REALTIME, &wake_at) == 0) {
                    wake_at.tv_sec += 60;
                    (void)pthread_cond_timedwait(&cache->condition,
                                                 &cache->mutex, &wake_at);
                } else {
                    (void)pthread_cond_wait(&cache->condition, &cache->mutex);
                }
            }
        }
        if (cache->stopping) {
            pthread_mutex_unlock(&cache->mutex);
            return NULL;
        }
        size_t index = cache->queue[cache->queue_head];
        cache->queue_head = (cache->queue_head + 1u) % TG_ROUTE_DNS_CACHE_MAX;
        --cache->queue_len;
        char domain[TG_ROUTE_DNS_DOMAIN_MAX];
        memcpy(domain, cache->entries[index].domain, sizeof(domain));
        pthread_mutex_unlock(&cache->mutex);

        tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX] = {{0}};
        size_t count = 0;
        int rc = cache->lookup(cache->lookup_context, domain, addresses, &count);
        if (count > TG_ROUTE_DNS_ADDRESS_MAX) count = 0;
        for (size_t i = 0; i < count; ++i)
            if (!public_target(&addresses[i])) count = 0;

        pthread_mutex_lock(&cache->mutex);
        route_dns_entry *entry = &cache->entries[index];
        entry->pending = 0;
        uint64_t now = monotonic_ms();
        if (rc == 0 && count) {
            memcpy(entry->addresses, addresses, count * sizeof(addresses[0]));
            entry->address_count = count;
            entry->next_address = 0;
            entry->expires_at_ms = now + TG_ROUTE_DNS_TTL_MS;
            entry->retry_at_ms = 0;
        } else {
            entry->retry_at_ms = now + TG_ROUTE_DNS_RETRY_MS;
        }
        pthread_mutex_unlock(&cache->mutex);
    }
}

tg_route_dns *tg_route_dns_create(SSL_CTX *tls_context, uint32_t socket_mark,
                                  tg_cf_domain_pool *domain_pool,
                                  tg_route_dns_lookup_fn lookup,
                                  void *context) {
    tg_route_dns *cache = calloc(1, sizeof(*cache));
    if (!cache) return NULL;
    if (pthread_mutex_init(&cache->mutex, NULL) != 0) {
        free(cache);
        return NULL;
    }
    if (pthread_cond_init(&cache->condition, NULL) != 0) {
        pthread_mutex_destroy(&cache->mutex);
        free(cache);
        return NULL;
    }
    cache->tls_context = tls_context;
    cache->domain_pool = domain_pool;
    cache->socket_mark = socket_mark;
    cache->lookup = lookup ? lookup : system_then_doh_lookup;
    cache->lookup_context = lookup ? context : cache;
    if (pthread_create(&cache->worker, NULL, resolver_worker, cache) != 0) {
        pthread_cond_destroy(&cache->condition);
        pthread_mutex_destroy(&cache->mutex);
        free(cache);
        return NULL;
    }
    cache->worker_started = 1;
    return cache;
}

void tg_route_dns_destroy(tg_route_dns *cache) {
    if (!cache) return;
    pthread_mutex_lock(&cache->mutex);
    cache->stopping = 1;
    pthread_cond_signal(&cache->condition);
    pthread_mutex_unlock(&cache->mutex);
    if (cache->worker_started) pthread_join(cache->worker, NULL);
    pthread_cond_destroy(&cache->condition);
    pthread_mutex_destroy(&cache->mutex);
    free(cache);
}

static int valid_domain(const char *domain) {
    if (!domain) return 0;
    size_t length = strlen(domain);
    if (!length || length >= TG_ROUTE_DNS_DOMAIN_MAX) return 0;
    size_t label_len = 0;
    int label_starts_hyphen = 0;
    for (size_t i = 0; i <= length; ++i) {
        char ch = domain[i];
        if (ch == '.' || ch == '\0') {
            if (!label_len || label_len > 63 || label_starts_hyphen ||
                domain[i - 1] == '-') return 0;
            label_len = 0;
            label_starts_hyphen = 0;
            continue;
        }
        if (ch == '-' && label_len == 0) label_starts_hyphen = 1;
        else if (!((ch >= 'A' && ch <= 'Z') ||
                   (ch >= 'a' && ch <= 'z') ||
                   (ch >= '0' && ch <= '9') || ch == '-')) return 0;
        ++label_len;
    }
    return strchr(domain, '.') != NULL;
}

int tg_route_dns_prefetch(tg_route_dns *cache, const char *domain) {
    if (!cache || !valid_domain(domain)) return -1;
    pthread_mutex_lock(&cache->mutex);
    size_t index = get_entry(cache, domain);
    int rc = index == TG_ROUTE_DNS_CACHE_MAX
        ? -1 : enqueue(cache, index, monotonic_ms());
    pthread_mutex_unlock(&cache->mutex);
    return rc;
}

void tg_route_dns_prefetch_cf_pool(tg_route_dns *cache,
                                   tg_cf_domain_pool *pool) {
    if (!cache || !pool) return;
    /* Bound initial requests on small routers. Remaining hostnames are
     * enqueued lazily by route selection when needed. */
    size_t count = tg_cf_domain_pool_count(pool);
    if (count > 3u) count = 3u;
    for (size_t i = 0; i < count; ++i) {
        char base[TG_CF_DOMAIN_LEN];
        if (tg_cf_domain_pool_copy_at(pool, i, base) != 0) continue;
        for (unsigned dc = 1; dc <= 5; ++dc) {
            for (unsigned variant = 0; variant <= 1; ++variant) {
                char host[TG_CF_DOMAIN_LEN];
                int n = snprintf(host, sizeof(host), "kws%u%s.%s", dc,
                                 variant ? "-1" : "", base);
                if (n > 0 && (size_t)n < sizeof(host))
                    (void)tg_route_dns_prefetch(cache, host);
            }
        }
    }
}

int tg_route_dns_resolve_status(tg_route_dns *cache, const char *domain,
                                tg_listener_destination *out) {
    if (!cache || !valid_domain(domain) || !out) return -1;
    pthread_mutex_lock(&cache->mutex);
    size_t index = get_entry(cache, domain);
    if (index == TG_ROUTE_DNS_CACHE_MAX) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    route_dns_entry *entry = &cache->entries[index];
    uint64_t now = monotonic_ms();
    if (entry->address_count) {
        if (now >= entry->expires_at_ms) (void)enqueue(cache, index, now);
        *out = entry->addresses[entry->next_address++ % entry->address_count];
        pthread_mutex_unlock(&cache->mutex);
        return 0;
    }
    if (entry->retry_at_ms && now < entry->retry_at_ms) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    int queued = enqueue(cache, index, now);
    int status = queued == 0 && entry->pending ? 1 : -1;
    pthread_mutex_unlock(&cache->mutex);
    return status;
}

int tg_route_dns_resolve(tg_route_dns *cache, const char *domain,
                         tg_listener_destination *out) {
    return tg_route_dns_resolve_status(cache, domain, out) == 0 ? 0 : -1;
}
