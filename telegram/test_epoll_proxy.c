#define _POSIX_C_SOURCE 200809L
#include "tg_epoll_proxy.h"

void tg_epoll_proxy_test_set_ping_interval_ms(uint64_t interval_ms);
#include "tg_mtproto.h"
#include "tg_limits.h"
#include "tg_stats_socket.h"
#include "tg_tls.h"
#include "tg_ws.h"
#include "tg_route_plan.h"

#include <assert.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int hold_pending_connect;
static int pending_connect_fd = -1;
static uint16_t counted_connect_port;
static unsigned counted_connect_attempts;

int __real_connect(int fd, const struct sockaddr *address, socklen_t length);
int __real_epoll_ctl(int epoll_fd, int operation, int fd,
                     struct epoll_event *event);
int __real_clock_gettime(clockid_t clock_id, struct timespec *time);

static int accept_error;
int __real_accept4(int fd, struct sockaddr *address, socklen_t *length, int flags);
int __wrap_accept4(int fd, struct sockaddr *address, socklen_t *length, int flags) {
    if (accept_error) {
        errno = accept_error;
        return -1;
    }
    return __real_accept4(fd, address, length, flags);
}

static atomic_uint_fast64_t test_monotonic_offset_ms;

int __wrap_clock_gettime(clockid_t clock_id, struct timespec *time) {
    int result = __real_clock_gettime(clock_id, time);
    if (result == 0 && clock_id == CLOCK_MONOTONIC) {
        uint64_t offset = atomic_load(&test_monotonic_offset_ms);
        time->tv_sec += (time_t)(offset / 1000u);
        time->tv_nsec += (long)(offset % 1000u) * 1000000L;
        if (time->tv_nsec >= 1000000000L) {
            ++time->tv_sec;
            time->tv_nsec -= 1000000000L;
        }
    }
    return result;
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (address && address->sa_family == AF_INET && counted_connect_port &&
        ntohs(((const struct sockaddr_in *)address)->sin_port) ==
            counted_connect_port)
        ++counted_connect_attempts;
    if (hold_pending_connect && address && address->sa_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
        if (ntohl(ipv4->sin_addr.s_addr) == 0xc00002c8u &&
            ntohs(ipv4->sin_port) == 443) {
            pending_connect_fd = fd;
            errno = EINPROGRESS;
            return -1;
        }
    }
    return __real_connect(fd, address, length);
}

int __wrap_epoll_ctl(int epoll_fd, int operation, int fd,
                     struct epoll_event *event) {
    if (hold_pending_connect && fd == pending_connect_fd &&
        operation != EPOLL_CTL_DEL)
        return 0;
    return __real_epoll_ctl(epoll_fd, operation, fd, event);
}

typedef struct {
    tg_listener_destination original;
    tg_listener_destination upstream;
    tg_listener_destination direct_upstream;
    tg_listener_destination worker_upstream;
    tg_listener_destination cf_proxy_b_upstream;
    pthread_mutex_t *original_mutex;
    size_t routes;
    size_t resolve_calls;
    size_t cf_proxy_a_resolve_calls;
    size_t cf_proxy_b_resolve_calls;
    atomic_int fail_cf_proxy_a_dns;
    atomic_int dns_ready;
} proxy_fixture;

typedef struct {
    tg_epoll_proxy *server;
    atomic_int stop;
} proxy_runner;

typedef struct {
    int listener;
    const char *cert_path;
    const char *key_path;
    const char *expected_sni;
    const char *expected_path;
    int expect_binary_subprotocol;
    const char *required_subprotocol;
    int omit_subprotocol;
    int expect_no_browser_headers;
    int expect_ping_after_handshake;
    int arbitrary_response;
    int ack_only_response;
    int close_without_response;
    size_t partial_client_packet_prefix;
    int wait_for_fallback;
    int partial_server_frame_before_fallback;
    int skip_client_packet;
    size_t response_prefix_len;
    int wait_for_second;
    int accepted_count;
    unsigned response_delay_ms;
    size_t media_chunks;
    int repeat_response;
    uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN];
    size_t handshake_len;
    uint8_t expected_packet[12];
    size_t expected_packet_len;
    uint8_t response_packet[96];
    size_t response_packet_len;
    atomic_int complete;
} wss_server_fixture;

typedef struct {
    int listener;
    const char *cert_path;
    const char *key_path;
    uint8_t expected[64u + 12u];
    unsigned tls_rejections;
    atomic_int complete;
} wss_fallback_fixture;

typedef struct {
    int listener;
    unsigned connections;
} echo_load_fixture;

static const uint8_t test_handshake[64] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x87,0xae,0xb3,0xfe,0x05,0x9b,0x48,0x07
};

static void prepare_wss_response(wss_server_fixture *fixture,
                                 const uint8_t handshake[64],
                                 tg_mtproto_proto proto) {
    uint8_t clear[12u + 4u + 40u + 1u] = {0};
    size_t ack_len;
    if (proto == TG_MTPROTO_PADDED_INTERMEDIATE) {
        clear[0] = 8;
        memset(clear + 4, 0xff, 4);
        clear[8] = 1;
        clear[9] = 2;
        clear[10] = 3;
        clear[11] = 4;
        ack_len = 12u;
    } else {
        if (proto == TG_MTPROTO_ABRIDGED) clear[0] = 0x80;
        else clear[3] = 0x80;
        ack_len = 4u;
    }

    size_t header_len = proto == TG_MTPROTO_ABRIDGED ? 1u : 4u;
    size_t padding_len = proto == TG_MTPROTO_PADDED_INTERMEDIATE ? 1u : 0u;
    size_t packet_len = 40u + padding_len;
    uint8_t *packet = clear + ack_len;
    if (proto == TG_MTPROTO_ABRIDGED) {
        packet[0] = 10;
    } else {
        packet[0] = (uint8_t)packet_len;
        packet[1] = (uint8_t)(packet_len >> 8);
        packet[2] = (uint8_t)(packet_len >> 16);
        packet[3] = (uint8_t)(packet_len >> 24);
    }
    uint8_t *body = packet + header_len;
    for (size_t i = 0; i < 8; ++i) body[i] = (uint8_t)(i + 1u);
    for (size_t i = 0; i < 16; ++i) {
        body[8 + i] = (uint8_t)(0x20u + i);
        body[24 + i] = (uint8_t)(0x40u + i);
    }
    if (padding_len) body[40] = 0xa5;

    size_t clear_len = ack_len + header_len + packet_len;
    tg_mtproto_ctr server_encrypt = {0};
    assert(tg_mtproto_direct_server_stream_cipher(handshake,
                                                   &server_encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&server_encrypt, clear, clear_len) == 0);
    memcpy(fixture->response_packet, clear, clear_len);
    fixture->response_packet_len = clear_len;
    tg_mtproto_ctr_destroy(&server_encrypt);
}

static void make_wss_test_handshake(tg_mtproto_proto proto, uint32_t dc_id,
                                    int is_media, uint8_t handshake[64]) {
    tg_mtproto_ctr to_server = {0}, from_server = {0};
    assert(tg_mtproto_make_obfuscated2_init(proto, dc_id, is_media, handshake,
                                             &to_server, &from_server) == 0);
    tg_mtproto_ctr_destroy(&to_server);
    tg_mtproto_ctr_destroy(&from_server);
}

static int original_destination(void *opaque, int fd,
                                tg_listener_destination *out) {
    (void)fd;
    proxy_fixture *fixture = opaque;
    if (fixture->original_mutex)
        assert(pthread_mutex_lock(fixture->original_mutex) == 0);
    *out = fixture->original;
    if (fixture->original_mutex)
        assert(pthread_mutex_unlock(fixture->original_mutex) == 0);
    return 0;
}

static int select_target(void *opaque,
                         const tg_listener_destination *original,
                         const uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN],
                         tg_listener_destination *out) {
    proxy_fixture *fixture = opaque;
    ++fixture->routes;
    tg_mtproto_init parsed;
    if (original->port != 443 ||
        tg_mtproto_parse_obfuscated2(handshake, &parsed) != 0) return -1;
    *out = fixture->upstream;
    return 0;
}

static int select_tcp_passthrough(void *opaque,
                                  const tg_listener_destination *original,
                                  const uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN],
                                  tg_epoll_route_selection *out) {
    out->tcp_only = 1;
    return select_target(opaque, original, handshake, &out->upstream);
}

static int resolve_test_route_domain(void *opaque, const char *domain,
                                     tg_listener_destination *out) {
    proxy_fixture *fixture = opaque;
    ++fixture->resolve_calls;
    if (strcmp(domain, "kws4-1.cfproxy-a.test") == 0 ||
        strcmp(domain, "kws4.cfproxy-a.test") == 0) {
        ++fixture->cf_proxy_a_resolve_calls;
        if (atomic_load(&fixture->fail_cf_proxy_a_dns)) return -1;
        *out = fixture->upstream;
        return 0;
    }
    if (strcmp(domain, "kws4-1.cfproxy-b.test") == 0 ||
        strcmp(domain, "kws4.cfproxy-b.test") == 0) {
        ++fixture->cf_proxy_b_resolve_calls;
        *out = fixture->cf_proxy_b_upstream;
        return 0;
    }
    if (strcmp(domain, "worker.test") != 0 &&
        strcmp(domain, "kws4.cfproxy.test") != 0 &&
        strcmp(domain, "kws4-1.cfproxy.test") != 0 &&
        strcmp(domain, "kws203-1.cfproxy.test") != 0) return -1;
    *out = fixture->upstream;
    return 0;
}

static int resolve_pending_test_route_domain(void *opaque, const char *domain,
                                             tg_listener_destination *out) {
    proxy_fixture *fixture = opaque;
    ++fixture->resolve_calls;
    if (strcmp(domain, "worker.test") != 0) return -1;
    if (!atomic_load(&fixture->dns_ready)) return 1;
    *out = fixture->worker_upstream;
    return 0;
}

static int select_pending_test_route(
    void *opaque, const tg_listener_destination *original,
    const uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN],
    tg_epoll_route_selection *selection) {
    proxy_fixture *fixture = opaque;
    tg_mtproto_init parsed;
    ++fixture->routes;
    if (original->port != 443 ||
        tg_mtproto_parse_obfuscated2(handshake, &parsed) != 0) return -1;
    selection->upstream = fixture->direct_upstream.port
        ? fixture->direct_upstream : fixture->upstream;
    selection->dc_id = 4;
    selection->is_media = 1;
    selection->proto = parsed.proto;
    return 0;
}

static int create_listener(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(fd, 8) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    *port = ntohs(address.sin_port);
    return fd;
}

static void set_ipv4(tg_listener_destination *out, const char *ip,
                     uint16_t port) {
    memset(out, 0, sizeof(*out));
    out->family = AF_INET;
    out->port = port;
    assert(inet_pton(AF_INET, ip, out->address) == 1);
}

static void set_ipv6(tg_listener_destination *out, const char *ip,
                     uint16_t port) {
    memset(out, 0, sizeof(*out));
    out->family = AF_INET6;
    out->port = port;
    assert(inet_pton(AF_INET6, ip, out->address) == 1);
}

static int ssl_read_exact(SSL *ssl, uint8_t *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        size_t received = 0;
        int result = SSL_read_ex(ssl, data + offset, length - offset, &received);
        if (result != 1 || received == 0) return -1;
        offset += received;
    }
    return 0;
}

static int ssl_write_exact(SSL *ssl, const uint8_t *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        size_t written = 0;
        if (SSL_write_ex(ssl, data + offset, length - offset, &written) != 1 ||
            written == 0)
            return -1;
        offset += written;
    }
    return 0;
}

static EVP_PKEY *make_wss_test_key(void) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    assert(context && EVP_PKEY_keygen_init(context) == 1);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) == 1);
    assert(EVP_PKEY_keygen(context, &key) == 1);
    EVP_PKEY_CTX_free(context);
    return key;
}

static X509 *make_wss_test_cert(EVP_PKEY *key) {
    X509 *cert = X509_new();
    assert(cert && X509_set_version(cert, 2) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(cert), -60) != NULL);
    assert(X509_gmtime_adj(X509_getm_notAfter(cert), 3600) != NULL);
    assert(X509_set_pubkey(cert, key) == 1);
    X509_NAME *name = X509_get_subject_name(cert);
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"kws4.web.telegram.org", -1, -1, 0) == 1);
    assert(X509_set_issuer_name(cert, name) == 1);
    X509_EXTENSION *extension = X509V3_EXT_conf_nid(
        NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    assert(extension && X509_add_ext(cert, extension, -1) == 1);
    X509_EXTENSION_free(extension);
    extension = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
        "DNS:kws4.web.telegram.org,DNS:kws4-1.web.telegram.org,"
        "DNS:worker.test,DNS:kws4.cfproxy.test,DNS:kws4-1.cfproxy.test,"
        "DNS:kws4.cfproxy-a.test,DNS:kws4-1.cfproxy-a.test,"
        "DNS:kws4.cfproxy-b.test,DNS:kws4-1.cfproxy-b.test,"
        "DNS:kws2.cfproxy.test,DNS:kws2-1.cfproxy.test,DNS:kws203-1.cfproxy.test,IP:127.0.0.1");
    assert(extension && X509_add_ext(cert, extension, -1) == 1);
    X509_EXTENSION_free(extension);
    assert(X509_sign(cert, key, EVP_sha256()) > 0);
    return cert;
}

static int read_masked_client_frame(SSL *ssl, uint8_t *opcode,
                                    uint8_t *payload, size_t capacity,
                                    size_t *payload_len) {
    uint8_t header[2] = {0}, mask[4];
    if (ssl_read_exact(ssl, header, sizeof(header)) != 0 ||
        (header[0] & 0x80u) == 0 || (header[0] & 0x70u) != 0 ||
        (header[1] & 0x80u) == 0) {
        return -1;
    }
    uint64_t length = header[1] & 0x7fu;
    if (length == 126) {
        uint8_t extended[2];
        if (ssl_read_exact(ssl, extended, sizeof(extended)) != 0) return -1;
        length = ((uint64_t)extended[0] << 8) | extended[1];
    } else if (length == 127) {
        return -1;
    }
    if (length > capacity || ssl_read_exact(ssl, mask, sizeof(mask)) != 0 ||
        (length && ssl_read_exact(ssl, payload, (size_t)length) != 0))
        return -1;
    for (size_t i = 0; i < (size_t)length; ++i) payload[i] ^= mask[i & 3u];
    *opcode = header[0] & 15u;
    *payload_len = (size_t)length;
    return 0;
}

static void read_masked_client_frame_prefix(
    SSL *ssl, const uint8_t *expected, size_t prefix_len) {
    uint8_t header[2] = {0}, mask[4], prefix[12];
    assert(prefix_len <= sizeof(prefix));
    assert(ssl_read_exact(ssl, header, sizeof(header)) == 0);
    assert((header[0] & 0x8fu) == (0x80u | TG_WS_BINARY));
    assert((header[1] & 0x80u) != 0 && (header[1] & 0x7fu) >= prefix_len &&
           (header[1] & 0x7fu) < 126u);
    assert(ssl_read_exact(ssl, mask, sizeof(mask)) == 0);
    assert(ssl_read_exact(ssl, prefix, prefix_len) == 0);
    for (size_t i = 0; i < prefix_len; ++i) prefix[i] ^= mask[i & 3u];
    assert(memcmp(prefix, expected, prefix_len) == 0);
}

static int write_server_frame(SSL *ssl, uint8_t opcode,
                              const uint8_t *payload, size_t payload_len) {
    uint8_t frame[TG_MTPROTO_HANDSHAKE_LEN + 16u];
    size_t header = payload_len < 126u ? 2u : 4u;
    if (payload_len > sizeof(frame) - header) return -1;
    frame[0] = (uint8_t)(0x80u | opcode);
    if (header == 2u) frame[1] = (uint8_t)payload_len;
    else {
        frame[1] = 126;
        frame[2] = (uint8_t)(payload_len >> 8);
        frame[3] = (uint8_t)payload_len;
    }
    if (payload_len) memcpy(frame + header, payload, payload_len);
    return ssl_write_exact(ssl, frame, header + payload_len);
}

#define TEST_MEDIA_CHUNK 16384u

static void write_media_chunks(SSL *ssl, const wss_server_fixture *fixture) {
    if (!fixture->media_chunks) return;
    tg_mtproto_ctr cipher = {0};
    assert(tg_mtproto_direct_server_stream_cipher(fixture->handshake, &cipher) == 0);
    uint8_t response[sizeof(fixture->response_packet)];
    memcpy(response, fixture->response_packet, fixture->response_packet_len);
    assert(tg_mtproto_ctr_xor(&cipher, response, fixture->response_packet_len) == 0);
    uint8_t frame[4u + TEST_MEDIA_CHUNK] = {0x82, 126, 0x40, 0};
    for (size_t i = 0; i < fixture->media_chunks; ++i) {
        /* Intermediate framing, followed by deterministic payload bytes. */
        memset(frame + 4u, (uint8_t)(i + 1u), TEST_MEDIA_CHUNK);
        const uint8_t packet_length[] = {0xfc, 0x3f, 0, 0};
        memcpy(frame + 4u, packet_length, sizeof(packet_length));
        assert(tg_mtproto_ctr_xor(&cipher, frame + 4u, TEST_MEDIA_CHUNK) == 0);
        assert(ssl_write_exact(ssl, frame, sizeof(frame)) == 0);
    }
    tg_mtproto_ctr_destroy(&cipher);
}

static void serve_direct_wss_connection(wss_server_fixture *fixture, int fd) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    assert(context && SSL_CTX_use_certificate_file(context, fixture->cert_path,
                                                    SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_use_PrivateKey_file(context, fixture->key_path,
                                       SSL_FILETYPE_PEM) == 1);
    SSL *ssl = SSL_new(context);
    assert(ssl && SSL_set_fd(ssl, fd) == 1 && SSL_accept(ssl) == 1);
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    const char *expected_sni = fixture->expected_sni
        ? fixture->expected_sni : "kws4-1.web.telegram.org";
    const char *expected_path = fixture->expected_path
        ? fixture->expected_path : "/apiws";
    int expect_binary_subprotocol = fixture->expected_sni
        ? fixture->expect_binary_subprotocol : 1;
    if (!sni || strcmp(sni, expected_sni) != 0)
        fprintf(stderr, "Неверный SNI тестового WSS: ожидался %s, получен %s\n",
                expected_sni, sni ? sni : "отсутствует");
    assert(sni && strcmp(sni, expected_sni) == 0);

    char request[2048];
    size_t request_len = 0;
    while (request_len < sizeof(request) - 1u) {
        assert(ssl_read_exact(ssl, (uint8_t *)request + request_len, 1) == 0);
        ++request_len;
        if (request_len >= 4u &&
            memcmp(request + request_len - 4u, "\r\n\r\n", 4) == 0)
            break;
    }
    request[request_len] = '\0';
    char expected_request[640];
    int expected_request_len = snprintf(expected_request, sizeof(expected_request),
        "GET %s HTTP/1.1\r\n", expected_path);
    assert(expected_request_len > 0 && (size_t)expected_request_len < sizeof(expected_request));
    assert(strncmp(request, expected_request, (size_t)expected_request_len) == 0);
    if (fixture->required_subprotocol) {
        char header[128];
        assert(snprintf(header, sizeof(header), "Sec-WebSocket-Protocol: %s\r\n",
                        fixture->required_subprotocol) > 0);
        assert(strstr(request, header));
    } else if (expect_binary_subprotocol)
        assert(strstr(request, "Sec-WebSocket-Protocol: binary\r\n"));
    else
        assert(!strstr(request, "Sec-WebSocket-Protocol:"));
    if (fixture->expect_no_browser_headers) {
        assert(!strstr(request, "Origin: https://web.telegram.org\r\n"));
        assert(!strstr(request, "User-Agent: Mozilla/5.0"));
    } else {
        assert(strstr(request, "Origin: https://web.telegram.org\r\n"));
        assert(strstr(request, "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
    }
    char *key_line = strstr(request, "Sec-WebSocket-Key: ");
    assert(key_line);
    key_line += strlen("Sec-WebSocket-Key: ");
    char source[64], accept_value[40], response[256];
    int source_len = snprintf(source, sizeof(source), "%.24s%s", key_line, guid);
    uint8_t digest[SHA_DIGEST_LENGTH];
    unsigned int digest_len = 0;
    assert(source_len > 0 && (size_t)source_len < sizeof(source));
    assert(EVP_Digest(source, (size_t)source_len, digest, &digest_len,
                      EVP_sha1(), NULL) == 1 && digest_len == sizeof(digest));
    assert(EVP_EncodeBlock((unsigned char *)accept_value, digest,
                           (int)sizeof(digest)) == 28);
    accept_value[28] = '\0';
    const char *protocol = fixture->omit_subprotocol ? NULL :
        fixture->required_subprotocol ? fixture->required_subprotocol :
        expect_binary_subprotocol ? "binary" : NULL;
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s%s%s\r\n",
        accept_value, protocol ? "Sec-WebSocket-Protocol: " : "",
        protocol ? protocol : "", protocol ? "\r\n" : "");
    assert(response_len > 0 && (size_t)response_len < sizeof(response));
    assert(ssl_write_exact(ssl, (const uint8_t *)response,
                           (size_t)response_len) == 0);
    if (fixture->omit_subprotocol) {
        uint8_t unexpected;
        int rc = SSL_read(ssl, &unexpected, 1);
        assert(rc <= 0 && SSL_get_error(ssl, rc) != SSL_ERROR_WANT_READ);
        atomic_store(&fixture->complete, 1);
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(context);
        return;
    }

    uint8_t payload[TG_MTPROTO_HANDSHAKE_LEN + 32u], opcode;
    size_t payload_len = 0;
    int handshake_frame_rc = read_masked_client_frame(
        ssl, &opcode, payload, sizeof(payload), &payload_len);
    assert(handshake_frame_rc == 0);
    const uint8_t *expected_handshake = fixture->handshake_len
        ? fixture->handshake : test_handshake;
    size_t expected_handshake_len = fixture->handshake_len
        ? fixture->handshake_len : sizeof(test_handshake);
    assert(opcode == TG_WS_BINARY && payload_len == expected_handshake_len);
    assert(memcmp(payload, expected_handshake, payload_len) == 0);
    if (fixture->expect_ping_after_handshake) {
        int ping_rc = read_masked_client_frame(ssl, &opcode, payload,
                                               sizeof(payload), &payload_len);
        assert(ping_rc == 0);
        assert(opcode == TG_WS_PING);
        assert(payload_len == 3 && memcmp(payload, "d2k", 3) == 0);
        assert(write_server_frame(ssl, TG_WS_PONG, payload, payload_len) == 0);
        atomic_store(&fixture->complete, 1);
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(context);
        return;
    }
    if (fixture->wait_for_fallback) {
        if (fixture->partial_server_frame_before_fallback) {
            const uint8_t partial_frame_header = 0x82u;
            assert(ssl_write_exact(ssl, &partial_frame_header, 1) == 0);
        }
        struct pollfd wait = {.fd = fixture->listener, .events = POLLIN};
        assert(poll(&wait, 1, 2000) > 0);
        int second = accept(fixture->listener, NULL, NULL);
        assert(second >= 0);
        fixture->accepted_count = 2;
        fixture->wait_for_fallback = 0;
        fixture->expected_sni = "kws4.cfproxy.test";
        fixture->expected_path = "/apiws";
        fixture->expect_binary_subprotocol = 1;
        fixture->skip_client_packet = 1;
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(context);
        serve_direct_wss_connection(fixture, second);
        return;
    }
    if (fixture->partial_client_packet_prefix) {
        read_masked_client_frame_prefix(ssl, fixture->expected_packet,
                                        fixture->partial_client_packet_prefix);
        atomic_store(&fixture->complete, 1);
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(context);
        return;
    }
    if (!fixture->skip_client_packet) {
        int packet_frame_rc = read_masked_client_frame(
            ssl, &opcode, payload, sizeof(payload), &payload_len);
        assert(packet_frame_rc == 0);
        size_t expected_len = fixture->expected_packet_len
            ? fixture->expected_packet_len : sizeof(fixture->expected_packet);
        assert(opcode == TG_WS_BINARY && payload_len == expected_len);
        assert(memcmp(payload, fixture->expected_packet, payload_len) == 0);
    }
    if (fixture->wait_for_second) {
        struct pollfd wait = {.fd = fixture->listener, .events = POLLIN};
        assert(poll(&wait, 1, 450) > 0);
        int second = accept(fixture->listener, NULL, NULL);
        assert(second >= 0);
        fixture->accepted_count = 2;
        fixture->wait_for_second = 0;
        fixture->expected_sni = "kws4.web.telegram.org";
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(context);
        serve_direct_wss_connection(fixture, second);
        return;
    }
    if (fixture->close_without_response) {
        atomic_store(&fixture->complete, 1);
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(context);
        return;
    }
    if (fixture->response_prefix_len) {
        assert(fixture->response_packet_len > fixture->response_prefix_len);
        uint8_t header[2] = {0x82u, (uint8_t)fixture->response_packet_len};
        assert(fixture->response_packet_len < 126u);
        assert(ssl_write_exact(ssl, header, sizeof(header)) == 0);
        assert(ssl_write_exact(ssl, fixture->response_packet,
                               fixture->response_prefix_len) == 0);
        atomic_store(&fixture->complete, 1);
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(context);
        return;
    }
    if (fixture->ack_only_response) {
        assert(write_server_frame(ssl, TG_WS_BINARY,
                                  fixture->response_packet,
                                  fixture->response_packet_len) == 0);
        struct timespec delay = {.tv_sec = 1, .tv_nsec = 500000000};
        nanosleep(&delay, NULL);
    } else if (fixture->arbitrary_response) {
        assert(fixture->response_packet_len == 4u);
        assert(write_server_frame(ssl, TG_WS_BINARY,
                                  fixture->response_packet,
                                  fixture->response_packet_len) == 0);
    } else {
        if (fixture->response_delay_ms) {
            struct timespec delay = {
                .tv_sec = fixture->response_delay_ms / 1000u,
                .tv_nsec = (long)(fixture->response_delay_ms % 1000u) * 1000000L
            };
            nanosleep(&delay, NULL);
        }
        assert(write_server_frame(ssl, TG_WS_BINARY,
                                  fixture->response_packet,
                                  fixture->response_packet_len) == 0);
        write_media_chunks(ssl, fixture);
        if (fixture->repeat_response) {
            assert(read_masked_client_frame(ssl, &opcode, payload, sizeof(payload),
                                            &payload_len) == 0);
            assert(opcode == TG_WS_BINARY && payload_len == 12);
            assert(write_server_frame(ssl, TG_WS_BINARY, fixture->response_packet,
                                      fixture->response_packet_len) == 0);
        }
        assert(read_masked_client_frame(ssl, &opcode, payload, sizeof(payload),
                                        &payload_len) == 0);
        assert(opcode == TG_WS_CLOSE && payload_len == 0);
        assert(write_server_frame(ssl, TG_WS_CLOSE, NULL, 0) == 0);
    }
    atomic_store(&fixture->complete, 1);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(context);
}

static void *serve_direct_wss(void *opaque) {
    wss_server_fixture *fixture = opaque;
    int fd = accept(fixture->listener, NULL, NULL);
    assert(fd >= 0);
    fixture->accepted_count = 1;
    serve_direct_wss_connection(fixture, fd);
    return NULL;
}

static void *serve_wss_partial_request_then_watch_retry(void *opaque) {
    wss_server_fixture *fixture = opaque;
    int fd = accept(fixture->listener, NULL, NULL);
    assert(fd >= 0);
    fixture->accepted_count = 1;
    fixture->expected_sni = "kws4-1.web.telegram.org";
    serve_direct_wss_connection(fixture, fd);

    struct pollfd wait = {.fd = fixture->listener, .events = POLLIN};
    if (poll(&wait, 1, 750) > 0) {
        int retry = accept(fixture->listener, NULL, NULL);
        if (retry >= 0) {
            fixture->accepted_count = 2;
            close(retry);
        }
    }
    return NULL;
}

static void *serve_rejected_wss_then_tcp(void *opaque) {
    wss_fallback_fixture *fixture = opaque;
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    assert(context && SSL_CTX_use_certificate_file(context, fixture->cert_path,
                                                    SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_use_PrivateKey_file(context, fixture->key_path,
                                       SSL_FILETYPE_PEM) == 1);
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        int tls_fd = accept(fixture->listener, NULL, NULL);
        assert(tls_fd >= 0);
        SSL *ssl = SSL_new(context);
        assert(ssl && SSL_set_fd(ssl, tls_fd) == 1 && SSL_accept(ssl) == 1);
        const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        assert(sni && strcmp(sni, attempt == 0 ? "kws4-1.web.telegram.org"
                                               : "kws4.web.telegram.org") == 0);
        char request[2048];
        size_t request_len = 0;
        while (request_len < sizeof(request) - 1u) {
            assert(ssl_read_exact(ssl, (uint8_t *)request + request_len, 1) == 0);
            ++request_len;
            if (request_len >= 4u &&
                memcmp(request + request_len - 4u, "\r\n\r\n", 4) == 0)
                break;
        }
        request[request_len] = '\0';
        assert(strstr(request, "GET /apiws HTTP/1.1\r\n"));
        static const char denied[] =
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        assert(ssl_write_exact(ssl, (const uint8_t *)denied,
                               sizeof(denied) - 1u) == 0);
        SSL_free(ssl);
        close(tls_fd);
    }
    SSL_CTX_free(context);

    int tcp_fd = accept(fixture->listener, NULL, NULL);
    assert(tcp_fd >= 0);
    uint8_t received[sizeof(fixture->expected)];
    size_t used = 0;
    while (used < sizeof(received)) {
        ssize_t n = recv(tcp_fd, received + used, sizeof(received) - used, 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        used += (size_t)n;
    }
    assert(memcmp(received, fixture->expected, sizeof(received)) == 0);
    size_t sent = 0;
    while (sent < sizeof(received)) {
        ssize_t n = send(tcp_fd, received + sent, sizeof(received) - sent, 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        sent += (size_t)n;
    }
    (void)shutdown(tcp_fd, SHUT_WR);
    close(tcp_fd);
    atomic_store(&fixture->complete, 1);
    return NULL;
}

static void *serve_bad_certificate_then_tcp(void *opaque) {
    wss_fallback_fixture *fixture = opaque;
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    assert(context && SSL_CTX_use_certificate_file(context, fixture->cert_path,
                                                    SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_use_PrivateKey_file(context, fixture->key_path,
                                       SSL_FILETYPE_PEM) == 1);
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        int tls_fd = accept(fixture->listener, NULL, NULL);
        assert(tls_fd >= 0);
        struct timeval timeout = {.tv_sec = 5};
        assert(setsockopt(tls_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                          sizeof(timeout)) == 0);
        SSL *ssl = SSL_new(context);
        assert(ssl && SSL_set_fd(ssl, tls_fd) == 1);
        assert(SSL_accept(ssl) != 1);
        ++fixture->tls_rejections;
        SSL_free(ssl);
        close(tls_fd);
    }
    SSL_CTX_free(context);

    int tcp_fd = accept(fixture->listener, NULL, NULL);
    assert(tcp_fd >= 0);
    uint8_t received[sizeof(fixture->expected)];
    size_t used = 0;
    while (used < sizeof(received)) {
        ssize_t n = recv(tcp_fd, received + used, sizeof(received) - used, 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        used += (size_t)n;
    }
    assert(memcmp(received, fixture->expected, sizeof(received)) == 0);
    size_t sent = 0;
    while (sent < sizeof(received)) {
        ssize_t n = send(tcp_fd, received + sent, sizeof(received) - sent, 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        sent += (size_t)n;
    }
    (void)shutdown(tcp_fd, SHUT_WR);
    close(tcp_fd);
    atomic_store(&fixture->complete, 1);
    return NULL;
}

static void *run_proxy(void *opaque) {
    proxy_runner *runner = opaque;
    while (!atomic_load(&runner->stop)) {
        if (tg_epoll_proxy_step(runner->server, 20) < 0) break;
    }
    return NULL;
}

static void *echo_server(void *opaque) {
    int listener = *(int *)opaque;
    int fd = accept(listener, NULL, NULL);
    assert(fd >= 0);
    uint8_t bytes[4096];
    for (;;) {
        ssize_t n = recv(fd, bytes, sizeof(bytes), 0);
        if (n == 0) break;
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        size_t sent = 0;
        while (sent < (size_t)n) {
            ssize_t m = send(fd, bytes + sent, (size_t)n - sent, 0);
            if (m < 0 && errno == EINTR) continue;
            assert(m > 0);
            sent += (size_t)m;
        }
    }
    close(fd);
    return NULL;
}

static void *echo_load_server(void *opaque) {
    echo_load_fixture *fixture = opaque;
    for (unsigned connection = 0; connection < fixture->connections;
         ++connection) {
        int fd = accept(fixture->listener, NULL, NULL);
        assert(fd >= 0);
        uint8_t bytes[4096];
        for (;;) {
            ssize_t n = recv(fd, bytes, sizeof(bytes), 0);
            if (n == 0) break;
            if (n < 0 && errno == EINTR) continue;
            assert(n > 0);
            size_t sent = 0;
            while (sent < (size_t)n) {
                ssize_t m = send(fd, bytes + sent, (size_t)n - sent, 0);
                if (m < 0 && errno == EINTR) continue;
                assert(m > 0);
                sent += (size_t)m;
            }
        }
        (void)shutdown(fd, SHUT_WR);
        close(fd);
    }
    return NULL;
}

static size_t count_open_fds(void) {
    DIR *directory = opendir("/proc/self/fd");
    assert(directory);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            ++count;
    closedir(directory);
    return count;
}

static void step_many(tg_epoll_proxy *server, unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
        assert(tg_epoll_proxy_step(server, 2) >= 0);
        struct timespec pause = {.tv_nsec = 1000000};
        nanosleep(&pause, NULL);
    }
}

static int connect_to_listener(uint16_t port) {
    int client = socket(AF_INET, SOCK_STREAM, 0);
    assert(client >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
                                  .sin_port = htons(port),
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);
    return client;
}

static uint64_t test_monotonic_us(void) {
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * UINT64_C(1000000) +
           (uint64_t)now.tv_nsec / 1000u;
}

static int exchange_wss_test_client(uint16_t port,
                                    const uint8_t handshake[64],
                                    const uint8_t *packet, size_t packet_len,
                                    const uint8_t *response,
                                    size_t response_len,
                                    uint64_t *elapsed_us) {
    uint64_t started = test_monotonic_us();
    int client = connect_to_listener(port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, handshake, 64, 0) == 64);
    assert(send(client, packet, packet_len, 0) == (ssize_t)packet_len);
    assert(shutdown(client, SHUT_WR) == 0);
    uint8_t received[96];
    assert(response_len <= sizeof(received));
    size_t used = 0;
    while (used < response_len) {
        struct pollfd wait = {.fd = client, .events = POLLIN};
        assert(poll(&wait, 1, 5000) > 0);
        ssize_t n = recv(client, received + used, response_len - used, 0);
        assert(n > 0);
        used += (size_t)n;
    }
    assert(memcmp(received, response, response_len) == 0);
    if (elapsed_us) *elapsed_us = test_monotonic_us() - started;
    return client;
}

static void test_epoll_bridge_preserves_handshake_and_half_close(void) {
    uint16_t upstream_port, listen_port;
    int upstream_listener = create_listener(&upstream_port);
    int listener = create_listener(&listen_port);
    pthread_t echo_thread;
    assert(pthread_create(&echo_thread, NULL, echo_server, &upstream_listener) == 0);

    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", upstream_port);
    tg_config routing = {0};
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 1024 * 1024,
        .configured_max_connections = 16,
        .handshake_timeout_ms = 1000,
        .idle_timeout_ms = 5000,
        .routing_config = &routing,
        .original_destination = original_destination,
        .select_route = select_tcp_passthrough,
        .context = &fixture,
    };
    tg_epoll_proxy *server = tg_epoll_proxy_create(&config);
    assert(server != NULL);
    assert(tg_epoll_proxy_max_connections(server) > 0 &&
           tg_epoll_proxy_max_connections(server) <= 16);

    int client = connect_to_listener(listen_port);
    const uint8_t *handshake = test_handshake;
    const uint8_t payload[] = {0x41,0x42,0x43,0x44,0x45};
    assert(send(client, handshake, 11, 0) == 11);
    step_many(server, 4);
    assert(send(client, handshake + 11, TG_MTPROTO_HANDSHAKE_LEN - 11, 0) ==
           (ssize_t)(TG_MTPROTO_HANDSHAKE_LEN - 11));
    assert(send(client, payload, sizeof(payload), 0) == (ssize_t)sizeof(payload));
    assert(shutdown(client, SHUT_WR) == 0);

    uint8_t received[TG_MTPROTO_HANDSHAKE_LEN + sizeof(payload)];
    size_t used = 0;
    for (unsigned i = 0; i < 200 && used < sizeof(received); ++i) {
        step_many(server, 1);
        ssize_t n = recv(client, received + used, sizeof(received) - used,
                         MSG_DONTWAIT);
        if (n > 0) used += (size_t)n;
        else assert(n == 0 || errno == EAGAIN || errno == EWOULDBLOCK);
    }
    assert(used == sizeof(received));
    assert(memcmp(received, handshake, TG_MTPROTO_HANDSHAKE_LEN) == 0);
    assert(memcmp(received + TG_MTPROTO_HANDSHAKE_LEN, payload,
                  sizeof(payload)) == 0);
    assert(fixture.routes == 1);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(server, &stats) == 0);
    assert(stats.active_connections <= 1 && stats.connections_started == 1);
    assert(stats.bytes_from_clients == sizeof(test_handshake) + sizeof(payload));
    assert(stats.bytes_from_upstreams == sizeof(received));
    assert(stats.buffer_bytes_peak >= sizeof(test_handshake));
    assert(stats.buffer_bytes_current == 0);
    close(client);
    tg_epoll_proxy_destroy(server);
    close(listener);
    close(upstream_listener);
    assert(pthread_join(echo_thread, NULL) == 0);
}

static void test_epoll_many_concurrent_tcp_clients(void) {
    enum { CLIENT_COUNT = 16 };
    const uint8_t payload[] = {0xa1,0xb2,0xc3,0xd4,0xe5};
    size_t open_fds_before = count_open_fds();
    uint16_t upstream_port, listen_port;
    int upstream_listener = create_listener(&upstream_port);
    int listener = create_listener(&listen_port);
    echo_load_fixture echo = {.listener = upstream_listener,
                              .connections = CLIENT_COUNT};
    pthread_t echo_thread;
    assert(pthread_create(&echo_thread, NULL, echo_load_server, &echo) == 0);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", upstream_port);
    tg_config routing = {.diagnostic_direct_tcp = 1};
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = CLIENT_COUNT,
        .handshake_timeout_ms = 5000,
        .idle_timeout_ms = 5000,
        .routing_config = &routing,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy && tg_epoll_proxy_max_connections(proxy) >= CLIENT_COUNT);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);
    int clients[CLIENT_COUNT];
    for (unsigned i = 0; i < CLIENT_COUNT; ++i) {
        clients[i] = connect_to_listener(listen_port);
        struct timeval timeout = {.tv_sec = 5};
        assert(setsockopt(clients[i], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                          sizeof(timeout)) == 0);
        assert(send(clients[i], test_handshake, sizeof(test_handshake), 0) ==
               (ssize_t)sizeof(test_handshake));
        assert(send(clients[i], payload, sizeof(payload), 0) ==
               (ssize_t)sizeof(payload));
        assert(shutdown(clients[i], SHUT_WR) == 0);
    }
    uint8_t expected[sizeof(test_handshake) + sizeof(payload)];
    memcpy(expected, test_handshake, sizeof(test_handshake));
    memcpy(expected + sizeof(test_handshake), payload, sizeof(payload));
    for (unsigned i = 0; i < CLIENT_COUNT; ++i) {
        uint8_t received[sizeof(expected)];
        size_t used = 0;
        while (used < sizeof(received)) {
            struct pollfd wait = {.fd = clients[i], .events = POLLIN};
            assert(poll(&wait, 1, 5000) > 0);
            ssize_t n = recv(clients[i], received + used,
                             sizeof(received) - used, 0);
            assert(n > 0);
            used += (size_t)n;
        }
        assert(memcmp(received, expected, sizeof(expected)) == 0);
        close(clients[i]);
    }
    assert(pthread_join(echo_thread, NULL) == 0);
    struct timespec settle = {.tv_nsec = 100000000};
    while (nanosleep(&settle, &settle) != 0 && errno == EINTR) {}
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    assert(fixture.routes == CLIENT_COUNT);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.connections_started == CLIENT_COUNT &&
           stats.active_connections == 0);
    assert(stats.bytes_from_clients ==
           CLIENT_COUNT * (sizeof(test_handshake) + sizeof(payload)));
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(upstream_listener);
    assert(count_open_fds() == open_fds_before);
}

static void test_pending_tcp_connect_expires_before_idle_timeout(void) {
    size_t fds_before = count_open_fds();
    uint16_t listen_port;
    int listener = create_listener(&listen_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "192.0.2.200", 443);
    tg_config routing = {.diagnostic_direct_tcp = 1};
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 1024 * 1024,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 75,
        .idle_timeout_ms = 5000,
        .routing_config = &routing,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    int client = connect_to_listener(listen_port);
    hold_pending_connect = 1;
    pending_connect_fd = -1;
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    for (unsigned i = 0; i < 10 && pending_connect_fd < 0; ++i)
        assert(tg_epoll_proxy_step(proxy, 20) >= 0);
    assert(pending_connect_fd >= 0);
    assert(tg_epoll_proxy_active_connections(proxy) == 1);

    for (unsigned i = 0; i < 20 &&
         tg_epoll_proxy_active_connections(proxy) != 0; ++i)
        assert(tg_epoll_proxy_step(proxy, 25) >= 0);
    assert(tg_epoll_proxy_active_connections(proxy) == 0);

    hold_pending_connect = 0;
    pending_connect_fd = -1;
    close(client);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    assert(count_open_fds() == fds_before);
}

static void test_read_only_stats_socket(void) {
    char directory[] = "/tmp/d2k-tg-stats-XXXXXX";
    assert(mkdtemp(directory) != NULL);
    char path[108];
    int path_length = snprintf(path, sizeof(path), "%s/stats.sock", directory);
    assert(path_length > 0 && (size_t)path_length < sizeof(path));

    uint16_t listen_port;
    int listener = create_listener(&listen_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", 443);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 575u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 1000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = SSL_CTX_new(TLS_client_method()),
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    assert(config.tls_context != NULL);
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy != NULL);
    tg_epoll_proxy_stats initial_stats;
    assert(tg_epoll_proxy_get_stats(proxy, &initial_stats) == 0);
    assert(initial_stats.max_wss_connections == initial_stats.max_connections);
    assert(initial_stats.active_wss_connections == 0);
    assert(initial_stats.buffer_bytes_current == 0);
    assert(initial_stats.buffer_bytes_peak == 0);
    assert(initial_stats.buffer_bytes_limit > 0);
    assert(initial_stats.buffer_bytes_limit >=
           initial_stats.max_wss_connections * TG_WS_PUMP_RX_INITIAL);
    struct stat socket_stat;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, (size_t)path_length + 1);
    int stale = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(stale >= 0);
    assert(bind(stale, (struct sockaddr *)&address, sizeof(address)) == 0);
    close(stale);

    tg_stats_socket stats_socket = {.fd = -1};
    assert(tg_stats_socket_open(&stats_socket, path) == 0);
    assert(stats_socket.process_generation != 0);
    tg_stats_socket duplicate = {.fd = -1};
    assert(tg_stats_socket_open(&duplicate, path) != 0);
    assert(stat(path, &socket_stat) == 0 && S_ISSOCK(socket_stat.st_mode));
    assert((socket_stat.st_mode & 0777) == 0600);

    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(client >= 0);
    assert(connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(tg_stats_socket_serve(&stats_socket, proxy, NULL) == 0);
    char response[64u * 1024u];
    ssize_t length = recv(client, response, sizeof(response) - 1, 0);
    assert(length > 0);
    response[length] = '\0';
    assert(strstr(response, "\"active_connections\":0") != NULL);
    assert(strstr(response, "\"connections_started\":0") != NULL);
    assert(strstr(response, "\"process_started_at\":") != NULL);
    char expected_generation[64];
    assert(snprintf(expected_generation, sizeof(expected_generation),
        "\"process_generation\":%" PRIu64, stats_socket.process_generation) > 0);
    assert(strstr(response, expected_generation) != NULL);
    assert(strstr(response, "\"accepted_connections\":0") != NULL);
    assert(strstr(response, "\"active_sessions\":[]") != NULL);
    assert(strstr(response, "\"route_sessions_truncated\":false") != NULL);
    assert(strstr(response, "\"route_cooldown_ms\":1000") != NULL);
    assert(strstr(response, "\"route_cooldowns\":[]") != NULL);
    assert(strstr(response, "\"route_cooldowns_truncated\":false") != NULL);
    assert(strstr(response, "\"active_wss_connections\":0") != NULL);
    assert(strstr(response, "\"max_wss_connections\":") != NULL);
    assert(strstr(response, "\"buffer_bytes_current\":0") != NULL);
    assert(strstr(response, "\"buffer_bytes_peak\":0") != NULL);
    assert(strstr(response, "\"buffer_bytes_limit\":") != NULL);
    assert(strstr(response, "\"process_id\":") != NULL);
    assert(strstr(response, "\"rss_kib\":") != NULL);
    assert(strstr(response, "\"rss_hwm_kib\":") != NULL);
    assert(strstr(response, "\"rss_anon_kib\":") != NULL);
    assert(strstr(response, "\"vm_data_kib\":") != NULL);
    assert(strstr(response, "\"vm_swap_kib\":") != NULL);
    assert(strstr(response, "\"smaps_rollup_status\":") != NULL);
    assert(strstr(response, "\"rss_minus_known_allocations_bytes\":") != NULL);
    assert(strstr(response, "\"fd_count\":") != NULL);
    assert(strstr(response, "\"soft_nofile_limit\":") != NULL);
    assert(strstr(response, "\"dc_map_status\":\"unavailable\"") != NULL);
    assert(strstr(response, "\"route_health\":[]") != NULL);
    assert(strstr(response, "\"problem_sessions\":[]") != NULL);
    assert(strstr(response, "\"last_success_dc\":0") != NULL);
    assert(strstr(response, "\"last_failure_stage\":0") != NULL);
    assert(strstr(response, "\"client_response_latency_total\":0") != NULL);
    assert(strstr(response, "\"client_response_latency_p50_us\":0") != NULL);
    close(client);

    tg_stats_socket_close(&stats_socket);
    assert(access(path, F_OK) != 0);
    tg_epoll_proxy_destroy(proxy);
    SSL_CTX_free(config.tls_context);
    close(listener);
    assert(rmdir(directory) == 0);
}

static void test_invalid_handshake_fails_closed(void) {
    uint16_t listen_port;
    int listener = create_listener(&listen_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", 443);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 1024 * 1024,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 1000,
        .idle_timeout_ms = 5000,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *server = tg_epoll_proxy_create(&config);
    assert(server != NULL);
    int client = connect_to_listener(listen_port);
    const uint8_t invalid[TG_MTPROTO_HANDSHAKE_LEN] = {0};
    assert(send(client, invalid, sizeof(invalid), 0) == (ssize_t)sizeof(invalid));
    step_many(server, 20);
    assert(fixture.routes == 1);
    assert(tg_epoll_proxy_active_connections(server) == 0);
    close(client);
    tg_epoll_proxy_destroy(server);
    close(listener);
}

static void test_client_disconnect_during_route_selection(void) {
    uint16_t listen_port;
    int listener = create_listener(&listen_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", 443);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 1024 * 1024,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 1000,
        .idle_timeout_ms = 5000,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    int client = connect_to_listener(listen_port);
    assert(send(client, test_handshake, 17, 0) == 17);
    close(client);
    step_many(proxy, 20);
    assert(fixture.routes == 0);
    assert(tg_epoll_proxy_active_connections(proxy) == 0);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
}

static void test_route_dns_failure_skips_worker(void) {
    uint16_t listen_port, closed_port;
    int listener = create_listener(&listen_port);
    int closed_listener = create_listener(&closed_port);
    close(closed_listener);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", closed_port);
    tg_config routing = {0};
    routing.ws_routing = TG_WS_ROUTING_CF_FIRST;
    routing.cf_worker_domain_count = 1;
    memcpy(routing.cf_worker_domains[0], "missing.test",
           sizeof("missing.test"));
    SSL_CTX *tls_context = SSL_CTX_new(TLS_client_method());
    assert(tls_context);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 1000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .resolve_domain = resolve_test_route_domain,
        .route_context = &fixture,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);
    int client = connect_to_listener(listen_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    uint8_t unexpected;
    assert(recv(client, &unexpected, sizeof(unexpected), 0) == 0);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    assert(fixture.routes == 1 && fixture.resolve_calls == 1);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.wss_attempts == 2 && stats.wss_failures == 2);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    SSL_CTX_free(tls_context);
}

static void test_all_routes_unavailable_fail_closed(int cloudflare_only) {
    uint16_t listen_port, closed_port;
    int listener = create_listener(&listen_port);
    int closed_listener = create_listener(&closed_port);
    close(closed_listener);
    counted_connect_port = closed_port;
    counted_connect_attempts = 0;
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", closed_port);
    SSL_CTX *tls_context = SSL_CTX_new(TLS_client_method());
    assert(tls_context);
    const tg_config legacy = {.diagnostic_direct_tcp = 1, .tcp_fallback_timeout_secs = 10};
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 1000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .cloudflare_only = cloudflare_only,
        .routing_config = cloudflare_only ? &legacy : NULL,
        .tls_context = tls_context,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);
    int client = connect_to_listener(listen_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    uint8_t unexpected;
    assert(recv(client, &unexpected, sizeof(unexpected), 0) == 0);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    assert(fixture.routes == 1);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.active_connections == 0 && stats.last_failure_dc == 4);
    if (cloudflare_only) {
        assert(counted_connect_attempts == 0 && stats.wss_attempts == 0);
        assert(stats.last_failure_stage == TG_EPOLL_FAILURE_ROUTE_UNAVAILABLE);
    } else {
        assert(counted_connect_attempts == 2);
        assert(stats.wss_attempts == 2 && stats.wss_failures == 2);
        assert(stats.last_failure_route == TG_ROUTE_DIRECT_WSS &&
               stats.last_failure_stage == TG_EPOLL_FAILURE_TCP);
    }
    counted_connect_port = 0;
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    SSL_CTX_free(tls_context);
}

static void test_disabled_wss_does_not_enable_automatic_tcp(void) {
    uint16_t listen_port, closed_port;
    int listener = create_listener(&listen_port);
    int closed_listener = create_listener(&closed_port);
    close(closed_listener);
    counted_connect_port = closed_port;
    counted_connect_attempts = 0;
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", closed_port);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 1000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 0,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);
    int client = connect_to_listener(listen_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    uint8_t unexpected;
    assert(recv(client, &unexpected, sizeof(unexpected), 0) == 0);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    assert(fixture.routes == 1);
    assert(counted_connect_attempts == 0);
    counted_connect_port = 0;
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.active_connections == 0 &&
           stats.wss_attempts == 0 && stats.wss_failures == 0 &&
           stats.last_failure_route == TG_ROUTE_NONE &&
           stats.last_failure_stage == TG_EPOLL_FAILURE_ROUTE_UNAVAILABLE);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
}

static void test_self_dial_target_is_rejected(void) {
    uint16_t listen_port;
    int listener = create_listener(&listen_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", 443);
    const uint16_t proxy_ports[] = {1443};
    tg_config routing = {.diagnostic_direct_tcp = 1};
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 1024 * 1024,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 1000,
        .idle_timeout_ms = 5000,
        .enforce_self_dial = 1,
        .listen_ports = proxy_ports,
        .listen_port_count = 1,
        .routing_config = &routing,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *server = tg_epoll_proxy_create(&config);
    assert(server != NULL);
    int client = connect_to_listener(listen_port);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    step_many(server, 20);
    assert(fixture.routes == 1);
    assert(tg_epoll_proxy_active_connections(server) == 0);
    close(client);
    tg_epoll_proxy_destroy(server);
    close(listener);
}

static void test_epoll_wss_forwards_unrecognized_binary_response(void) {
    char directory[] = "/tmp/d2k-tg-wss-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, proxy_port;
    wss_server_fixture wss = {.listener = create_listener(&ws_port),
                              .cert_path = cert_path,
                              .key_path = key_path,
                              .expect_binary_subprotocol = 1,
                              .arbitrary_response = 1};
    atomic_init(&wss.complete, 0);
    uint8_t invalid_response[4] = {0};
    tg_mtproto_ctr server_encrypt = {0};
    assert(tg_mtproto_direct_server_stream_cipher(test_handshake,
                                                   &server_encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&server_encrypt, invalid_response,
                              sizeof(invalid_response)) == 0);
    tg_mtproto_ctr_destroy(&server_encrypt);
    memcpy(wss.response_packet, invalid_response, sizeof(invalid_response));
    wss.response_packet_len = sizeof(invalid_response);
    memcpy(wss.expected_packet, (uint8_t[]){8,0,0,0,0x11,0x22,0x33,0x44,
                                             0x55,0x66,0x77,0x88},
           sizeof(wss.expected_packet));
    tg_mtproto_ctr client_decrypt = {0}, client_encrypt = {0};
    assert(tg_mtproto_direct_stream_ciphers(test_handshake, &client_decrypt,
                                             &client_encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&client_encrypt, wss.expected_packet,
                              sizeof(wss.expected_packet)) == 0);
    tg_mtproto_ctr_destroy(&client_decrypt);
    tg_mtproto_ctr_destroy(&client_encrypt);

    pthread_t wss_thread;
    assert(pthread_create(&wss_thread, NULL, serve_direct_wss, &wss) == 0);
    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    assert(tg_epoll_proxy_max_connections(proxy) > 1);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, test_handshake, 17, 0) == 17);
    assert(send(client, test_handshake + 17, sizeof(test_handshake) - 17u, 0) ==
           (ssize_t)(sizeof(test_handshake) - 17u));
    const uint8_t clear_packet[12] = {8,0,0,0,0x11,0x22,0x33,0x44,
                                      0x55,0x66,0x77,0x88};
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    uint8_t encrypted_packet[sizeof(clear_packet)];
    memcpy(encrypted_packet, clear_packet, sizeof(clear_packet));
    assert(tg_mtproto_direct_stream_ciphers(test_handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, encrypted_packet,
                              sizeof(encrypted_packet)) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);
    assert(send(client, encrypted_packet, sizeof(encrypted_packet), 0) ==
           (ssize_t)sizeof(encrypted_packet));

    uint8_t response[sizeof(invalid_response)];
    size_t received = 0;
    while (received < sizeof(response)) {
        ssize_t n = recv(client, response + received,
                         sizeof(response) - received, 0);
        assert(n > 0);
        received += (size_t)n;
    }
    assert(memcmp(response, invalid_response, sizeof(response)) == 0);
    uint8_t extra;
    assert(recv(client, &extra, sizeof(extra), 0) == 0);
    assert(pthread_join(wss_thread, NULL) == 0);
    assert(atomic_load(&wss.complete) == 1 && fixture.routes == 1);
    /* Leave the client write side open after upstream EOF. It must release
     * the slot on the close deadline instead of keeping it until idle. */
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    assert(tg_epoll_proxy_active_connections(proxy) == 1);
    atomic_store(&test_monotonic_offset_ms, 3100u);
    assert(tg_epoll_proxy_step(proxy, 0) >= 0);
    atomic_store(&test_monotonic_offset_ms, 0);
    assert(tg_epoll_proxy_active_connections(proxy) == 0);
    close(client);
    tg_epoll_proxy_stats route_stats;
    assert(tg_epoll_proxy_get_stats(proxy, &route_stats) == 0);
    assert(route_stats.wss_attempts == 1 && route_stats.wss_responses == 0 &&
           route_stats.wss_failures == 1);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(wss.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_epoll_wss_transport_ack_keeps_route_selected(void) {
    char directory[] = "/tmp/d2k-tg-wss-ack-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, proxy_port;
    wss_server_fixture wss = {.listener = create_listener(&ws_port),
                              .cert_path = cert_path,
                              .key_path = key_path,
                              .expect_binary_subprotocol = 1,
                              .ack_only_response = 1};
    atomic_init(&wss.complete, 0);
    prepare_wss_response(&wss, test_handshake, TG_MTPROTO_INTERMEDIATE);
    wss.response_packet_len = 4;
    memcpy(wss.expected_packet, (uint8_t[]){8,0,0,0,0x11,0x22,0x33,0x44,
                                             0x55,0x66,0x77,0x88},
           sizeof(wss.expected_packet));
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    assert(tg_mtproto_direct_stream_ciphers(test_handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, wss.expected_packet,
                              sizeof(wss.expected_packet)) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);

    pthread_t wss_thread;
    assert(pthread_create(&wss_thread, NULL, serve_direct_wss, &wss) == 0);
    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 600,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 3};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    assert(send(client, wss.expected_packet, sizeof(wss.expected_packet), 0) ==
           (ssize_t)sizeof(wss.expected_packet));
    uint8_t response[4];
    size_t received = 0;
    while (received < sizeof(response)) {
        ssize_t n = recv(client, response + received,
                         sizeof(response) - received, 0);
        assert(n > 0);
        received += (size_t)n;
    }
    assert(memcmp(response, wss.response_packet, sizeof(response)) == 0);
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 900000000};
    nanosleep(&delay, NULL);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.active_connections == 1 && stats.wss_attempts == 1 &&
           stats.wss_responses == 0 && stats.wss_failures == 0);

    assert(shutdown(client, SHUT_WR) == 0);
    close(client);
    assert(pthread_join(wss_thread, NULL) == 0);
    assert(atomic_load(&wss.complete) == 1);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(wss.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_epoll_hedged_wss_commits_one_route_before_payload(
    tg_mtproto_proto proto, int adaptive) {
    char directory[] = "/tmp/d2k-tg-wss-hedge-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, proxy_port;
    wss_server_fixture wss = {.listener = create_listener(&ws_port),
                              .cert_path = cert_path,
                              .key_path = key_path,
                              .expect_binary_subprotocol = 1};
    atomic_init(&wss.complete, 0);
    wss.expected_sni = adaptive ? "kws4-1.cfproxy.test" : "kws4-1.web.telegram.org";
    uint8_t handshake[64];
    make_wss_test_handshake(proto, 4, 1, handshake);
    memcpy(wss.handshake, handshake, sizeof(handshake));
    wss.handshake_len = sizeof(handshake);
    prepare_wss_response(&wss, handshake, proto);
    static const uint8_t request_body[8] =
        {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    size_t header_len = proto == TG_MTPROTO_ABRIDGED ? 1u : 4u;
    wss.expected_packet_len = header_len + sizeof(request_body);
    wss.expected_packet[0] =
        proto == TG_MTPROTO_ABRIDGED ? 2u : (uint8_t)sizeof(request_body);
    memset(wss.expected_packet + 1, 0, header_len - 1u);
    memcpy(wss.expected_packet + header_len, request_body,
           sizeof(request_body));
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    assert(tg_mtproto_direct_stream_ciphers(handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, wss.expected_packet,
                              wss.expected_packet_len) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);
    pthread_t wss_thread;
    assert(pthread_create(&wss_thread, NULL, serve_direct_wss, &wss) == 0);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {0};
    routing.ws_routing = adaptive ? TG_WS_ROUTING_ADAPTIVE : TG_WS_ROUTING_HEDGED;
    if (adaptive) {
        routing.cf_proxy_domain_count = 1;
        strcpy(routing.cf_proxy_domains[0], "cfproxy.test");
        set_ipv4(&fixture.direct_upstream, "192.0.2.200", 443);
        hold_pending_connect = 1;
    }
    routing.ws_hedge_delay_ms = 125;
    routing.ws_hedge_limit = 1;
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 64u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .original_destination = original_destination,
        .select_target = adaptive ? NULL : select_target,
        .select_route = adaptive ? select_pending_test_route : NULL,
        .resolve_domain = adaptive ? resolve_test_route_domain : NULL,
        .route_context = &fixture,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, handshake, sizeof(handshake), 0) ==
           (ssize_t)sizeof(handshake));
    assert(send(client, wss.expected_packet, wss.expected_packet_len, 0) ==
           (ssize_t)wss.expected_packet_len);
    uint8_t echoed[sizeof(wss.response_packet)];
    size_t received = 0;
    while (received < wss.response_packet_len) {
        struct pollfd wait = {.fd = client, .events = POLLIN};
        assert(poll(&wait, 1, 5000) > 0);
        ssize_t n = recv(client, echoed + received,
                         wss.response_packet_len - received, 0);
        assert(n > 0);
        received += (size_t)n;
    }
    assert(memcmp(echoed, wss.response_packet, wss.response_packet_len) == 0);
    tg_epoll_proxy_stats route_stats;
    assert(tg_epoll_proxy_get_stats(proxy, &route_stats) == 0);
    assert(route_stats.active_connections == 1 &&
           route_stats.active_sessions_count == 1);
    const tg_active_route_session *session = &route_stats.active_sessions[0];
    assert(session->id > 0 && session->has_dc && session->dc == 4);
    assert(session->has_media && session->is_media);
    assert(session->stage == TG_ROUTE_SESSION_STAGE_FIRST_WSS_BINARY_RESPONSE);
    if (adaptive) {
        assert(session->fallback_state == TG_ROUTE_SESSION_FIRST_BINARY_RESPONSE);
        assert(session->selected_transport == TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_PROXY);
    } else {
        assert(session->direct_state == TG_ROUTE_SESSION_FIRST_BINARY_RESPONSE);
        assert(session->selected_transport == TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS);
    }
    assert(session->telegram_response_seen);
    assert(session->client_port == 443 && session->upstream_port == ws_port);
    assert(session->age_ms > 0 && session->first_response_latency_ms > 0);
    assert(session->bytes_from_clients >= wss.expected_packet_len);
    assert(session->bytes_from_upstreams >= wss.response_packet_len);
    assert(session->event_count >= 4);
    assert(session->events[session->event_count - 1u].state ==
           TG_ROUTE_SESSION_FIRST_BINARY_RESPONSE);
    assert(session->events[session->event_count - 1u].sequence >
           session->events[session->event_count - 2u].sequence);
    assert(session->events[session->event_count - 1u].timestamp_ms > 0);
    assert(route_stats.monotonic_time_ms >=
           session->events[session->event_count - 1u].timestamp_ms);
    assert(session->events[session->event_count - 1u].failure_stage ==
           TG_EPOLL_FAILURE_NONE);

    char stats_path[256];
    assert(snprintf(stats_path, sizeof(stats_path), "%s/stats.sock", directory) > 0);
    tg_stats_socket stats_socket = {.fd = -1};
    assert(tg_stats_socket_open(&stats_socket, stats_path) == 0);
    int stats_client = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(stats_client >= 0);
    struct sockaddr_un stats_address = {.sun_family = AF_UNIX};
    memcpy(stats_address.sun_path, stats_path, strlen(stats_path) + 1u);
    assert(connect(stats_client, (struct sockaddr *)&stats_address,
                   sizeof(stats_address)) == 0);
    assert(tg_stats_socket_serve(&stats_socket, proxy, NULL) == 0);
    char stats_json[64u * 1024u];
    size_t stats_json_len = 0;
    for (;;) {
        assert(stats_json_len < sizeof(stats_json) - 1u);
        ssize_t n = recv(stats_client, stats_json + stats_json_len,
                         sizeof(stats_json) - 1u - stats_json_len, 0);
        if (n == 0) break;
        assert(n > 0);
        stats_json_len += (size_t)n;
    }
    stats_json[stats_json_len] = '\0';
    char expected_session_bytes[128];
    assert(snprintf(expected_session_bytes, sizeof(expected_session_bytes),
        "\"telegram_response_seen\":true,\"bytes_from_clients\":%" PRIu64
        ",\"bytes_from_upstreams\":%" PRIu64,
        session->bytes_from_clients, session->bytes_from_upstreams) > 0);
    assert(strstr(stats_json, expected_session_bytes) != NULL);
    assert(strstr(stats_json, "\"client_queue_capacity_bytes\":") != NULL);
    assert(strstr(stats_json, "\"route_health\":[") != NULL);
    assert(strstr(stats_json, "\"failure_by_stage\":{") != NULL);
    close(stats_client);
    tg_stats_socket_close(&stats_socket);

    assert(shutdown(client, SHUT_WR) == 0);
    assert(pthread_join(wss_thread, NULL) == 0);
    assert(wss.accepted_count == 1 && atomic_load(&wss.complete) == 1);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    assert(tg_epoll_proxy_get_stats(proxy, &route_stats) == 0);
    /* A slow test runner may launch the second direct candidate before
     * the first TLS handshake finishes. Only one route can carry payload. */
    assert(route_stats.wss_attempts >= (adaptive ? 2u : 1u) &&
           route_stats.wss_attempts <= 2u && route_stats.wss_responses == 1);
    hold_pending_connect = 0;
    pending_connect_fd = -1;
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(wss.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_epoll_wss_partial_request_is_not_replayed(void) {
    char directory[] = "/tmp/d2k-tg-wss-recovery-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, proxy_port;
    wss_server_fixture wss = {.listener = create_listener(&ws_port),
                              .cert_path = cert_path,
                              .key_path = key_path,
                              .expect_binary_subprotocol = 1,
                              .partial_client_packet_prefix = 4};
    atomic_init(&wss.complete, 0);
    prepare_wss_response(&wss, test_handshake, TG_MTPROTO_INTERMEDIATE);
    const uint8_t clear_packet[12] = {8,0,0,0,0x11,0x22,0x33,0x44,
                                      0x55,0x66,0x77,0x88};
    memcpy(wss.expected_packet, clear_packet, sizeof(clear_packet));
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    assert(tg_mtproto_direct_stream_ciphers(test_handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, wss.expected_packet,
                              sizeof(wss.expected_packet)) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);
    pthread_t wss_thread;
    assert(pthread_create(&wss_thread, NULL,
                          serve_wss_partial_request_then_watch_retry,
                          &wss) == 0);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 64u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    counted_connect_port = ws_port;
    counted_connect_attempts = 0;
    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    assert(send(client, wss.expected_packet, sizeof(wss.expected_packet), 0) ==
           (ssize_t)sizeof(wss.expected_packet));
    assert(shutdown(client, SHUT_WR) == 0);
    assert(pthread_join(wss_thread, NULL) == 0);
    struct pollfd client_wait = {.fd = client, .events = POLLIN};
    assert(poll(&client_wait, 1, 5000) > 0);
    uint8_t response[sizeof(wss.response_packet)];
    assert(recv(client, response, sizeof(response), 0) == 0);
    assert(wss.accepted_count == 1 && atomic_load(&wss.complete) == 1);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.wss_attempts == 1 && stats.wss_failures == 1 &&
           stats.wss_responses == 0 && counted_connect_attempts == 1);
    assert(stats.last_failure_dc > 0 &&
           stats.last_failure_route == TG_ROUTE_DIRECT_WSS &&
           stats.last_failure_stage == TG_EPOLL_FAILURE_MTPROTO);
    counted_connect_port = 0;
    counted_connect_attempts = 0;
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(wss.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_epoll_wss_partial_response_does_not_replay_request(void) {
    char directory[] = "/tmp/d2k-tg-wss-partial-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, proxy_port;
    wss_server_fixture wss = {.listener = create_listener(&ws_port),
                              .cert_path = cert_path,
                              .key_path = key_path,
                              .expect_binary_subprotocol = 1,
                              .response_prefix_len = 4};
    atomic_init(&wss.complete, 0);
    prepare_wss_response(&wss, test_handshake, TG_MTPROTO_INTERMEDIATE);
    const uint8_t clear_packet[12] = {8,0,0,0,0x11,0x22,0x33,0x44,
                                      0x55,0x66,0x77,0x88};
    memcpy(wss.expected_packet, clear_packet, sizeof(clear_packet));
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    assert(tg_mtproto_direct_stream_ciphers(test_handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, wss.expected_packet,
                              sizeof(wss.expected_packet)) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);
    pthread_t wss_thread;
    assert(pthread_create(&wss_thread, NULL, serve_direct_wss, &wss) == 0);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);
    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    assert(send(client, wss.expected_packet, sizeof(wss.expected_packet), 0) ==
           (ssize_t)sizeof(wss.expected_packet));
    assert(shutdown(client, SHUT_WR) == 0);
    uint8_t unexpected;
    assert(recv(client, &unexpected, sizeof(unexpected), 0) == 0);
    assert(pthread_join(wss_thread, NULL) == 0);
    assert(atomic_load(&wss.complete) == 1);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    assert(fixture.routes == 1);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.wss_attempts == 1 && stats.wss_failures == 1 &&
           stats.wss_responses == 0);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(wss.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static int select_raw_worker_endpoint(
    void *opaque, const tg_listener_destination *original,
    const uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN],
    tg_epoll_route_selection *selection) {
    proxy_fixture *fixture = opaque;
    tg_mtproto_init parsed;
    ++fixture->routes;
    if ((original->port != 443 && original->port != 5222) ||
        tg_mtproto_parse_obfuscated2(handshake, &parsed) != 0)
        return -1;
    selection->dc_id = parsed.dc_id;
    selection->is_media = parsed.is_media;
    selection->tcp_only = 1;
    selection->proto = parsed.proto;
    selection->upstream = fixture->upstream;
    return 0;
}

int tg_epoll_proxy_test_worker_pool_take(int fd, SSL *ssl,
                                      const char *hostname, const char *path);

static void test_worker_pool_requires_exact_target(void) {
    uint16_t port;
    int listener = create_listener(&port);
    int fd = connect_to_listener(port);
    int peer = accept(listener, NULL, NULL);
    assert(peer >= 0);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    assert(ctx);
    SSL *ssl = SSL_new(ctx);
    assert(ssl && SSL_set_fd(ssl, fd) == 1);
    assert(tg_epoll_proxy_test_worker_pool_take(fd, ssl, "worker.test",
        "/apiws?dst=149.154.167.151&dc=2&media=1") == 0);
    assert(tg_epoll_proxy_test_worker_pool_take(fd, ssl, "worker.test",
        "/apiws?dst=149.154.167.51&dc=2&media=0") == 0);
    assert(tg_epoll_proxy_test_worker_pool_take(fd, ssl, "worker.test",
        "/apiws?dst=149.154.167.51&dc=4&media=1") == 0);
    assert(tg_epoll_proxy_test_worker_pool_take(fd, ssl, "worker.test",
        "/d2o/apiws/5222?dst=149.154.167.51&dc=2&media=1") == 0);
    assert(tg_epoll_proxy_test_worker_pool_take(fd, ssl, "other.test",
        "/apiws?dst=149.154.167.51&dc=2&media=1") == 0);
    assert(tg_epoll_proxy_test_worker_pool_take(fd, ssl, "worker.test",
        "/apiws?dst=149.154.167.51&dc=2&media=1") == 1);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(peer);
    close(fd);
    close(listener);
}

static void test_epoll_cf_worker_uses_raw_stream_framing(uint16_t raw_port,
                                                        int legacy_worker,
                                                        int slow_proxy, uint32_t dc,
                                                        const char *dc_address, int media) {
    char directory[] = "/tmp/d2k-tg-worker-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, proxy_port;
    uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN];
    make_wss_test_handshake(TG_MTPROTO_INTERMEDIATE, dc, media, handshake);
    char path[128];
    int path_len = snprintf(path, sizeof(path), "%s?dst=%s&dc=%u&media=%d",
        raw_port == 5222 ? "/d2o/apiws/5222" : "/apiws",
        dc_address, dc, media);
    assert(path_len > 0 && (size_t)path_len < sizeof(path));
    wss_server_fixture worker = {
        .listener = create_listener(&ws_port),
        .cert_path = cert_path,
        .key_path = key_path,
        .expected_sni = "worker.test",
        .expected_path = path,
        .required_subprotocol = raw_port == 5222 ? "d2o-tcp-5222-v1" : NULL,
        .omit_subprotocol = legacy_worker,
        .expect_binary_subprotocol = 0,
        .expect_no_browser_headers = 1
    };
    atomic_init(&worker.complete, 0);
    memcpy(worker.handshake, handshake, sizeof(handshake));
    worker.handshake_len = sizeof(handshake);
    prepare_wss_response(&worker, handshake, TG_MTPROTO_INTERMEDIATE);
    const uint8_t clear_packet[12] = {8,0,0,0,0x11,0x22,0x33,0x44,
                                      0x55,0x66,0x77,0x88};
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    memcpy(worker.expected_packet, clear_packet, sizeof(clear_packet));
    assert(tg_mtproto_direct_stream_ciphers(handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, worker.expected_packet,
                              sizeof(worker.expected_packet)) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);
    pthread_t worker_thread;
    assert(pthread_create(&worker_thread, NULL, serve_direct_wss, &worker) == 0);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    fixture.original.family = strchr(dc_address, ':') ? AF_INET6 : AF_INET;
    fixture.original.port = raw_port ? raw_port : 443;
    assert(inet_pton(fixture.original.family, dc_address, fixture.original.address) == 1);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {0};
    uint16_t slow_port;
    int slow_listener = slow_proxy ? create_listener(&slow_port) : -1;
    routing.ws_routing = slow_proxy ? TG_WS_ROUTING_ADAPTIVE : TG_WS_ROUTING_CF_FIRST;
    routing.ws_hedge_delay_ms = 25;
    routing.ws_hedge_limit = 1;
    routing.cf_worker_domain_count = 1;
    memcpy(routing.cf_worker_domains[0], "worker.test", sizeof("worker.test"));
    routing.cf_proxy_domain_count = slow_proxy ? 1 : 0;
    memcpy(routing.cf_proxy_domains[0], "cfproxy-b.test", sizeof("cfproxy-b.test"));
    if (slow_proxy) set_ipv4(&fixture.cf_proxy_b_upstream, "127.0.0.1", slow_port);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .cloudflare_only = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .resolve_domain = resolve_test_route_domain,
        .route_context = &fixture,
        .original_destination = original_destination,
        .select_target = select_target,
        .select_route = raw_port ? select_raw_worker_endpoint : NULL,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, handshake, sizeof(handshake), 0) ==
           (ssize_t)sizeof(handshake));
    assert(send(client, worker.expected_packet,
                sizeof(worker.expected_packet), 0) ==
           (ssize_t)sizeof(worker.expected_packet));
    assert(shutdown(client, SHUT_WR) == 0);
    if (legacy_worker) {
        uint8_t unexpected;
        ssize_t n = recv(client, &unexpected, 1, 0);
        assert(n == 0 || (n < 0 && errno == ECONNRESET));
    } else {
        uint8_t echoed[sizeof(worker.response_packet)];
        size_t received = 0;
        while (received < worker.response_packet_len) {
            struct pollfd wait = {.fd = client, .events = POLLIN};
            assert(poll(&wait, 1, 5000) > 0);
            ssize_t n = recv(client, echoed + received,
                             worker.response_packet_len - received, 0);
            assert(n > 0);
            received += (size_t)n;
        }
        assert(memcmp(echoed, worker.response_packet,
                      worker.response_packet_len) == 0);
    }
    assert(pthread_join(worker_thread, NULL) == 0);
    assert(atomic_load(&worker.complete) == 1 && fixture.routes == 1);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_stats route_stats;
    assert(tg_epoll_proxy_get_stats(proxy, &route_stats) == 0);
    assert(route_stats.wss_attempts == (slow_proxy ? 2u : 1u));
    if (legacy_worker) {
        assert(route_stats.last_failure_route == TG_ROUTE_CF_WORKER);
        assert(route_stats.last_failure_stage == TG_EPOLL_FAILURE_WORKER_PORT);
    } else if (!raw_port) {
        assert(route_stats.wss_responses == 1 && route_stats.cf_wss_responses == 1);
    }
    if (slow_proxy) {
        assert(fixture.cf_proxy_b_resolve_calls == 1);
        close(slow_listener);
    }
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(worker.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_async_route_dns_waits_before_worker(void) {
    char directory[] = "/tmp/d2k-tg-worker-dns-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, closed_port, proxy_port;
    wss_server_fixture worker = {
        .listener = create_listener(&ws_port),
        .cert_path = cert_path,
        .key_path = key_path,
        .expected_sni = "worker.test",
        .expected_path = "/apiws?dst=149.154.167.51&dc=4&media=1",
        .expect_binary_subprotocol = 0,
        .expect_no_browser_headers = 1
    };
    atomic_init(&worker.complete, 0);
    prepare_wss_response(&worker, test_handshake, TG_MTPROTO_INTERMEDIATE);
    const uint8_t clear_packet[12] = {8,0,0,0,0x11,0x22,0x33,0x44,
                                      0x55,0x66,0x77,0x88};
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    memcpy(worker.expected_packet, clear_packet, sizeof(clear_packet));
    assert(tg_mtproto_direct_stream_ciphers(test_handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, worker.expected_packet,
                              sizeof(worker.expected_packet)) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);
    pthread_t worker_thread;
    assert(pthread_create(&worker_thread, NULL, serve_direct_wss, &worker) == 0);

    int closed_listener = create_listener(&closed_port);
    close(closed_listener);
    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    atomic_init(&fixture.dns_ready, 0);
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", closed_port);
    set_ipv4(&fixture.worker_upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {0};
    routing.ws_routing = TG_WS_ROUTING_CF_FIRST;
    routing.cf_worker_domain_count = 1;
    memcpy(routing.cf_worker_domains[0], "worker.test", sizeof("worker.test"));
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .resolve_domain = resolve_pending_test_route_domain,
        .route_context = &fixture,
        .original_destination = original_destination,
        .select_route = select_pending_test_route,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    assert(send(client, worker.expected_packet,
                sizeof(worker.expected_packet), 0) ==
           (ssize_t)sizeof(worker.expected_packet));
    assert(shutdown(client, SHUT_WR) == 0);
    struct pollfd wait = {.fd = client, .events = POLLIN};
    assert(poll(&wait, 1, 100) == 0);
    atomic_store(&fixture.dns_ready, 1);

    uint8_t echoed[sizeof(worker.response_packet)];
    size_t received = 0;
    while (received < worker.response_packet_len) {
        wait.revents = 0;
        assert(poll(&wait, 1, 5000) > 0);
        ssize_t n = recv(client, echoed + received,
                         worker.response_packet_len - received, 0);
        assert(n > 0);
        received += (size_t)n;
    }
    assert(memcmp(echoed, worker.response_packet,
                  worker.response_packet_len) == 0);
    assert(pthread_join(worker_thread, NULL) == 0);
    assert(atomic_load(&worker.complete) == 1 && fixture.routes == 1);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_stats route_stats;
    assert(tg_epoll_proxy_get_stats(proxy, &route_stats) == 0);
    assert(route_stats.wss_attempts == 1 && route_stats.wss_responses == 1 &&
           route_stats.cf_wss_responses == 1);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(worker.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_epoll_cf_proxy_preserves_media_dc_hostname_and_framing(void) {
    char directory[] = "/tmp/d2k-tg-cf-proxy-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, proxy_port;
    wss_server_fixture cf_proxy = {
        .listener = create_listener(&ws_port),
        .cert_path = cert_path,
        .key_path = key_path,
        .expected_sni = "kws203-1.cfproxy.test",
        .expected_path = "/apiws",
        .expect_binary_subprotocol = 1
    };
    atomic_init(&cf_proxy.complete, 0);
    uint8_t handshake[64];
    make_wss_test_handshake(TG_MTPROTO_INTERMEDIATE, 203, 1, handshake);
    memcpy(cf_proxy.handshake, handshake, sizeof(handshake));
    cf_proxy.handshake_len = sizeof(handshake);
    prepare_wss_response(&cf_proxy, handshake, TG_MTPROTO_INTERMEDIATE);
    const uint8_t clear_packet[12] = {8,0,0,0,0x11,0x22,0x33,0x44,
                                      0x55,0x66,0x77,0x88};
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    memcpy(cf_proxy.expected_packet, clear_packet, sizeof(clear_packet));
    assert(tg_mtproto_direct_stream_ciphers(handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, cf_proxy.expected_packet,
                              sizeof(cf_proxy.expected_packet)) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);
    pthread_t cf_thread;
    assert(pthread_create(&cf_thread, NULL, serve_direct_wss, &cf_proxy) == 0);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {0};
    routing.ws_routing = TG_WS_ROUTING_CF_FIRST;
    routing.cf_proxy_domain_count = 1;
    memcpy(routing.cf_proxy_domains[0], "cfproxy.test", sizeof("cfproxy.test"));
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .resolve_domain = resolve_test_route_domain,
        .route_context = &fixture,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, handshake, sizeof(handshake), 0) ==
           (ssize_t)sizeof(handshake));
    assert(send(client, cf_proxy.expected_packet,
                sizeof(cf_proxy.expected_packet), 0) ==
           (ssize_t)sizeof(cf_proxy.expected_packet));
    assert(shutdown(client, SHUT_WR) == 0);
    uint8_t echoed[sizeof(cf_proxy.response_packet)];
    size_t received = 0;
    while (received < cf_proxy.response_packet_len) {
        struct pollfd wait = {.fd = client, .events = POLLIN};
        assert(poll(&wait, 1, 5000) > 0);
        ssize_t n = recv(client, echoed + received,
                         cf_proxy.response_packet_len - received, 0);
        assert(n > 0);
        received += (size_t)n;
    }
    assert(memcmp(echoed, cf_proxy.response_packet,
                  cf_proxy.response_packet_len) == 0);
    assert(pthread_join(cf_thread, NULL) == 0);
    assert(atomic_load(&cf_proxy.complete) == 1 && fixture.routes == 1);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_stats route_stats;
    assert(tg_epoll_proxy_get_stats(proxy, &route_stats) == 0);
    assert(route_stats.wss_attempts == 1 && route_stats.wss_responses == 1 &&
           route_stats.cf_wss_responses == 1);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(cf_proxy.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_epoll_reuses_confirmed_media_route_across_ips(void) {
    char directory[] = "/tmp/d2k-tg-route-reuse-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, direct_port, proxy_port;
    wss_server_fixture cf_proxy = {
        .listener = create_listener(&ws_port),
        .cert_path = cert_path,
        .key_path = key_path,
        .expected_sni = "kws4-1.cfproxy-b.test",
        .expected_path = "/apiws",
        .expect_binary_subprotocol = 1
    };
    atomic_init(&cf_proxy.complete, 0);
    uint8_t handshake[64];
    make_wss_test_handshake(TG_MTPROTO_INTERMEDIATE, 4, 1, handshake);
    memcpy(cf_proxy.handshake, handshake, sizeof(handshake));
    cf_proxy.handshake_len = sizeof(handshake);
    prepare_wss_response(&cf_proxy, handshake, TG_MTPROTO_INTERMEDIATE);
    const uint8_t clear_packet[12] = {8,0,0,0,0x11,0x22,0x33,0x44,
                                      0x55,0x66,0x77,0x88};
    memcpy(cf_proxy.expected_packet, clear_packet, sizeof(clear_packet));
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    assert(tg_mtproto_direct_stream_ciphers(handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, cf_proxy.expected_packet,
                              sizeof(cf_proxy.expected_packet)) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);

    int direct_listener = create_listener(&direct_port);
    assert(close(direct_listener) == 0);
    direct_listener = -1;

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    pthread_mutex_t original_mutex;
    assert(pthread_mutex_init(&original_mutex, NULL) == 0);
    fixture.original_mutex = &original_mutex;
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    fixture.cf_proxy_b_upstream = fixture.upstream;
    set_ipv4(&fixture.direct_upstream, "127.0.0.1", direct_port);
    atomic_init(&fixture.fail_cf_proxy_a_dns, 1);
    counted_connect_port = direct_port;
    counted_connect_attempts = 0;
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {0};
    routing.ws_routing = TG_WS_ROUTING_ADAPTIVE;
    routing.cf_proxy_domain_count = 2;
    memcpy(routing.cf_proxy_domains[0], "cfproxy-a.test", sizeof("cfproxy-a.test"));
    memcpy(routing.cf_proxy_domains[1], "cfproxy-b.test", sizeof("cfproxy-b.test"));
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .resolve_domain = resolve_test_route_domain,
        .route_context = &fixture,
        .original_destination = original_destination,
        .select_route = select_pending_test_route,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    enum { LATENCY_REUSE_SAMPLES = 20 };
    uint64_t client_latency_us[LATENCY_REUSE_SAMPLES];
    pthread_t cf_thread;
    for (size_t i = 0; i < LATENCY_REUSE_SAMPLES; ++i) {
        assert(pthread_mutex_lock(&original_mutex) == 0);
        if (i % 2u)
            set_ipv6(&fixture.original, "2001:db8::43", 443);
        else
            set_ipv4(&fixture.original, "149.154.167.51", 443);
        assert(pthread_mutex_unlock(&original_mutex) == 0);
        atomic_store(&cf_proxy.complete, 0);
        assert(pthread_create(&cf_thread, NULL, serve_direct_wss,
                              &cf_proxy) == 0);
        int client = exchange_wss_test_client(proxy_port, handshake,
            cf_proxy.expected_packet, sizeof(cf_proxy.expected_packet),
            cf_proxy.response_packet, cf_proxy.response_packet_len,
            &client_latency_us[i]);
        assert(pthread_join(cf_thread, NULL) == 0);
        assert(atomic_load(&cf_proxy.complete) == 1);
        close(client);
        if (i == 0) {
            /* A cold route tries both direct WSS hostnames before CF. */
            assert(counted_connect_attempts == 2);
            atomic_fetch_add(&test_monotonic_offset_ms, 180000u);
        }
        if (i == 1) assert(counted_connect_attempts == 2);
    }

    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.wss_responses == LATENCY_REUSE_SAMPLES &&
           stats.cf_wss_responses == LATENCY_REUSE_SAMPLES);
    assert(stats.client_response_latency_total == LATENCY_REUSE_SAMPLES &&
           stats.client_response_latency_samples == LATENCY_REUSE_SAMPLES &&
           stats.client_response_latency_p50_us > 0 &&
           stats.client_response_latency_p95_us >=
               stats.client_response_latency_p50_us);
    assert(fixture.cf_proxy_a_resolve_calls == 2u &&
           fixture.cf_proxy_b_resolve_calls == LATENCY_REUSE_SAMPLES &&
           fixture.routes == LATENCY_REUSE_SAMPLES &&
           counted_connect_attempts == 2);
    uint64_t reconnect_samples[LATENCY_REUSE_SAMPLES - 1u];
    memcpy(reconnect_samples, client_latency_us + 1u,
           sizeof(reconnect_samples));
    for (size_t i = 1; i < LATENCY_REUSE_SAMPLES - 1u; ++i) {
        uint64_t value = reconnect_samples[i];
        size_t j = i;
        while (j && reconnect_samples[j - 1u] > value) {
            reconnect_samples[j] = reconnect_samples[j - 1u];
            --j;
        }
        reconnect_samples[j] = value;
    }
    size_t reconnect_p50 =
        ((LATENCY_REUSE_SAMPLES - 1u) * 50u + 99u) / 100u - 1u;
    size_t reconnect_p95 =
        ((LATENCY_REUSE_SAMPLES - 1u) * 95u + 99u) / 100u - 1u;
    assert(client_latency_us[0] < 200000u);
    assert(reconnect_samples[reconnect_p95] < 100000u);
    printf("Лабораторная задержка первого ответа через CF Proxy: "
           "первая=%" PRIu64 " мкс, переподключение p50=%" PRIu64
           " мкс p95=%" PRIu64 " мкс; подтверждено ответов=%zu\n",
           client_latency_us[0], reconnect_samples[reconnect_p50],
           reconnect_samples[reconnect_p95], (size_t)LATENCY_REUSE_SAMPLES);
    atomic_store(&test_monotonic_offset_ms, 0);
    counted_connect_port = 0;
    counted_connect_attempts = 0;
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(cf_proxy.listener);
    if (direct_listener >= 0) close(direct_listener);
    assert(pthread_mutex_destroy(&original_mutex) == 0);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void exchange_wss_test_fixture(uint16_t proxy_port,
                                      const uint8_t handshake[64],
                                      wss_server_fixture *upstream) {
    atomic_store(&upstream->complete, 0);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, serve_direct_wss, upstream) == 0);
    int client = exchange_wss_test_client(proxy_port, handshake,
        upstream->expected_packet, sizeof(upstream->expected_packet),
        upstream->response_packet, upstream->response_packet_len, NULL);
    assert(pthread_join(thread, NULL) == 0);
    assert(atomic_load(&upstream->complete) == 1);
    close(client);
}

static void test_epoll_cools_down_cf_proxy_after_dns_failure(void) {
    char directory[] = "/tmp/d2k-tg-route-dns-health-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t a_port, b_port, proxy_port;
    wss_server_fixture route_a = {
        .listener = create_listener(&a_port),
        .cert_path = cert_path,
        .key_path = key_path,
        .expected_sni = "kws4-1.cfproxy-a.test",
        .expected_path = "/apiws",
        .expect_binary_subprotocol = 1
    };
    wss_server_fixture route_b = {
        .listener = create_listener(&b_port),
        .cert_path = cert_path,
        .key_path = key_path,
        .expected_sni = "kws4-1.cfproxy-b.test",
        .expected_path = "/apiws",
        .expect_binary_subprotocol = 1,
        .response_delay_ms = 80
    };
    atomic_init(&route_a.complete, 0);
    atomic_init(&route_b.complete, 0);
    uint8_t handshake[64];
    make_wss_test_handshake(TG_MTPROTO_INTERMEDIATE, 4, 1, handshake);
    memcpy(route_a.handshake, handshake, sizeof(handshake));
    memcpy(route_b.handshake, handshake, sizeof(handshake));
    route_a.handshake_len = sizeof(handshake);
    route_b.handshake_len = sizeof(handshake);
    prepare_wss_response(&route_a, handshake, TG_MTPROTO_INTERMEDIATE);
    prepare_wss_response(&route_b, handshake, TG_MTPROTO_INTERMEDIATE);
    const uint8_t clear_packet[12] = {8,0,0,0,0x11,0x22,0x33,0x44,
                                      0x55,0x66,0x77,0x88};
    memcpy(route_a.expected_packet, clear_packet, sizeof(clear_packet));
    memcpy(route_b.expected_packet, clear_packet, sizeof(clear_packet));
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    assert(tg_mtproto_direct_stream_ciphers(handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, route_a.expected_packet,
                              sizeof(route_a.expected_packet)) == 0);
    memcpy(route_b.expected_packet, route_a.expected_packet,
           sizeof(route_b.expected_packet));
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    atomic_init(&fixture.fail_cf_proxy_a_dns, 0);
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", a_port);
    set_ipv4(&fixture.cf_proxy_b_upstream, "127.0.0.1", b_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {0};
    routing.ws_routing = TG_WS_ROUTING_CF_FIRST;
    routing.cf_proxy_domain_count = 2;
    memcpy(routing.cf_proxy_domains[0], "cfproxy-a.test",
           sizeof("cfproxy-a.test"));
    memcpy(routing.cf_proxy_domains[1], "cfproxy-b.test",
           sizeof("cfproxy-b.test"));
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .resolve_domain = resolve_test_route_domain,
        .route_context = &fixture,
        .original_destination = original_destination,
        .select_route = select_pending_test_route,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    exchange_wss_test_fixture(proxy_port, handshake, &route_a);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    routing.ws_routing = TG_WS_ROUTING_ADAPTIVE;
    atomic_store(&fixture.fail_cf_proxy_a_dns, 1);
    atomic_store(&runner.stop, 0);
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);
    exchange_wss_test_fixture(proxy_port, handshake, &route_b);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    int saw_dns_cooldown = 0;
    for (size_t i = 0; i < stats.route_cooldowns_count; ++i) {
        const tg_route_cooldown *cooldown = &stats.route_cooldowns[i];
        if (cooldown->dc == 4 && cooldown->is_media &&
            cooldown->transport == TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_PROXY &&
            cooldown->failure_stage == TG_EPOLL_FAILURE_DNS)
            saw_dns_cooldown = 1;
    }
    assert(saw_dns_cooldown);
    assert(fixture.cf_proxy_a_resolve_calls == 3 &&
           fixture.cf_proxy_b_resolve_calls == 1);

    atomic_store(&runner.stop, 0);
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);
    exchange_wss_test_fixture(proxy_port, handshake, &route_b);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    assert(fixture.cf_proxy_a_resolve_calls == 3 &&
           fixture.cf_proxy_b_resolve_calls == 2);
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.wss_attempts == 3 && stats.wss_failures == 0 &&
           stats.wss_responses == 3 && stats.cf_wss_responses == 3);

    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(route_a.listener);
    close(route_b.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_wss_partial_frame_before_response_advances_route(void) {
    char directory[] = "/tmp/d2k-tg-wss-response-timeout-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, proxy_port;
    wss_server_fixture cf_proxy = {
        .listener = create_listener(&ws_port),
        .cert_path = cert_path,
        .key_path = key_path,
        .expected_sni = "kws4-1.cfproxy.test",
        .expected_path = "/apiws",
        .expect_binary_subprotocol = 1,
        .wait_for_fallback = 1,
        .partial_server_frame_before_fallback = 1
    };
    atomic_init(&cf_proxy.complete, 0);
    prepare_wss_response(&cf_proxy, test_handshake, TG_MTPROTO_INTERMEDIATE);
    pthread_t cf_thread;
    assert(pthread_create(&cf_thread, NULL, serve_direct_wss, &cf_proxy) == 0);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {0};
    routing.ws_routing = TG_WS_ROUTING_CF_FIRST;
    routing.cf_proxy_domain_count = 1;
    memcpy(routing.cf_proxy_domains[0], "cfproxy.test", sizeof("cfproxy.test"));
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 250,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .resolve_domain = resolve_test_route_domain,
        .route_context = &fixture,
        .original_destination = original_destination,
        .select_route = select_pending_test_route,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 4};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    uint8_t response[sizeof(cf_proxy.response_packet)];
    struct pollfd wait = {.fd = client, .events = POLLIN};
    assert(poll(&wait, 1, 3500) > 0);
    size_t received = 0;
    while (received < cf_proxy.response_packet_len) {
        ssize_t n = recv(client, response + received,
                         cf_proxy.response_packet_len - received, 0);
        assert(n > 0);
        received += (size_t)n;
    }
    assert(memcmp(response, cf_proxy.response_packet,
                  cf_proxy.response_packet_len) == 0);
    assert(shutdown(client, SHUT_WR) == 0);
    assert(pthread_join(cf_thread, NULL) == 0);
    assert(atomic_load(&cf_proxy.complete) == 1 &&
           cf_proxy.accepted_count == 2);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_stats route_stats;
    assert(tg_epoll_proxy_get_stats(proxy, &route_stats) == 0);
    assert(route_stats.wss_attempts == 2 && route_stats.wss_failures == 1 &&
           route_stats.wss_responses == 1 && route_stats.cf_wss_responses == 1);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(cf_proxy.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_epoll_falls_back_to_original_tcp_after_wss_failure(void) {
    char directory[] = "/tmp/d2k-tg-wss-fallback-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, proxy_port;
    wss_fallback_fixture fake = {.listener = create_listener(&ws_port),
                                 .cert_path = cert_path,
                                 .key_path = key_path};
    atomic_init(&fake.complete, 0);
    memcpy(fake.expected, test_handshake, sizeof(test_handshake));
    uint8_t *expected_packet = fake.expected + sizeof(test_handshake);
    memcpy(expected_packet, (uint8_t[]){8,0,0,0,0x11,0x22,0x33,0x44,
                                        0x55,0x66,0x77,0x88}, 12);
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    assert(tg_mtproto_direct_stream_ciphers(test_handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, expected_packet, 12) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);
    pthread_t fake_thread;
    assert(pthread_create(&fake_thread, NULL, serve_rejected_wss_then_tcp,
                          &fake) == 0);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {.tcp_fallback_timeout_secs = 10};
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy && tg_epoll_proxy_max_connections(proxy) > 1);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, fake.expected, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    assert(send(client, expected_packet, 12, 0) == 12);
    assert(shutdown(client, SHUT_WR) == 0);
    uint8_t echoed[sizeof(fake.expected)];
    size_t received = 0;
    while (received < sizeof(echoed)) {
        struct pollfd wait = {.fd = client, .events = POLLIN};
        assert(poll(&wait, 1, 5000) > 0);
        ssize_t n = recv(client, echoed + received, sizeof(echoed) - received, 0);
        assert(n > 0);
        received += (size_t)n;
    }
    assert(memcmp(echoed, fake.expected, sizeof(echoed)) == 0);
    assert(pthread_join(fake_thread, NULL) == 0);
    assert(atomic_load(&fake.complete) == 1 && fixture.routes == 1);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_stats route_stats;
    assert(tg_epoll_proxy_get_stats(proxy, &route_stats) == 0);
    assert(route_stats.wss_attempts == 2 && route_stats.wss_failures == 2 &&
           route_stats.wss_responses == 0);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(fake.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_epoll_certificate_failure_keeps_diagnostic_tcp(void) {
    char directory[] = "/tmp/d2k-tg-wss-bad-cert-XXXXXX";
    char cert_path[256], key_path[256], trust_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/server.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/server-key.pem", directory) > 0);
    assert(snprintf(trust_path, sizeof(trust_path), "%s/unrelated-ca.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);
    EVP_PKEY *unrelated_key = make_wss_test_key();
    X509 *unrelated_cert = make_wss_test_cert(unrelated_key);
    file = fopen(trust_path, "w");
    assert(file && PEM_write_X509(file, unrelated_cert) == 1);
    fclose(file);
    X509_free(unrelated_cert);
    EVP_PKEY_free(unrelated_key);

    uint16_t ws_port, proxy_port;
    wss_fallback_fixture fake = {.listener = create_listener(&ws_port),
                                 .cert_path = cert_path,
                                 .key_path = key_path};
    atomic_init(&fake.complete, 0);
    memcpy(fake.expected, test_handshake, sizeof(test_handshake));
    uint8_t *expected_packet = fake.expected + sizeof(test_handshake);
    memcpy(expected_packet, (uint8_t[]){8,0,0,0,0x11,0x22,0x33,0x44,
                                        0x55,0x66,0x77,0x88}, 12);
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    assert(tg_mtproto_direct_stream_ciphers(test_handshake, &decrypt,
                                             &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, expected_packet, 12) == 0);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);
    pthread_t fake_thread;
    assert(pthread_create(&fake_thread, NULL, serve_bad_certificate_then_tcp,
                          &fake) == 0);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(trust_path);
    assert(tls_context);
    tg_config routing = {0};
    routing.diagnostic_direct_tcp = 1;
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy && tg_epoll_proxy_max_connections(proxy) > 1);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 5};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, fake.expected, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    assert(send(client, expected_packet, 12, 0) == 12);
    assert(shutdown(client, SHUT_WR) == 0);
    uint8_t echoed[sizeof(fake.expected)];
    size_t received = 0;
    while (received < sizeof(echoed)) {
        struct pollfd wait = {.fd = client, .events = POLLIN};
        assert(poll(&wait, 1, 5000) > 0);
        ssize_t n = recv(client, echoed + received, sizeof(echoed) - received, 0);
        assert(n > 0);
        received += (size_t)n;
    }
    assert(memcmp(echoed, fake.expected, sizeof(echoed)) == 0);
    assert(pthread_join(fake_thread, NULL) == 0);
    assert(atomic_load(&fake.complete) == 1 && fake.tls_rejections == 2);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    assert(fixture.routes == 1);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.wss_attempts == 2 && stats.wss_failures == 2 &&
           stats.wss_responses == 0);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(fake.listener);
    SSL_CTX_free(tls_context);
    unlink(trust_path);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_epoll_wss_sends_ping(void) {
    char directory[] = "/tmp/d2k-tg-wss-ping-XXXXXX";
    char cert_path[256], key_path[256];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    uint16_t ws_port, proxy_port;
    wss_server_fixture wss = {
        .listener = create_listener(&ws_port),
        .cert_path = cert_path,
        .key_path = key_path,
        .expected_sni = "kws4-1.web.telegram.org",
        .expected_path = "/apiws",
        .expect_binary_subprotocol = 1,
        .expect_ping_after_handshake = 1
    };
    atomic_init(&wss.complete, 0);
    memcpy(wss.handshake, test_handshake, sizeof(test_handshake));
    wss.handshake_len = sizeof(test_handshake);
    pthread_t wss_thread;
    assert(pthread_create(&wss_thread, NULL, serve_direct_wss, &wss) == 0);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {0};
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 5000,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &routing,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy_test_set_ping_interval_ms(80);
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);

    int client = connect_to_listener(proxy_port);
    struct timeval timeout = {.tv_sec = 4};
    assert(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    assert(pthread_join(wss_thread, NULL) == 0);
    assert(atomic_load(&wss.complete) == 1);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_test_set_ping_interval_ms(30000u);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(wss.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_adaptive_races_alternates_in_both_wss_branches(void) {
    uint16_t client_port, target_port;
    int listener = create_listener(&client_port);
    int target = create_listener(&target_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", target_port);
    fixture.cf_proxy_b_upstream = fixture.upstream;
    SSL_CTX *tls_context = SSL_CTX_new(TLS_client_method());
    assert(tls_context);
    tg_config routing = {
        .ws_routing = TG_WS_ROUTING_ADAPTIVE,
        .ws_hedge_delay_ms = 125, .ws_hedge_limit = 1,
        .cf_proxy_domain_count = 2,
        .cf_proxy_domains = {"cfproxy-a.test", "cfproxy-b.test"}
    };
    tg_epoll_proxy_config config = {
        .listener_fd = listener, .queue_bytes = 4096,
        .memory_budget_bytes = 16 * 1024 * 1024, .configured_max_connections = 8,
        .handshake_timeout_ms = 5000, .idle_timeout_ms = 6000,
        .enable_direct_wss = 1, .tls_context = tls_context, .routing_config = &routing,
        .original_destination = original_destination, .select_route = select_pending_test_route,
        .resolve_domain = resolve_test_route_domain, .route_context = &fixture,
        .context = &fixture
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    int client = connect_to_listener(client_port);
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    step_many(proxy, 5);
    for (unsigned i = 0; i < 3; ++i) {
        atomic_fetch_add(&test_monotonic_offset_ms, 126u);
        step_many(proxy, 3);
    }
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.wss_attempts == 4 && stats.active_wss_connections == 4);
    assert(fixture.cf_proxy_a_resolve_calls == 1 && fixture.cf_proxy_b_resolve_calls == 1);
    close(client);
    tg_epoll_proxy_destroy(proxy);
    close(target);
    close(listener);
    SSL_CTX_free(tls_context);
    atomic_store(&test_monotonic_offset_ms, 0);
}

static void test_listener_recovery_preserves_runtime(void) {
    uint16_t port, replacement_port;
    int listener = create_listener(&port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    tg_epoll_proxy_config config = {
        .listener_fd = listener, .queue_bytes = 4096,
        .memory_budget_bytes = 1024 * 1024, .configured_max_connections = 4,
        .handshake_timeout_ms = 1000, .idle_timeout_ms = 5000,
        .original_destination = original_destination, .select_target = select_target,
        .context = &fixture
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy);
    int pending = connect_to_listener(port);
    accept_error = EMFILE;
    for (unsigned i = 0; i < 6; ++i) {
        assert(tg_epoll_proxy_step(proxy, 0) >= 0);
        atomic_fetch_add(&test_monotonic_offset_ms, 501u);
        assert(tg_epoll_proxy_step(proxy, 0) >= 0);
    }
    accept_error = EIO;
    for (unsigned i = 0; i < 4; ++i) {
        assert(tg_epoll_proxy_step(proxy, 0) >= 0);
        atomic_fetch_add(&test_monotonic_offset_ms, 51u);
        assert(tg_epoll_proxy_step(proxy, 0) >= 0);
    }
    assert(tg_epoll_proxy_step(proxy, 0) == TG_EPOLL_REBIND_LISTENER);
    assert(tg_epoll_proxy_set_listener(proxy, -1) == 0);
    close(listener);
    close(pending);
    accept_error = 0;
    int replacement = create_listener(&replacement_port);
    assert(tg_epoll_proxy_set_listener(proxy, replacement) == 0);
    int client = connect_to_listener(replacement_port);
    assert(tg_epoll_proxy_step(proxy, 100) > 0);
    assert(tg_epoll_proxy_active_connections(proxy) == 1);
    close(client);
    tg_epoll_proxy_destroy(proxy);
    close(replacement);
    atomic_store(&test_monotonic_offset_ms, 0);
}

static void test_small_fd_limit_keeps_a_client_slot(void) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        const struct rlimit fd_limit = {.rlim_cur = 48, .rlim_max = 48};
        assert(setrlimit(RLIMIT_NOFILE, &fd_limit) == 0);
        uint16_t port;
        int listener = create_listener(&port);
        SSL_CTX *tls_context = SSL_CTX_new(TLS_client_method());
        assert(tls_context);
        const tg_config routing = {.ws_hedge_limit = 8};
        tg_epoll_proxy_config config = {
            .listener_fd = listener,
            .queue_bytes = 65536,
            .memory_budget_bytes = 8u * 1024u * 1024u,
            .configured_max_connections = 1,
            .handshake_timeout_ms = 1000,
            .idle_timeout_ms = 5000,
            .enable_direct_wss = 1,
            .tls_context = tls_context,
            .routing_config = &routing,
            .select_target = select_target
        };
        tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
        assert(proxy && tg_epoll_proxy_max_connections(proxy) == 1);
        tg_epoll_proxy_destroy(proxy);
        SSL_CTX_free(tls_context);
        close(listener);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

typedef struct {
    wss_server_fixture upstream[4];
    tg_listener_destination targets[4];
    int fail_dc4_proxy;
} memory_recovery_fixture;

static int resolve_memory_test_route(void *opaque, const char *hostname,
                                     tg_listener_destination *out) {
    memory_recovery_fixture *fixture = opaque;
    /* DC4 media must fail both Proxy variants before reaching Worker. */
    if (fixture->fail_dc4_proxy && strcmp(hostname, "kws4.cfproxy.test") == 0)
        return -1;
    for (size_t i = 0; i < 4; ++i) {
        if (strcmp(hostname, fixture->upstream[i].expected_sni) == 0) {
            *out = fixture->targets[i];
            return 0;
        }
    }
    return -1;
}

static void receive_exact_client(int fd, uint8_t *data, size_t len) {
    while (len) {
        ssize_t received = recv(fd, data, len, 0);
        assert(received > 0);
        data += (size_t)received;
        len -= (size_t)received;
    }
}

typedef struct {
    int fd;
    wss_server_fixture *upstream;
} media_test_client;

static void *read_media_test_client(void *opaque) {
    const media_test_client *client = opaque;
    wss_server_fixture *upstream = client->upstream;
    uint8_t data[TEST_MEDIA_CHUNK];
    receive_exact_client(client->fd, data, upstream->response_packet_len);
    assert(memcmp(data, upstream->response_packet, upstream->response_packet_len) == 0);
    if (!upstream->media_chunks) return NULL;
    tg_mtproto_ctr cipher = {0};
    assert(tg_mtproto_direct_server_stream_cipher(upstream->handshake, &cipher) == 0);
    assert(tg_mtproto_ctr_xor(&cipher, data, upstream->response_packet_len) == 0);
    for (size_t i = 0; i < upstream->media_chunks; ++i) {
        receive_exact_client(client->fd, data, sizeof(data));
        assert(tg_mtproto_ctr_xor(&cipher, data, sizeof(data)) == 0);
        assert(memcmp(data, (uint8_t[]){0xfc, 0x3f, 0, 0}, 4) == 0);
        for (size_t j = 4; j < sizeof(data); ++j) assert(data[j] == (uint8_t)(i + 1u));
    }
    tg_mtproto_ctr_destroy(&cipher);
    return NULL;
}

static void test_media_after_low_memory_start(size_t media_chunks) {
    char directory[] = "/tmp/d2k-tg-memory-XXXXXX", cert_path[256], key_path[256];
    assert(mkdtemp(directory));
    assert(snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", directory) > 0);
    assert(snprintf(key_path, sizeof(key_path), "%s/key.pem", directory) > 0);
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    memory_recovery_fixture fixture = {0};
    static const char *const sni[] = {
        "kws4.cfproxy.test", "kws2.cfproxy.test", "kws2-1.cfproxy.test", "worker.test"
    };
    static const uint32_t dc[] = {4, 2, 2, 4};
    pthread_t upstream_threads[4], readers[2];
    media_test_client clients[4];
    for (size_t i = 0; i < 4; ++i) {
        uint16_t port;
        wss_server_fixture *upstream = &fixture.upstream[i];
        upstream->listener = create_listener(&port);
        upstream->cert_path = cert_path;
        upstream->key_path = key_path;
        upstream->expected_sni = sni[i];
        upstream->expected_path = i == 3
            ? "/apiws?dst=149.154.167.51&dc=4&media=1" : "/apiws";
        upstream->expect_binary_subprotocol = i != 3;
        upstream->expect_no_browser_headers = i == 3;
        upstream->media_chunks = i >= 2 ? media_chunks : 0;
        upstream->repeat_response = i < 2;
        upstream->handshake_len = sizeof(upstream->handshake);
        atomic_init(&upstream->complete, 0);
        make_wss_test_handshake(TG_MTPROTO_INTERMEDIATE, dc[i], i >= 2,
                                upstream->handshake);
        prepare_wss_response(upstream, upstream->handshake, TG_MTPROTO_INTERMEDIATE);
        memcpy(upstream->expected_packet, (uint8_t[]){8,0,0,0,1,2,3,4,5,6,7,8}, 12);
        tg_mtproto_ctr decrypt = {0}, encrypt = {0};
        assert(tg_mtproto_direct_stream_ciphers(upstream->handshake, &decrypt, &encrypt) == 0);
        assert(tg_mtproto_ctr_xor(&encrypt, upstream->expected_packet, 12) == 0);
        tg_mtproto_ctr_destroy(&decrypt);
        tg_mtproto_ctr_destroy(&encrypt);
        set_ipv4(&fixture.targets[i], "127.0.0.1", port);
        assert(pthread_create(&upstream_threads[i], NULL, serve_direct_wss, upstream) == 0);
    }

    uint16_t proxy_port;
    int listener = create_listener(&proxy_port);
    proxy_fixture target = {0};
    set_ipv4(&target.original, "149.154.167.51", 443);
    target.upstream = fixture.targets[0];
    tg_config routing = {.ws_routing = TG_WS_ROUTING_CF_FIRST};
    routing.cf_proxy_domain_count = 1;
    routing.cf_worker_domain_count = 1;
    memcpy(routing.cf_proxy_domains[0], "cfproxy.test", sizeof("cfproxy.test"));
    memcpy(routing.cf_worker_domains[0], "worker.test", sizeof("worker.test"));
    SSL_CTX *tls = tg_tls_client_context(cert_path);
    assert(tls);
    const size_t mib = 1024u * 1024u, total = 128u * mib, configured = 32;
    const size_t cold = 8u * mib, recovered = 48u * mib;
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 64u * 1024u,
        .configured_max_connections = configured,
        .initial_connection_limit = tg_limits_policy_connections(
            tg_limits_soft_nofile(), total, cold, configured),
        .memory_budget_bytes = tg_limits_runtime_memory_budget(total, cold),
        .handshake_timeout_ms = 3000,
        .idle_timeout_ms = 30000,
        .enable_direct_wss = 1,
        .cloudflare_only = 1,
        .tls_context = tls,
        .routing_config = &routing,
        .resolve_domain = resolve_memory_test_route,
        .route_context = &fixture,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &target
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy && tg_epoll_proxy_max_connections(proxy) == 2);
    proxy_runner runner = {.server = proxy};
    atomic_init(&runner.stop, 0);
    pthread_t proxy_thread;
    uint64_t media_started_us = 0;
    assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);
    for (size_t i = 0; i < 4; ++i) {
        if (i == 2) {
            atomic_store(&runner.stop, 1);
            assert(pthread_join(proxy_thread, NULL) == 0);
            assert(tg_epoll_proxy_active_connections(proxy) == 2);
            /* Under pressure there is no room for another session, but the
             * already allocated buffers must remain usable. */
            size_t ceiling = tg_limits_runtime_memory_budget(total, total);
            size_t admission = tg_limits_policy_admission(tg_limits_soft_nofile(),
                total, 0, configured, tg_epoll_proxy_active_connections(proxy));
            tg_epoll_proxy_update_limits(proxy, admission, 0, ceiling);
            tg_epoll_proxy_stats pressure;
            assert(tg_epoll_proxy_get_stats(proxy, &pressure) == 0);
            assert(pressure.buffer_bytes_current > 0);
            assert(pressure.buffer_bytes_limit == pressure.buffer_bytes_current);
            assert(pressure.max_connections == 2 && pressure.active_connections == 2);
            int rejected = connect_to_listener(proxy_port);
            assert(tg_epoll_proxy_step(proxy, 0) >= 0);
            uint8_t byte;
            assert(recv(rejected, &byte, sizeof(byte), MSG_DONTWAIT) == 0);
            close(rejected);
            assert(tg_epoll_proxy_get_stats(proxy, &pressure) == 0);
            assert(pressure.accept_limit_rejections == 1);
            fixture.fail_dc4_proxy = 1;
            tg_epoll_proxy_update_limits(proxy,
                tg_limits_policy_connections(tg_limits_soft_nofile(),
                                             total, recovered, configured),
                tg_limits_runtime_memory_budget(total, recovered),
                tg_limits_runtime_memory_budget(total, total));
            atomic_store(&runner.stop, 0);
            assert(pthread_create(&proxy_thread, NULL, run_proxy, &runner) == 0);
            media_started_us = test_monotonic_us();
        }
        clients[i].fd = connect_to_listener(proxy_port);
        clients[i].upstream = &fixture.upstream[i];
        struct timeval timeout = {.tv_sec = 10};
        assert(setsockopt(clients[i].fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        assert(send(clients[i].fd, fixture.upstream[i].handshake, 64, MSG_NOSIGNAL) == 64);
        assert(send(clients[i].fd, fixture.upstream[i].expected_packet, 12, MSG_NOSIGNAL) == 12);
        if (i < 2) read_media_test_client(&clients[i]);
        else assert(pthread_create(&readers[i - 2], NULL, read_media_test_client, &clients[i]) == 0);
    }
    uint64_t text_latency_us = 0;
    /* Send a second valid transport packet on each established text stream
     * while the media readers and writers are running. */
    for (size_t i = 0; i < 2; ++i) {
        wss_server_fixture *upstream = clients[i].upstream;
        uint8_t packet[] = {8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t discarded[sizeof(packet)] = {0};
        tg_mtproto_ctr decrypt = {0}, encrypt = {0};
        assert(tg_mtproto_direct_stream_ciphers(upstream->handshake, &decrypt, &encrypt) == 0);
        assert(tg_mtproto_ctr_xor(&encrypt, discarded, sizeof(discarded)) == 0);
        assert(tg_mtproto_ctr_xor(&encrypt, packet, sizeof(packet)) == 0);
        tg_mtproto_ctr_destroy(&decrypt);
        tg_mtproto_ctr_destroy(&encrypt);
        uint64_t sent_us = test_monotonic_us();
        assert(send(clients[i].fd, packet, sizeof(packet), MSG_NOSIGNAL) == (ssize_t)sizeof(packet));
        read_media_test_client(&clients[i]);
        uint64_t elapsed_us = test_monotonic_us() - sent_us;
        if (elapsed_us > text_latency_us) text_latency_us = elapsed_us;
    }
    for (size_t i = 0; i < 2; ++i) assert(pthread_join(readers[i], NULL) == 0);
    uint64_t media_elapsed_us = test_monotonic_us() - media_started_us;
    for (size_t i = 0; i < 4; ++i) {
        assert(shutdown(clients[i].fd, SHUT_WR) == 0);
        assert(pthread_join(upstream_threads[i], NULL) == 0);
        assert(atomic_load(&fixture.upstream[i].complete) == 1);
        close(clients[i].fd);
        close(fixture.upstream[i].listener);
    }
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_stats stats;
    assert(tg_epoll_proxy_get_stats(proxy, &stats) == 0);
    assert(stats.wss_responses == 4 && stats.cf_wss_responses == 4);
    assert(stats.buffer_bytes_peak < mib);
    assert(stats.buffer_budget_rejections == 0 && stats.allocation_failures == 0);
    assert(stats.wss_read_pauses == stats.wss_read_resumes && stats.wss_reads_paused == 0);
    printf("mixed traffic: 4/4, media 2/2, WSS buffer peak %zu bytes, "
           "media %zu bytes in %" PRIu64 " us, text max RTT %" PRIu64 " us\n",
           stats.buffer_bytes_peak, 2u * TEST_MEDIA_CHUNK * media_chunks,
           media_elapsed_us, text_latency_us);
    tg_epoll_proxy_destroy(proxy);
    SSL_CTX_free(tls);
    close(listener);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

int main(int argc, char **argv) {
    (void)signal(SIGPIPE, SIG_IGN);
    if (argc == 2) {
        test_media_after_low_memory_start((size_t)strtoul(argv[1], NULL, 10));
        return 0;
    }
    test_media_after_low_memory_start(512);
    test_small_fd_limit_keeps_a_client_slot();
    test_listener_recovery_preserves_runtime();
    test_adaptive_races_alternates_in_both_wss_branches();
    test_epoll_bridge_preserves_handshake_and_half_close();
    test_epoll_many_concurrent_tcp_clients();
    test_pending_tcp_connect_expires_before_idle_timeout();
    test_read_only_stats_socket();
    test_invalid_handshake_fails_closed();
    test_client_disconnect_during_route_selection();
    test_route_dns_failure_skips_worker();
    test_all_routes_unavailable_fail_closed(0);
    test_all_routes_unavailable_fail_closed(1);
    test_disabled_wss_does_not_enable_automatic_tcp();
    test_self_dial_target_is_rejected();
    test_epoll_wss_forwards_unrecognized_binary_response();
    test_epoll_wss_transport_ack_keeps_route_selected();
    test_epoll_hedged_wss_commits_one_route_before_payload(TG_MTPROTO_ABRIDGED, 0);
    test_epoll_hedged_wss_commits_one_route_before_payload(TG_MTPROTO_INTERMEDIATE, 0);
    test_epoll_hedged_wss_commits_one_route_before_payload(TG_MTPROTO_INTERMEDIATE, 1);
    test_epoll_hedged_wss_commits_one_route_before_payload(
        TG_MTPROTO_PADDED_INTERMEDIATE, 0);
    test_epoll_wss_partial_request_is_not_replayed();
    test_epoll_wss_partial_response_does_not_replay_request();
    static const struct { uint32_t dc; const char *address; } worker_dcs[] = {
        {1, "149.154.175.50"}, {2, "149.154.167.51"}, {3, "149.154.175.100"},
        {4, "149.154.167.91"}, {5, "149.154.171.5"}, {203, "91.105.192.100"}
    };
    test_worker_pool_requires_exact_target();
    for (size_t i = 0; i < sizeof(worker_dcs) / sizeof(worker_dcs[0]); ++i)
        test_epoll_cf_worker_uses_raw_stream_framing(
            0, 0, 0, worker_dcs[i].dc, worker_dcs[i].address, 0);
    /* Ordinary, dedicated media, and IPv6 destinations must survive the
     * Worker upgrade unchanged, including when Proxy is attempted first. */
    test_epoll_cf_worker_uses_raw_stream_framing(0, 0, 0, 2, "149.154.167.50", 0);
    test_epoll_cf_worker_uses_raw_stream_framing(0, 0, 0, 2, "149.154.167.151", 1);
    test_epoll_cf_worker_uses_raw_stream_framing(0, 0, 1, 4, "149.154.167.43", 1);
    test_epoll_cf_worker_uses_raw_stream_framing(0, 0, 0, 4, "2001:67c:4e8:f004::a", 0);
    test_epoll_cf_worker_uses_raw_stream_framing(443, 0, 0, 4, "149.154.167.51", 1);
    test_epoll_cf_worker_uses_raw_stream_framing(5222, 0, 0, 4, "149.154.167.51", 1);
    test_epoll_cf_worker_uses_raw_stream_framing(5222, 1, 0, 4, "149.154.167.51", 1);
    test_epoll_wss_sends_ping();
    test_async_route_dns_waits_before_worker();
    test_epoll_cf_proxy_preserves_media_dc_hostname_and_framing();
    test_epoll_reuses_confirmed_media_route_across_ips();
    test_epoll_cools_down_cf_proxy_after_dns_failure();
    test_wss_partial_frame_before_response_advances_route();
    test_epoll_falls_back_to_original_tcp_after_wss_failure();
    test_epoll_certificate_failure_keeps_diagnostic_tcp();
    puts("Тесты epoll-прокси Telegram: ок");
    return 0;
}
