#define _POSIX_C_SOURCE 200809L
#include "tg_epoll_proxy.h"
#include "tg_mtproto.h"
#include "tg_stats_socket.h"
#include "tg_tls.h"
#include "tg_ws.h"

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    tg_listener_destination original;
    tg_listener_destination upstream;
    size_t routes;
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
    int arbitrary_response;
    int wait_for_second;
    int accepted_count;
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
    atomic_int complete;
} wss_fallback_fixture;

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

static void make_wss_test_handshake(tg_mtproto_proto proto,
                                    uint8_t handshake[64]) {
    tg_mtproto_ctr to_server = {0}, from_server = {0};
    assert(tg_mtproto_make_obfuscated2_init(proto, 4, 1, handshake,
                                             &to_server, &from_server) == 0);
    tg_mtproto_ctr_destroy(&to_server);
    tg_mtproto_ctr_destroy(&from_server);
}

static int original_destination(void *opaque, int fd,
                                tg_listener_destination *out) {
    (void)fd;
    *out = ((proxy_fixture *)opaque)->original;
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

static int resolve_test_route_domain(void *opaque, const char *domain,
                                     tg_listener_destination *out) {
    proxy_fixture *fixture = opaque;
    if (strcmp(domain, "worker.test") != 0 &&
        strcmp(domain, "cfproxy.test") != 0) return -1;
    *out = fixture->upstream;
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
        "DNS:worker.test,DNS:cfproxy.test,IP:127.0.0.1");
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
    if (expect_binary_subprotocol)
        assert(strstr(request, "Sec-WebSocket-Protocol: binary\r\n"));
    else
        assert(!strstr(request, "Sec-WebSocket-Protocol:"));
    assert(strstr(request, "Origin: https://web.telegram.org\r\n"));
    assert(strstr(request, "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
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
    int response_len = snprintf(response, sizeof(response),
        expect_binary_subprotocol
        ? "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
          "Connection: Upgrade\r\nSec-WebSocket-Protocol: binary\r\n"
          "Sec-WebSocket-Accept: %s\r\n\r\n"
        : "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
          "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
        accept_value);
    assert(response_len > 0 && (size_t)response_len < sizeof(response));
    assert(ssl_write_exact(ssl, (const uint8_t *)response,
                           (size_t)response_len) == 0);

    uint8_t payload[TG_MTPROTO_HANDSHAKE_LEN + 32u], opcode;
    size_t payload_len = 0;
    assert(read_masked_client_frame(ssl, &opcode, payload, sizeof(payload),
                                    &payload_len) == 0);
    const uint8_t *expected_handshake = fixture->handshake_len
        ? fixture->handshake : test_handshake;
    size_t expected_handshake_len = fixture->handshake_len
        ? fixture->handshake_len : sizeof(test_handshake);
    assert(opcode == TG_WS_BINARY && payload_len == expected_handshake_len);
    assert(memcmp(payload, expected_handshake, payload_len) == 0);
    assert(read_masked_client_frame(ssl, &opcode, payload, sizeof(payload),
                                    &payload_len) == 0);
    size_t expected_len = fixture->expected_packet_len
        ? fixture->expected_packet_len : sizeof(fixture->expected_packet);
    assert(opcode == TG_WS_BINARY && payload_len == expected_len);
    assert(memcmp(payload, fixture->expected_packet, payload_len) == 0);
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
    if (fixture->arbitrary_response) {
        uint8_t invalid[4] = {0};
        tg_mtproto_ctr server_encrypt = {0};
        assert(tg_mtproto_direct_server_stream_cipher(test_handshake,
                                                       &server_encrypt) == 0);
        assert(tg_mtproto_ctr_xor(&server_encrypt, invalid,
                                  sizeof(invalid)) == 0);
        assert(write_server_frame(ssl, TG_WS_BINARY, invalid,
                                  sizeof(invalid)) == 0);
        tg_mtproto_ctr_destroy(&server_encrypt);
    } else {
        assert(write_server_frame(ssl, TG_WS_BINARY,
                                  fixture->response_packet,
                                  fixture->response_packet_len) == 0);
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

static void *serve_hedged_wss(void *opaque) {
    wss_server_fixture *fixture = opaque;
    int first = accept(fixture->listener, NULL, NULL);
    assert(first >= 0);
    fixture->accepted_count = 1;
    fixture->expected_sni = "kws4-1.web.telegram.org";
    fixture->wait_for_second = 1;
    serve_direct_wss_connection(fixture, first);
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

static void test_epoll_bridge_preserves_handshake_and_half_close(void) {
    uint16_t upstream_port, listen_port;
    int upstream_listener = create_listener(&upstream_port);
    int listener = create_listener(&listen_port);
    pthread_t echo_thread;
    assert(pthread_create(&echo_thread, NULL, echo_server, &upstream_listener) == 0);

    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", upstream_port);
    tg_epoll_proxy_config config = {
        .listener_fd = listener,
        .queue_bytes = 4096,
        .memory_budget_bytes = 1024 * 1024,
        .configured_max_connections = 16,
        .handshake_timeout_ms = 1000,
        .idle_timeout_ms = 5000,
        .original_destination = original_destination,
        .select_target = select_target,
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
    close(client);
    tg_epoll_proxy_destroy(server);
    close(listener);
    close(upstream_listener);
    assert(pthread_join(echo_thread, NULL) == 0);
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
        .memory_budget_bytes = 1024 * 1024,
        .configured_max_connections = 8,
        .handshake_timeout_ms = 1000,
        .idle_timeout_ms = 5000,
        .original_destination = original_destination,
        .select_target = select_target,
        .context = &fixture,
    };
    tg_epoll_proxy *proxy = tg_epoll_proxy_create(&config);
    assert(proxy != NULL);
    struct stat socket_stat;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, (size_t)path_length + 1);
    int stale = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(stale >= 0);
    assert(bind(stale, (struct sockaddr *)&address, sizeof(address)) == 0);
    close(stale);

    tg_stats_socket stats_socket = {.fd = -1};
    assert(tg_stats_socket_open(&stats_socket, path) == 0);
    tg_stats_socket duplicate = {.fd = -1};
    assert(tg_stats_socket_open(&duplicate, path) != 0);
    assert(stat(path, &socket_stat) == 0 && S_ISSOCK(socket_stat.st_mode));
    assert((socket_stat.st_mode & 0777) == 0600);

    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(client >= 0);
    assert(connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(tg_stats_socket_serve(&stats_socket, proxy) == 0);
    char response[256];
    ssize_t length = recv(client, response, sizeof(response) - 1, 0);
    assert(length > 0);
    response[length] = '\0';
    assert(strstr(response, "\"active_connections\":0") != NULL);
    assert(strstr(response, "\"connections_started\":0") != NULL);
    close(client);

    tg_stats_socket_close(&stats_socket);
    assert(access(path, F_OK) != 0);
    tg_epoll_proxy_destroy(proxy);
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

static void test_self_dial_target_is_rejected(void) {
    uint16_t listen_port;
    int listener = create_listener(&listen_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", 443);
    const uint16_t proxy_ports[] = {1443};
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

static void test_epoll_direct_wss_preserves_mtproto_packet_boundaries(void) {
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
    assert(shutdown(client, SHUT_WR) == 0);

    uint8_t unexpected;
    assert(recv(client, &unexpected, sizeof(unexpected), 0) == 0);
    assert(pthread_join(wss_thread, NULL) == 0);
    assert(atomic_load(&wss.complete) == 1 && fixture.routes == 1);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
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

static void test_epoll_hedged_wss_uses_second_live_candidate(
    tg_mtproto_proto proto) {
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
    uint8_t handshake[64];
    make_wss_test_handshake(proto, handshake);
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
    assert(pthread_create(&wss_thread, NULL, serve_hedged_wss, &wss) == 0);

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {0};
    routing.ws_routing = TG_WS_ROUTING_HEDGED;
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
    assert(send(client, wss.expected_packet, wss.expected_packet_len, 0) ==
           (ssize_t)wss.expected_packet_len);
    assert(shutdown(client, SHUT_WR) == 0);
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
    assert(pthread_join(wss_thread, NULL) == 0);
    assert(wss.accepted_count == 2 && atomic_load(&wss.complete) == 1);
    close(client);
    atomic_store(&runner.stop, 1);
    assert(pthread_join(proxy_thread, NULL) == 0);
    tg_epoll_proxy_stats route_stats;
    assert(tg_epoll_proxy_get_stats(proxy, &route_stats) == 0);
    assert(route_stats.wss_attempts == 2 && route_stats.wss_responses == 1);
    tg_epoll_proxy_destroy(proxy);
    close(listener);
    close(wss.listener);
    SSL_CTX_free(tls_context);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(directory) == 0);
}

static void test_epoll_cf_worker_uses_raw_stream_framing(void) {
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
    wss_server_fixture worker = {
        .listener = create_listener(&ws_port),
        .cert_path = cert_path,
        .key_path = key_path,
        .expected_sni = "worker.test",
        .expected_path = "/apiws?dst=149.154.167.51&dc=4&media=1",
        .expect_binary_subprotocol = 0
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

    int listener = create_listener(&proxy_port);
    proxy_fixture fixture = {0};
    set_ipv4(&fixture.original, "149.154.167.51", 443);
    set_ipv4(&fixture.upstream, "127.0.0.1", ws_port);
    SSL_CTX *tls_context = tg_tls_client_context(cert_path);
    assert(tls_context);
    tg_config routing = {0};
    routing.ws_routing = TG_WS_ROUTING_CF_FIRST;
    routing.cf_worker_domain_count = 1;
    memcpy(routing.cf_worker_domains[0], "worker.test", sizeof("worker.test"));
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
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
    assert(send(client, worker.expected_packet,
                sizeof(worker.expected_packet), 0) ==
           (ssize_t)sizeof(worker.expected_packet));
    assert(shutdown(client, SHUT_WR) == 0);
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

static void test_epoll_cf_proxy_uses_mtproto_packet_framing(void) {
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
        .expected_sni = "cfproxy.test",
        .expected_path = "/apiws",
        .expect_binary_subprotocol = 1
    };
    atomic_init(&cf_proxy.complete, 0);
    prepare_wss_response(&cf_proxy, test_handshake, TG_MTPROTO_INTERMEDIATE);
    const uint8_t clear_packet[12] = {8,0,0,0,0x11,0x22,0x33,0x44,
                                      0x55,0x66,0x77,0x88};
    tg_mtproto_ctr decrypt = {0}, encrypt = {0};
    memcpy(cf_proxy.expected_packet, clear_packet, sizeof(clear_packet));
    assert(tg_mtproto_direct_stream_ciphers(test_handshake, &decrypt,
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
    assert(send(client, test_handshake, sizeof(test_handshake), 0) ==
           (ssize_t)sizeof(test_handshake));
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

static void test_epoll_direct_wss_rejection_falls_back_to_tcp(void) {
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

int main(void) {
    test_epoll_bridge_preserves_handshake_and_half_close();
    test_read_only_stats_socket();
    test_invalid_handshake_fails_closed();
    test_self_dial_target_is_rejected();
    test_epoll_direct_wss_preserves_mtproto_packet_boundaries();
    test_epoll_hedged_wss_uses_second_live_candidate(TG_MTPROTO_ABRIDGED);
    test_epoll_hedged_wss_uses_second_live_candidate(TG_MTPROTO_INTERMEDIATE);
    test_epoll_hedged_wss_uses_second_live_candidate(
        TG_MTPROTO_PADDED_INTERMEDIATE);
    test_epoll_cf_worker_uses_raw_stream_framing();
    test_epoll_cf_proxy_uses_mtproto_packet_framing();
    test_epoll_direct_wss_rejection_falls_back_to_tcp();
    puts("Тесты epoll-прокси Telegram: ок");
    return 0;
}
