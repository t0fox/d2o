#define _POSIX_C_SOURCE 200809L
#include "tg_mtproto.h"
#include "tg_mtproto_discovery.h"

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

typedef struct {
    int listener;
    int wrong_nonce;
    int invalid_plain_header;
} fake_telegram;

typedef struct {
    int listener;
    SSL_CTX *context;
} fake_wss;

static void read_all(int fd, uint8_t *data, size_t len) {
    size_t used = 0;
    while (used < len) {
        ssize_t n = recv(fd, data + used, len - used, 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        used += (size_t)n;
    }
}

static void write_all(int fd, const uint8_t *data, size_t len) {
    size_t used = 0;
    while (used < len) {
        ssize_t n = send(fd, data + used, len - used, 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        used += (size_t)n;
    }
}

static void ssl_read_all(SSL *ssl, uint8_t *data, size_t len) {
    size_t used = 0;
    while (used < len) {
        int n = SSL_read(ssl, data + used,
                         len - used > INT_MAX ? INT_MAX : (int)(len - used));
        assert(n > 0);
        used += (size_t)n;
    }
}

static void ssl_write_all(SSL *ssl, const uint8_t *data, size_t len) {
    size_t used = 0;
    while (used < len) {
        int n = SSL_write(ssl, data + used,
                          len - used > INT_MAX ? INT_MAX : (int)(len - used));
        assert(n > 0);
        used += (size_t)n;
    }
}

static EVP_PKEY *make_wss_test_key(void) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    assert(context && EVP_PKEY_keygen_init(context) == 1 &&
           EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) == 1 &&
           EVP_PKEY_keygen(context, &key) == 1);
    EVP_PKEY_CTX_free(context);
    return key;
}

static X509 *make_wss_test_cert(EVP_PKEY *key) {
    X509 *cert = X509_new();
    assert(cert && X509_set_version(cert, 2) == 1 &&
           ASN1_INTEGER_set(X509_get_serialNumber(cert), 11) == 1 &&
           X509_gmtime_adj(X509_getm_notBefore(cert), -60) != NULL &&
           X509_gmtime_adj(X509_getm_notAfter(cert), 3600) != NULL &&
           X509_set_pubkey(cert, key) == 1);
    X509_NAME *name = X509_get_subject_name(cert);
    assert(name && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"worker.example", -1, -1, 0) == 1 &&
        X509_set_issuer_name(cert, name) == 1);
    X509_EXTENSION *extension = X509V3_EXT_conf_nid(
        NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    assert(extension && X509_add_ext(cert, extension, -1) == 1);
    X509_EXTENSION_free(extension);
    extension = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
                                    "DNS:worker.example");
    assert(extension && X509_add_ext(cert, extension, -1) == 1);
    X509_EXTENSION_free(extension);
    assert(X509_sign(cert, key, EVP_sha256()) > 0);
    return cert;
}

static int create_wss_listener(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0 &&
           listen(fd, 1) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    *port = ntohs(address.sin_port);
    return fd;
}

static size_t read_client_ws_binary(SSL *ssl, uint8_t *payload, size_t cap) {
    uint8_t header[2];
    ssl_read_all(ssl, header, sizeof(header));
    assert((header[0] & 0x8fu) == 0x82u && (header[1] & 0x80u) != 0);
    uint64_t length = header[1] & 0x7fu;
    if (length == 126) {
        uint8_t extended[2];
        ssl_read_all(ssl, extended, sizeof(extended));
        length = ((uint64_t)extended[0] << 8) | extended[1];
    } else if (length == 127) {
        uint8_t extended[8];
        ssl_read_all(ssl, extended, sizeof(extended));
        length = 0;
        for (size_t i = 0; i < sizeof(extended); ++i)
            length = (length << 8) | extended[i];
    }
    assert(length <= cap);
    uint8_t mask[4];
    ssl_read_all(ssl, mask, sizeof(mask));
    ssl_read_all(ssl, payload, (size_t)length);
    for (size_t i = 0; i < (size_t)length; ++i) payload[i] ^= mask[i & 3u];
    return (size_t)length;
}

static void *serve_wss_discovery_request(void *opaque) {
    fake_wss *fake = opaque;
    int fd = accept(fake->listener, NULL, NULL);
    assert(fd >= 0);
    SSL *ssl = SSL_new(fake->context);
    assert(ssl && SSL_set_fd(ssl, fd) == 1 && SSL_accept(ssl) == 1);
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    assert(sni && strcmp(sni, "worker.example") == 0);

    char request[2048] = {0};
    size_t used = 0;
    while (used + 1 < sizeof(request) &&
           (!used || strstr(request, "\r\n\r\n") == NULL)) {
        ssl_read_all(ssl, (uint8_t *)request + used, 1);
        ++used;
        request[used] = '\0';
    }
    assert(strstr(request,
        "GET /apiws?dst=149.154.175.50&dc=1&media=0 HTTP/1.1\r\n") != NULL);
    assert(strstr(request, "Host: worker.example\r\n") != NULL);
    assert(strstr(request, "Sec-WebSocket-Protocol: binary\r\n") != NULL);
    const char *key_line = strstr(request, "Sec-WebSocket-Key: ");
    assert(key_line);
    key_line += strlen("Sec-WebSocket-Key: ");
    const char *key_end = strstr(key_line, "\r\n");
    assert(key_end && (size_t)(key_end - key_line) < 64);
    char key[64] = {0};
    memcpy(key, key_line, (size_t)(key_end - key_line));
    char material[128];
    int material_len = snprintf(material, sizeof(material),
        "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    assert(material_len > 0 && (size_t)material_len < sizeof(material));
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned digest_len = 0;
    assert(EVP_Digest(material, (size_t)material_len, digest, &digest_len,
                      EVP_sha1(), NULL) == 1);
    char accept_key[EVP_ENCODE_LENGTH(EVP_MAX_MD_SIZE)] = {0};
    assert(EVP_EncodeBlock((unsigned char *)accept_key, digest,
                           (int)digest_len) > 0);
    char response[512];
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "Sec-WebSocket-Protocol: binary\r\n\r\n", accept_key);
    assert(response_len > 0 && (size_t)response_len < sizeof(response));
    ssl_write_all(ssl, (const uint8_t *)response, (size_t)response_len);

    uint8_t frame[TG_MTPROTO_HANDSHAKE_LEN + 1024];
    size_t frame_len = read_client_ws_binary(ssl, frame, sizeof(frame));
    assert(frame_len == TG_MTPROTO_HANDSHAKE_LEN);
    tg_mtproto_init init;
    assert(tg_mtproto_parse_obfuscated2(frame, &init) == 0 && init.dc_id == 1);
    frame_len = read_client_ws_binary(ssl, frame, sizeof(frame));
    assert(frame_len == 4);
    frame_len = read_client_ws_binary(ssl, frame, sizeof(frame));
    assert(frame_len == 40);
    static const uint8_t close_frame[] = {0x88, 0x00};
    ssl_write_all(ssl, close_frame, sizeof(close_frame));
    SSL_free(ssl);
    close(fd);
    return NULL;
}

static uint32_t read_le32(const uint8_t bytes[4]) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void write_le32(uint8_t bytes[4], uint32_t value) {
    for (size_t i = 0; i < 4; ++i) bytes[i] = (uint8_t)(value >> (8 * i));
}

static void write_le64(uint8_t bytes[8], uint64_t value) {
    for (size_t i = 0; i < 8; ++i) bytes[i] = (uint8_t)(value >> (8 * i));
}

static void *serve_res_pq(void *opaque) {
    fake_telegram *fake = opaque;
    int fd = accept(fake->listener, NULL, NULL);
    assert(fd >= 0);
    uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN];
    read_all(fd, handshake, sizeof(handshake));
    tg_mtproto_init parsed;
    assert(tg_mtproto_parse_obfuscated2(handshake, &parsed) == 0);
    assert(parsed.dc_id == 4 && parsed.proto == TG_MTPROTO_INTERMEDIATE);

    uint8_t key[32], iv[16], frame_length[4], request[40];
    memcpy(key, handshake + 8, sizeof(key));
    memcpy(iv, handshake + 40, sizeof(iv));
    tg_mtproto_ctr incoming = {0};
    assert(tg_mtproto_ctr_init(&incoming, key, iv) == 0);
    uint8_t skip[TG_MTPROTO_HANDSHAKE_LEN] = {0};
    assert(tg_mtproto_ctr_xor(&incoming, skip, sizeof(skip)) == 0);
    read_all(fd, frame_length, sizeof(frame_length));
    assert(tg_mtproto_ctr_xor(&incoming, frame_length,
                              sizeof(frame_length)) == 0);
    assert(read_le32(frame_length) == sizeof(request));
    read_all(fd, request, sizeof(request));
    assert(tg_mtproto_ctr_xor(&incoming, request, sizeof(request)) == 0);
    tg_mtproto_ctr_destroy(&incoming);
    static const uint8_t zero_auth_key_id[8] = {0};
    assert(memcmp(request, zero_auth_key_id, sizeof(zero_auth_key_id)) == 0);
    uint64_t message_id = (uint64_t)request[8] |
                         ((uint64_t)request[9] << 8) |
                         ((uint64_t)request[10] << 16) |
                         ((uint64_t)request[11] << 24) |
                         ((uint64_t)request[12] << 32) |
                         ((uint64_t)request[13] << 40) |
                         ((uint64_t)request[14] << 48) |
                         ((uint64_t)request[15] << 56);
    assert(message_id != 0 && (message_id & 3u) == 0);
    assert(request[16] == 20 && request[17] == 0 && request[18] == 0 &&
           request[19] == 0);
    assert(memcmp(request + 20, "\xf1\x8e\x7e\xbe", 4) == 0);

    uint8_t body[56] = {0};
    memcpy(body, "\x63\x24\x16\x05", 4);
    memcpy(body + 4, request + 24, 16);
    if (fake->wrong_nonce) body[4] ^= 0x01;
    memset(body + 20, 0xa5, 16);
    body[36] = 2;
    body[37] = 0x17;
    body[38] = 0xed;
    body[39] = 0;
    memcpy(body + 40, "\x15\xc4\xb5\x1c", 4);
    body[44] = 1;
    for (size_t i = 0; i < 8; ++i) body[48 + i] = (uint8_t)(i + 1);
    uint8_t packet[4 + 20 + sizeof(body)] = {0};
    write_le32(packet, 20 + sizeof(body));
    packet[4 + 8] = 1;
    write_le32(packet + 4 + 16, sizeof(body));
    memcpy(packet + 4 + 20, body, sizeof(body));
    if (fake->invalid_plain_header == 1) packet[4] = 1;
    if (fake->invalid_plain_header == 2) memset(packet + 4 + 8, 0, 8);

    uint8_t reversed[48];
    for (size_t i = 0; i < sizeof(reversed); ++i)
        reversed[i] = handshake[55 - i];
    tg_mtproto_ctr outgoing = {0};
    assert(tg_mtproto_ctr_init(&outgoing, reversed, reversed + 32) == 0);
    assert(tg_mtproto_ctr_xor(&outgoing, packet, sizeof(packet)) == 0);
    tg_mtproto_ctr_destroy(&outgoing);
    write_all(fd, packet, sizeof(packet));
    close(fd);
    return NULL;
}

static int create_listener(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(fd, 4) == 0);
    socklen_t len = sizeof(address);
    assert(getsockname(fd, (struct sockaddr *)&address, &len) == 0);
    *port = ntohs(address.sin_port);
    return fd;
}

static void test_valid_res_pq_is_a_real_mtproto_health_signal(void) {
    uint16_t port;
    fake_telegram fake = {.listener = create_listener(&port)};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, serve_res_pq, &fake) == 0);
    tg_mtproto_probe_result result = {0};
    assert(tg_mtproto_probe_res_pq("127.0.0.1", port, 4, 0, 0, 2000,
                                   &result) == TG_MTPROTO_PROBE_OK);
    assert(result.status == TG_MTPROTO_PROBE_OK && result.pq_len == 2);
    assert(result.stage == TG_MTPROTO_PROBE_STAGE_RES_PQ);
    assert(result.pq[0] == 0x17 && result.pq[1] == 0xed);
    assert(pthread_join(thread, NULL) == 0);
    close(fake.listener);
}

static void test_response_with_wrong_nonce_is_not_healthy(void) {
    uint16_t port;
    fake_telegram fake = {.listener = create_listener(&port), .wrong_nonce = 1};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, serve_res_pq, &fake) == 0);
    tg_mtproto_probe_result result = {0};
    assert(tg_mtproto_probe_res_pq("127.0.0.1", port, 4, 0, 0, 2000,
                                   &result) == TG_MTPROTO_PROBE_INVALID);
    assert(result.stage == TG_MTPROTO_PROBE_STAGE_MTPROTO);
    assert(pthread_join(thread, NULL) == 0);
    close(fake.listener);
}

static void test_non_plain_response_is_not_healthy(void) {
    for (int invalid_header = 1; invalid_header <= 2; ++invalid_header) {
        uint16_t port;
        fake_telegram fake = {.listener = create_listener(&port),
                              .invalid_plain_header = invalid_header};
        pthread_t thread;
        assert(pthread_create(&thread, NULL, serve_res_pq, &fake) == 0);
        tg_mtproto_probe_result result = {0};
        assert(tg_mtproto_probe_res_pq("127.0.0.1", port, 4, 0, 0, 2000,
                                       &result) == TG_MTPROTO_PROBE_INVALID);
        assert(result.stage == TG_MTPROTO_PROBE_STAGE_MTPROTO);
        assert(pthread_join(thread, NULL) == 0);
        close(fake.listener);
    }
}

static void test_config_discovery_rejects_invalid_arguments(void) {
    tg_dc_snapshot snapshot = {.this_dc = 77};
    assert(tg_mtproto_discover_config(NULL, 443, 1, 1000, 0, 1,
                                      &snapshot) != 0);
    assert(snapshot.this_dc == 0 && snapshot.endpoint_count == 0);
    assert(tg_mtproto_discover_config("127.0.0.1", 0, 1, 1000, 0, 1,
                                      &snapshot) != 0);
    assert(tg_mtproto_discover_config("127.0.0.1", 443, 0, 1000, 0, 1,
                                      &snapshot) != 0);
    assert(tg_mtproto_discover_config("127.0.0.1", 443, 1, 0, 0, 1,
                                      &snapshot) != 0);
    assert(tg_mtproto_discover_config("127.0.0.1", 443, 1, 1000, 0, 0,
                                      &snapshot) != 0);
    snapshot.this_dc = 77;
    assert(tg_mtproto_discover_config_wss(NULL, "127.0.0.1",
                                          "worker.example", "/apiws", 443, 1,
                                          1000, 0, 1, &snapshot) != 0);
    assert(snapshot.this_dc == 0 && snapshot.endpoint_count == 0);
    snapshot.this_dc = 77;
    assert(tg_mtproto_discover_config_wss(NULL, NULL, "worker.example",
                                          "/apiws", 443, 1, 1000, 0, 1,
                                          &snapshot) != 0);
    assert(snapshot.this_dc == 0 && snapshot.endpoint_count == 0);
}

static void test_wss_discovery_authenticates_host_and_forwards_binary_stream(void) {
    uint16_t port = 0;
    EVP_PKEY *key = make_wss_test_key();
    X509 *cert = make_wss_test_cert(key);
    SSL_CTX *server_context = SSL_CTX_new(TLS_server_method());
    SSL_CTX *client_context = SSL_CTX_new(TLS_client_method());
    assert(server_context && client_context &&
           SSL_CTX_use_certificate(server_context, cert) == 1 &&
           SSL_CTX_use_PrivateKey(server_context, key) == 1 &&
           X509_STORE_add_cert(SSL_CTX_get_cert_store(client_context), cert) == 1);
    SSL_CTX_set_verify(client_context, SSL_VERIFY_PEER, NULL);
    fake_wss fake = {
        .listener = create_wss_listener(&port),
        .context = server_context
    };
    pthread_t thread;
    assert(pthread_create(&thread, NULL, serve_wss_discovery_request, &fake) == 0);
    tg_dc_snapshot snapshot = {.this_dc = 77};
    assert(tg_mtproto_discover_config_wss(
        client_context, "127.0.0.1", "worker.example",
        "/apiws?dst=149.154.175.50&dc=1&media=0", port, 1, 5000, 0,
        (int64_t)time(NULL), &snapshot) != 0);
    assert(snapshot.this_dc == 0 && snapshot.endpoint_count == 0);
    assert(pthread_join(thread, NULL) == 0);
    close(fake.listener);
    SSL_CTX_free(client_context);
    SSL_CTX_free(server_context);
    X509_free(cert);
    EVP_PKEY_free(key);
}

static void test_encrypted_response_ignores_control_messages_before_rpc_result(void) {
    const uint64_t request_message_id = UINT64_C(0x1234567800000000);
    uint8_t service[28] = {0};
    write_le32(service, UINT32_C(0x9ec20908));
    write_le64(service + 4, 9);
    write_le64(service + 12, 10);
    write_le64(service + 20, 11);
    const uint8_t *result = NULL;
    size_t result_len = 0;
    assert(tg_mtproto_parse_rpc_result(service, sizeof(service),
                                       request_message_id, 2, &result,
                                       &result_len) == 1);
    assert(tg_mtproto_parse_rpc_result(service, sizeof(service),
                                       request_message_id, 1, &result,
                                       &result_len) == 1);

    uint8_t container[52] = {0};
    write_le32(container, UINT32_C(0x73f1f8dc));
    write_le32(container + 4, 1);
    write_le64(container + 8, 13);
    write_le32(container + 16, 0);
    write_le32(container + 20, sizeof(service));
    memcpy(container + 24, service, sizeof(service));
    assert(tg_mtproto_parse_rpc_result(container, sizeof(container),
                                       request_message_id, 2, &result,
                                       &result_len) == 1);
    assert(tg_mtproto_parse_rpc_result(container, sizeof(container),
                                       request_message_id, 3, &result,
                                       &result_len) == -1);

    uint8_t control_container[88] = {0};
    write_le32(control_container, UINT32_C(0x73f1f8dc));
    write_le32(control_container + 4, 2);
    write_le64(control_container + 8, 13);
    write_le32(control_container + 16, 1);
    write_le32(control_container + 20, sizeof(service));
    memcpy(control_container + 24, service, sizeof(service));
    write_le64(control_container + 52, 17);
    write_le32(control_container + 60, 2);
    write_le32(control_container + 64, 20);
    write_le32(control_container + 68, UINT32_C(0x62d6b459));
    write_le32(control_container + 72, UINT32_C(0x1cb5c415));
    write_le32(control_container + 76, 1);
    write_le64(control_container + 80, request_message_id);
    assert(tg_mtproto_parse_rpc_result(control_container,
                                       sizeof(control_container),
                                       request_message_id, 2, &result,
                                       &result_len) == 1);

    uint8_t ack_container[44] = {0};
    write_le32(ack_container, UINT32_C(0x73f1f8dc));
    write_le32(ack_container + 4, 1);
    write_le64(ack_container + 8, 21);
    write_le32(ack_container + 16, 2);
    write_le32(ack_container + 20, 20);
    write_le32(ack_container + 24, UINT32_C(0x62d6b459));
    write_le32(ack_container + 28, UINT32_C(0x1cb5c415));
    write_le32(ack_container + 32, 1);
    write_le64(ack_container + 36, request_message_id);
    assert(tg_mtproto_parse_rpc_result(ack_container, sizeof(ack_container),
                                       request_message_id, 2, &result,
                                       &result_len) == 1);

    uint8_t empty_container[8] = {0};
    write_le32(empty_container, UINT32_C(0x73f1f8dc));
    assert(tg_mtproto_parse_rpc_result(empty_container,
                                       sizeof(empty_container),
                                       request_message_id, 2, &result,
                                       &result_len) == 1);

    uint8_t response_container[40] = {0};
    write_le32(response_container, UINT32_C(0x73f1f8dc));
    write_le32(response_container + 4, 1);
    write_le64(response_container + 8, 17);
    write_le32(response_container + 16, 1);
    write_le32(response_container + 20, 16);
    write_le32(response_container + 24, UINT32_C(0xf35c6d01));
    write_le64(response_container + 28, request_message_id);
    write_le32(response_container + 36, UINT32_C(0x12345678));
    assert(tg_mtproto_parse_rpc_result(response_container,
                                       sizeof(response_container),
                                       request_message_id, 2, &result,
                                       &result_len) == 0);
    assert(result == response_container + 36 && result_len == 4 &&
           result[0] == 0x78 && result[3] == 0x12);
}

static void test_wss_probe_rejects_invalid_configuration(void) {
    tg_mtproto_probe_result result = {0};
    assert(tg_mtproto_probe_res_pq_wss(NULL, "localhost", 1, 0, 1000,
                                       &result) == TG_MTPROTO_PROBE_INVALID);
    assert(result.stage == TG_MTPROTO_PROBE_STAGE_INPUT);
    assert(result.error == TG_MTPROTO_PROBE_ERROR_INVALID_INPUT);
    assert(tg_mtproto_probe_res_pq_wss(NULL, NULL, 1, 0, 1000,
                                       &result) == TG_MTPROTO_PROBE_INVALID);
    assert(tg_mtproto_probe_res_pq_wss(NULL, "localhost", 6, 0, 1000,
                                       &result) == TG_MTPROTO_PROBE_INVALID);
}

int main(void) {
    test_wss_probe_rejects_invalid_configuration();
    test_valid_res_pq_is_a_real_mtproto_health_signal();
    test_response_with_wrong_nonce_is_not_healthy();
    test_non_plain_response_is_not_healthy();
    test_config_discovery_rejects_invalid_arguments();
    test_wss_discovery_authenticates_host_and_forwards_binary_stream();
    test_encrypted_response_ignores_control_messages_before_rpc_result();
    puts("Тесты MTProto probe и response parser: ок");
    return 0;
}
