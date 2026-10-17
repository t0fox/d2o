#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "tg_tls.h"
#include "tg_ws.h"

#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct { int listener; const char *cert; const char *key; char sni[128]; int status; size_t payload_len; } server_args;

typedef struct { uint8_t data[16]; size_t len; int received; } pump_capture;
static int capture_message(void *ctx,const uint8_t *data,size_t len) {
    pump_capture *c=ctx; if(len>sizeof(c->data))return -1;
    memcpy(c->data,data,len);c->len=len;c->received=1;return 0;
}

static void *serve_one(void *opaque) {
    server_args *a = opaque;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    int fd = accept(a->listener, NULL, NULL);
    assert(ctx && fd >= 0);
    assert(SSL_CTX_use_certificate_file(ctx, a->cert, SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_use_PrivateKey_file(ctx, a->key, SSL_FILETYPE_PEM) == 1);
    SSL *ssl = SSL_new(ctx);
    assert(ssl && SSL_set_fd(ssl, fd) == 1);
    if (SSL_accept(ssl) == 1) {
        const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (name) snprintf(a->sni, sizeof(a->sni), "%s", name);
    }
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return NULL;
}

static int ssl_read_exact(SSL *ssl, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_read(ssl, buf + off, (int)(len - off));
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int ssl_write_exact(SSL *ssl, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, buf + off, (int)(len - off));
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static void *serve_ws(void *opaque) {
    server_args *a = opaque;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    int fd = accept(a->listener, NULL, NULL);
    assert(ctx && fd >= 0);
    assert(SSL_CTX_use_certificate_file(ctx, a->cert, SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_use_PrivateKey_file(ctx, a->key, SSL_FILETYPE_PEM) == 1);
    SSL *ssl = SSL_new(ctx);
    assert(ssl && SSL_set_fd(ssl, fd) == 1 && SSL_accept(ssl) == 1);
    char req[8192]; size_t used = 0;
    while (used < sizeof(req)-1 && (used < 4 || memcmp(req + used - 4, "\r\n\r\n", 4))) {
        assert(ssl_read_exact(ssl, (uint8_t *)req + used, 1) == 0);
        ++used;
    }
    req[used] = '\0';
    char *keyline = strstr(req, "Sec-WebSocket-Key: ");
    assert(keyline != NULL);
    keyline += strlen("Sec-WebSocket-Key: ");
    char client_key[25]; memcpy(client_key, keyline, 24); client_key[24] = '\0';
    char input[128]; snprintf(input, sizeof(input), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);
    uint8_t digest[SHA_DIGEST_LENGTH]; unsigned int digest_len = 0;
    assert(EVP_Digest(input, strlen(input), digest, &digest_len, EVP_sha1(), NULL) == 1);
    char accept[64]; int accept_len = EVP_EncodeBlock((unsigned char *)accept, digest, (int)digest_len);
    accept[accept_len] = '\0';
    char response[512];
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept);
    assert(response_len > 0 && ssl_write_exact(ssl, (uint8_t *)response, (size_t)response_len) == 0);
    uint8_t frame[128];
    assert(ssl_read_exact(ssl, frame, 2) == 0);
    assert(frame[0] == 0x82 && (frame[1] & 0x80) && (frame[1] & 0x7f) == 5);
    assert(ssl_read_exact(ssl, frame + 2, 9) == 0);
    for (size_t i=0; i<5; ++i) assert((uint8_t)(frame[6+i] ^ frame[2+i%4]) == "hello"[i]);
    const uint8_t first_fragment[] = {0x02,0x01,'o'};
    assert(ssl_write_exact(ssl, first_fragment, sizeof(first_fragment)) == 0);
    const uint8_t ping[] = {0x89,0x01,'p'};
    assert(ssl_write_exact(ssl, ping, sizeof(ping)) == 0);
    assert(ssl_read_exact(ssl, frame, 7) == 0);
    assert(frame[0] == 0x8a && frame[1] == 0x81 && frame[6] == ('p' ^ frame[2]));
    const uint8_t last_fragment[] = {0x80,0x01,'k'};
    assert(ssl_write_exact(ssl, last_fragment, sizeof(last_fragment)) == 0);
    const uint8_t text_frame[] = {0x81,0x01,'x'};
    assert(ssl_write_exact(ssl, text_frame, sizeof(text_frame)) == 0);
    const uint8_t close_frame[] = {0x88,0x00};
    assert(ssl_write_exact(ssl, close_frame, sizeof(close_frame)) == 0);
    SSL_free(ssl); close(fd); SSL_CTX_free(ctx);
    return NULL;
}

static EVP_PKEY *make_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    assert(ctx && EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1);
    assert(EVP_PKEY_keygen(ctx, &key) == 1);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static X509 *make_cert(EVP_PKEY *key) {
    X509 *cert = X509_new();
    X509_NAME *name;
    X509_EXTENSION *ext;
    assert(cert && X509_set_version(cert, 2) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(cert), -60) != NULL);
    assert(X509_gmtime_adj(X509_getm_notAfter(cert), 3600) != NULL);
    assert(X509_set_pubkey(cert, key) == 1);
    name = X509_get_subject_name(cert);
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                      (const unsigned char *)"relay.test", -1, -1, 0) == 1);
    assert(X509_set_issuer_name(cert, name) == 1);
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    assert(ext && X509_add_ext(cert, ext, -1) == 1); X509_EXTENSION_free(ext);
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
                              "DNS:relay.test,IP:127.0.0.1");
    assert(ext && X509_add_ext(cert, ext, -1) == 1); X509_EXTENSION_free(ext);
    assert(X509_sign(cert, key, EVP_sha256()) > 0);
    return cert;
}

static int listen_loopback(void) {
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=0};
    socklen_t len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(fd, 1) == 0);
    assert(getsockname(fd, (struct sockaddr *)&addr, &len) == 0);
    return fd;
}

static int connect_loopback(int listener) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0 && getsockname(listener, (struct sockaddr *)&addr, &len) == 0);
    assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    return fd;
}

static void write_large_fragment(SSL *ssl, uint8_t opcode, size_t len) {
    uint8_t header[10] = {opcode, 127, 0, 0, 0, 0, 0, 0, 0, 0};
    for (size_t i = 0; i < 8; ++i)
        header[2 + i] = (uint8_t)((uint64_t)len >> (56u - (unsigned)i * 8u));
    assert(ssl_write_exact(ssl, header, sizeof(header)) == 0);
    uint8_t payload[16u * 1024u];
    memset(payload, 0x5a, sizeof(payload));
    while (len) {
        size_t chunk = len < sizeof(payload) ? len : sizeof(payload);
        assert(ssl_write_exact(ssl, payload, chunk) == 0);
        len -= chunk;
    }
}

static void *serve_large_ws( void *opaque) {
    server_args *args = opaque;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    int fd = accept(args->listener, NULL, NULL);
    assert(ctx && fd >= 0);
    assert(SSL_CTX_use_certificate_file(ctx, args->cert, SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_use_PrivateKey_file(ctx, args->key, SSL_FILETYPE_PEM) == 1);
    SSL *ssl = SSL_new(ctx);
    assert(ssl && SSL_set_fd(ssl, fd) == 1 && SSL_accept(ssl) == 1);
    assert(args->payload_len > 0 && args->payload_len % 2u == 0);
    write_large_fragment(ssl, TG_WS_BINARY, args->payload_len / 2u);
    write_large_fragment(ssl, 0x80u, args->payload_len / 2u);
    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return NULL;
}

typedef struct {
    tg_ws_pump *pump;
    size_t expected_len;
    size_t rx_cap_at_callback;
    size_t reassembly_cap_at_callback;
    int received;
} large_pump_capture;

static int capture_large_message(void *opaque, const uint8_t *data, size_t len) {
    large_pump_capture *capture = opaque;
    if (!data || len != capture->expected_len || data[0] != 0x5a ||
        data[len - 1u] != 0x5a)
        return -1;
    capture->rx_cap_at_callback = capture->pump->rx_cap;
    capture->reassembly_cap_at_callback = capture->pump->reassembly.cap;
    capture->received = 1;
    return 0;
}

static void test_sni_and_certificate_validation(void) {
    char dir[] = "/tmp/d2k-tg-tls-XXXXXX", cert_path[256], key_path[256];
    EVP_PKEY *key;
    X509 *cert;
    SSL_CTX *client_ctx;
    SSL *ssl;
    pthread_t thread;
    server_args args = {0};
    assert(mkdtemp(dir) != NULL);
    snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", dir);
    snprintf(key_path, sizeof(key_path), "%s/key.pem", dir);
    key = make_key(); cert = make_cert(key);
    FILE *f = fopen(cert_path, "w"); assert(f && PEM_write_X509(f, cert) == 1); fclose(f);
    f = fopen(key_path, "w"); assert(f && PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) == 1); fclose(f);
    X509_free(cert); EVP_PKEY_free(key);
    args.cert = cert_path; args.key = key_path;

    args.listener = listen_loopback();
    assert(pthread_create(&thread, NULL, serve_one, &args) == 0);
    client_ctx = tg_tls_client_context(cert_path);
    assert(client_ctx != NULL);
    ssl = tg_tls_connect_fd(client_ctx, connect_loopback(args.listener), "relay.test");
    assert(ssl != NULL);
    SSL_free(ssl); SSL_CTX_free(client_ctx);
    pthread_join(thread, NULL); close(args.listener);
    assert(strcmp(args.sni, "relay.test") == 0);

    args.listener = listen_loopback(); args.sni[0] = '\0';
    assert(pthread_create(&thread, NULL, serve_one, &args) == 0);
    client_ctx = tg_tls_client_context(cert_path); assert(client_ctx);
    ssl = tg_tls_connect_fd_sni(client_ctx, connect_loopback(args.listener), "relay.test", "example.com");
    assert(ssl != NULL);
    SSL_free(ssl); SSL_CTX_free(client_ctx);
    pthread_join(thread, NULL); close(args.listener);
    assert(strcmp(args.sni, "example.com") == 0);

    args.listener = listen_loopback();
    assert(pthread_create(&thread, NULL, serve_one, &args) == 0);
    client_ctx = tg_tls_client_context(cert_path); assert(client_ctx);
    ssl = tg_tls_connect_fd_sni(client_ctx, connect_loopback(args.listener), "wrong.test", "relay.test");
    assert(ssl == NULL); /* A valid SNI certificate must not authenticate the wrong target. */
    SSL_CTX_free(client_ctx);
    pthread_join(thread, NULL); close(args.listener);

    args.listener = listen_loopback(); args.sni[0] = '\0';
    assert(pthread_create(&thread, NULL, serve_one, &args) == 0);
    client_ctx = tg_tls_client_context(cert_path);
    assert(client_ctx != NULL);
    ssl = tg_tls_connect_fd(client_ctx, connect_loopback(args.listener), "wrong.test");
    assert(ssl == NULL);
    SSL_CTX_free(client_ctx);
    pthread_join(thread, NULL); close(args.listener);
    unlink(key_path); unlink(cert_path); rmdir(dir);
}

static void test_tls_client_preparation_is_nonblocking(void) {
    char dir[] = "/tmp/d2k-tg-tls-async-XXXXXX", cert_path[256];
    int sockets[2];
    assert(mkdtemp(dir) != NULL);
    snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", dir);
    EVP_PKEY *key = make_key();
    X509 *cert = make_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    SSL_CTX *context = tg_tls_client_context(cert_path);
    assert(context && socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    int flags = fcntl(sockets[0], F_GETFL, 0);
    assert(flags >= 0 && fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK) == 0);
    SSL *ssl = tg_tls_prepare_client_fd(context, sockets[0], "relay.test",
                                        "front.test");
    assert(ssl && SSL_get_fd(ssl) == sockets[0] && !SSL_is_init_finished(ssl));
    int result = SSL_do_handshake(ssl);
    assert(result != 1 && SSL_get_error(ssl, result) == SSL_ERROR_WANT_READ);

    SSL_free(ssl);
    close(sockets[0]);
    close(sockets[1]);
    SSL_CTX_free(context);
    unlink(cert_path);
    assert(rmdir(dir) == 0);
}

static void test_websocket_upgrade_accepts_incremental_valid_response(void) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    tg_ws_upgrade_state state = {0};
    assert(tg_ws_upgrade_start(&state, "kws2.web.telegram.org", "/apiws") == 0);
    size_t request_len = 0;
    const uint8_t *request = tg_ws_upgrade_pending(&state, &request_len);
    assert(request && request_len > 0);
    char request_text[1024];
    assert(request_len < sizeof(request_text));
    memcpy(request_text, request, request_len);
    request_text[request_len] = '\0';
    assert(strstr(request_text, "GET /apiws HTTP/1.1\r\n"));
    char *key_line = strstr(request_text, "Sec-WebSocket-Key: ");
    assert(key_line);
    key_line += strlen("Sec-WebSocket-Key: ");
    char key[25];
    memcpy(key, key_line, 24);
    key[24] = '\0';
    assert(tg_ws_upgrade_advance(&state, request_len) == 0);
    assert(tg_ws_upgrade_pending(&state, &request_len) == NULL && request_len == 0);

    char source[64], accept[40], response[512];
    int source_len = snprintf(source, sizeof(source), "%s%s", key, guid);
    uint8_t digest[SHA_DIGEST_LENGTH];
    unsigned int digest_len = 0;
    assert(source_len > 0 && (size_t)source_len < sizeof(source));
    assert(EVP_Digest(source, (size_t)source_len, digest, &digest_len,
                      EVP_sha1(), NULL) == 1);
    assert(digest_len == sizeof(digest));
    assert(EVP_EncodeBlock((unsigned char *)accept, digest,
                           (int)sizeof(digest)) == 28);
    accept[28] = '\0';
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
        accept);
    assert(response_len > 0 && (size_t)response_len < sizeof(response));
    for (size_t i = 0; i < (size_t)response_len; ++i) {
        size_t consumed = 0;
        int rc = tg_ws_upgrade_feed(&state, (const uint8_t *)response + i, 1,
                                    &consumed);
        assert(consumed == 1);
        assert(rc == (i + 1u == (size_t)response_len ? 1 : 0));
    }
    assert(state.complete && !state.failed);
}

static void test_websocket_upgrade_rejects_invalid_accept_value(void) {
    tg_ws_upgrade_state state = {0};
    assert(tg_ws_upgrade_start(&state, "kws2.web.telegram.org", "/apiws") == 0);
    size_t request_len = 0;
    assert(tg_ws_upgrade_pending(&state, &request_len) != NULL);
    assert(tg_ws_upgrade_advance(&state, request_len) == 0);
    const char response[] =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n";
    size_t consumed = 0;
    assert(tg_ws_upgrade_feed(&state, (const uint8_t *)response,
                              sizeof(response) - 1u, &consumed) == -1);
    assert(state.failed && consumed == sizeof(response) - 1u);
}

static void test_websocket_upgrade_rejects_invalid_state_and_controls(void) {
    tg_ws_upgrade_state state = {0};
    assert(tg_ws_upgrade_start(&state, "kws2.web.telegram.org", "/apiws") == 0);
    size_t consumed = 0;
    assert(tg_ws_upgrade_feed(&state, NULL, 0, &consumed) == -1);
    assert(state.failed && consumed == 0);

    tg_ws_upgrade_state corrupt = {.request_len = 1, .request_offset = 2};
    assert(tg_ws_upgrade_advance(&corrupt, 0) == -1);
    assert(tg_ws_upgrade_start_ex(&state, "kws2.web.telegram.org", "/apiws",
                                  NULL, "", NULL) == -1);

    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    assert(tg_ws_upgrade_start(&state, "kws2.web.telegram.org", "/apiws") == 0);
    size_t request_len = 0;
    assert(tg_ws_upgrade_pending(&state, &request_len) != NULL);
    assert(tg_ws_upgrade_advance(&state, request_len) == 0);
    char source[64], accept[40], response[512];
    int source_len = snprintf(source, sizeof(source), "%s%s", state.key, guid);
    uint8_t digest[SHA_DIGEST_LENGTH];
    unsigned int digest_len = 0;
    assert(source_len > 0 && (size_t)source_len < sizeof(source));
    assert(EVP_Digest(source, (size_t)source_len, digest, &digest_len,
                      EVP_sha1(), NULL) == 1 && digest_len == sizeof(digest));
    assert(EVP_EncodeBlock((unsigned char *)accept, digest,
                           (int)sizeof(digest)) == 28);
    accept[28] = '\0';
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n"
        "X-Test: bad\001value\r\n\r\n", accept);
    assert(response_len > 0 && (size_t)response_len < sizeof(response));
    assert(tg_ws_upgrade_feed(&state, (const uint8_t *)response,
                              (size_t)response_len, &consumed) == -1);
    assert(state.failed && consumed > 0);
}

static void test_shipped_relay_trust_bundle_loads(void) {
    SSL_CTX *ctx=tg_tls_client_context("../files/tg-roots.pem");
    assert(ctx!=NULL);SSL_CTX_free(ctx);
}

static void test_websocket_upgrade_fragmentation_and_text_rejection(void) {
    char dir[] = "/tmp/d2k-tg-ws-XXXXXX", cert_path[256], key_path[256];
    EVP_PKEY *key; X509 *cert; SSL_CTX *client_ctx; SSL *ssl;
    pthread_t thread; server_args args = {0};
    tg_ws_pump pump; pump_capture capture={0};
    assert(mkdtemp(dir) != NULL);
    snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", dir);
    snprintf(key_path, sizeof(key_path), "%s/key.pem", dir);
    key=make_key(); cert=make_cert(key);
    FILE *f=fopen(cert_path,"w"); assert(f && PEM_write_X509(f,cert)==1); fclose(f);
    f=fopen(key_path,"w"); assert(f && PEM_write_PrivateKey(f,key,NULL,NULL,0,NULL,NULL)==1); fclose(f);
    X509_free(cert); EVP_PKEY_free(key);
    args.cert=cert_path; args.key=key_path; args.listener=listen_loopback();
    assert(pthread_create(&thread,NULL,serve_ws,&args)==0);
    client_ctx=tg_tls_client_context(cert_path); assert(client_ctx);
    ssl=tg_tls_connect_fd(client_ctx,connect_loopback(args.listener),"relay.test"); assert(ssl);
    assert(tg_ws_upgrade(ssl,"relay.test:443","/ws")==0);
    assert(tg_ws_pump_init(&pump,ssl)==0);
    assert(pump.rx_cap <= 16u * 1024u);
    assert(tg_ws_pump_queue_binary(&pump,(const uint8_t *)"hello",5)==0);
    int process_result=0;
    for(unsigned i=0;i<50&&process_result==0;i++) {
        struct pollfd pfd={.fd=tg_ws_pump_fd(&pump),.events=tg_ws_pump_events(&pump)};
        int rc=poll(&pfd,1,200); assert(rc>=0);
        process_result=tg_ws_pump_process(&pump,pfd.revents,capture_message,&capture);
        if(process_result!=0)break;
    }
    assert(process_result==-1 && pump.failed);
    assert(capture.received && capture.len==2 && memcmp(capture.data,"ok",2)==0);
    assert(pump.tx_bytes==0 && pump.tx_memory_bytes==0 && pump.tx_head==NULL);
    tg_ws_pump_destroy(&pump);
    SSL_free(ssl); SSL_CTX_free(client_ctx); pthread_join(thread,NULL); close(args.listener);
    unlink(key_path); unlink(cert_path); rmdir(dir);
}

static void test_websocket_pump_grows_and_releases_large_receive_buffers(void) {
    const size_t payload_len = 1024u * 1024u;
    char dir[] = "/tmp/d2k-tg-ws-large-XXXXXX", cert_path[256], key_path[256];
    assert(mkdtemp(dir) != NULL);
    snprintf(cert_path, sizeof(cert_path), "%s/cert.pem", dir);
    snprintf(key_path, sizeof(key_path), "%s/key.pem", dir);
    EVP_PKEY *key = make_key();
    X509 *cert = make_cert(key);
    FILE *file = fopen(cert_path, "w");
    assert(file && PEM_write_X509(file, cert) == 1);
    fclose(file);
    file = fopen(key_path, "w");
    assert(file && PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(file);
    X509_free(cert);
    EVP_PKEY_free(key);

    server_args args = {.listener = listen_loopback(), .cert = cert_path,
                        .key = key_path, .payload_len = payload_len};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, serve_large_ws, &args) == 0);
    SSL_CTX *client_ctx = tg_tls_client_context(cert_path);
    assert(client_ctx != NULL);
    SSL *ssl = tg_tls_connect_fd(client_ctx, connect_loopback(args.listener),
                                 "relay.test");
    assert(ssl != NULL);
    tg_ws_pump pump;
    tg_memory_budget budget = {.limit = 8u * 1024u * 1024u};
    assert(tg_ws_pump_init_accounted(&pump, ssl, &budget) == 0);
    assert(pump.rx_cap <= 16u * 1024u);
    assert(budget.used == pump.rx_cap);
    large_pump_capture capture = {.pump = &pump, .expected_len = payload_len};
    for (unsigned i = 0; i < 100 && !pump.closed; ++i) {
        struct pollfd pfd = {.fd = tg_ws_pump_fd(&pump),
                             .events = tg_ws_pump_events(&pump)};
        int ready = poll(&pfd, 1, 10000);
        assert(ready > 0);
        assert(tg_ws_pump_process(&pump, pfd.revents,
                                  capture_large_message, &capture) == 0);
    }
    assert(capture.received);
    assert(capture.rx_cap_at_callback >= payload_len / 2u);
    assert(capture.reassembly_cap_at_callback >= payload_len);
    assert(budget.peak > payload_len);
    assert(pump.rx_cap <= 64u * 1024u);
    assert(pump.reassembly.cap <= 64u * 1024u);
    tg_ws_pump_destroy(&pump);
    assert(budget.used == 0);
    SSL_free(ssl);
    SSL_CTX_free(client_ctx);
    pthread_join(thread, NULL);
    close(args.listener);
    unlink(key_path);
    unlink(cert_path);
    assert(rmdir(dir) == 0);
}

static void test_websocket_tiny_frames_charge_allocations(void) {
    tg_ws_pump pump={0};size_t accepted=0;
    while(accepted<150000 && tg_ws_pump_queue_binary(&pump,NULL,0)==0){
        accepted++;assert(pump.tx_memory_bytes<=TG_WS_MAX_MESSAGE+64u);
    }
    assert(accepted>0 && accepted<150000);
    assert(pump.tx_bytes<4u*1024u*1024u);
    size_t memory=pump.tx_memory_bytes;
    assert(tg_ws_pump_queue_binary(&pump,NULL,0)!=0 && pump.tx_memory_bytes==memory);
    tg_ws_pump_destroy(&pump);
    assert(pump.tx_memory_bytes==0 && pump.tx_bytes==0);
    assert(tg_ws_pump_queue_binary(&pump,(const uint8_t *)"x",1)==0);
    tg_ws_pump_destroy(&pump);
}

static void test_websocket_partial_write_retains_memory_budget(void) {
    int sockets[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,sockets)==0);
    for(size_t i=0;i<2;i++){
        int flags=fcntl(sockets[i],F_GETFL,0);assert(flags>=0);
        assert(fcntl(sockets[i],F_SETFL,flags|O_NONBLOCK)==0);
    }
    int sendbuf=65536;assert(setsockopt(sockets[0],SOL_SOCKET,SO_SNDBUF,&sendbuf,sizeof(sendbuf))==0);
    SSL_CTX *server_ctx=SSL_CTX_new(TLS_server_method()),*client_ctx=SSL_CTX_new(TLS_client_method());
    EVP_PKEY *key=make_key();X509 *cert=make_cert(key);assert(server_ctx && client_ctx);
    assert(SSL_CTX_use_certificate(server_ctx,cert)==1 && SSL_CTX_use_PrivateKey(server_ctx,key)==1);
    X509_free(cert);EVP_PKEY_free(key);
    SSL *client=SSL_new(client_ctx),*server=SSL_new(server_ctx);assert(client && server);
    assert(SSL_set_fd(client,sockets[0])==1 && SSL_set_fd(server,sockets[1])==1);
    SSL_set_connect_state(client);SSL_set_accept_state(server);
    for(unsigned i=0;i<1000 && (!SSL_is_init_finished(client)||!SSL_is_init_finished(server));i++){
        SSL *peers[]={client,server};
        for(size_t j=0;j<2;j++)if(!SSL_is_init_finished(peers[j])){
            int rc=SSL_do_handshake(peers[j]);
            if(rc!=1){int error=SSL_get_error(peers[j],rc);assert(error==SSL_ERROR_WANT_READ||error==SSL_ERROR_WANT_WRITE);}
        }
    }
    assert(SSL_is_init_finished(client) && SSL_is_init_finished(server));
    SSL_set_mode(client,SSL_MODE_ENABLE_PARTIAL_WRITE);
    tg_ws_pump pump;assert(tg_ws_pump_init(&pump,client)==0);
    uint8_t *payload=malloc(TG_WS_MAX_MESSAGE);assert(payload);memset(payload,1,TG_WS_MAX_MESSAGE);
    assert(tg_ws_pump_queue_binary(&pump,payload,TG_WS_MAX_MESSAGE)==0);
    size_t queued=pump.tx_bytes,memory=pump.tx_memory_bytes;
    assert(memory>queued && memory<=TG_WS_MAX_MESSAGE+64u);
    assert(tg_ws_pump_process(&pump,POLLOUT,NULL,NULL)==0);
    assert(pump.tx_bytes>0 && pump.tx_bytes<queued);
    assert(pump.tx_memory_bytes==memory);
    assert(tg_ws_pump_queue_binary(&pump,payload,TG_WS_MAX_MESSAGE)!=0);
    assert(pump.tx_memory_bytes==memory);
    uint8_t *wire=malloc(queued);assert(wire);size_t received=0;
    for(unsigned i=0;i<1000 && (pump.tx_bytes||received<queued);i++){
        assert(tg_ws_pump_process(&pump,POLLOUT,NULL,NULL)==0);
        while(received<queued){
            size_t n=0;int rc=SSL_read_ex(server,wire+received,queued-received,&n);
            if(rc!=1){int error=SSL_get_error(server,rc);assert(error==SSL_ERROR_WANT_READ||error==SSL_ERROR_WANT_WRITE);break;}
            assert(n>0);received+=n;
        }
    }
    assert(received==queued && pump.tx_bytes==0 && pump.tx_memory_bytes==0);
    uint8_t length[10]={0x82,0xff,0,0,0,0,0,0x40,0,0};
    assert(memcmp(wire,length,sizeof(length))==0);
    for(size_t i=0;i<TG_WS_MAX_MESSAGE;i++)assert((uint8_t)(wire[14+i]^wire[10+(i&3)])==1);
    assert(tg_ws_pump_queue_binary(&pump,payload,TG_WS_MAX_MESSAGE)==0);
    tg_ws_pump_destroy(&pump);free(payload);free(wire);
    SSL_free(client);SSL_free(server);SSL_CTX_free(client_ctx);SSL_CTX_free(server_ctx);
    close(sockets[0]);close(sockets[1]);
}

int main(void) {
    test_websocket_partial_write_retains_memory_budget();
    test_websocket_tiny_frames_charge_allocations();
    test_tls_client_preparation_is_nonblocking();
    test_websocket_upgrade_accepts_incremental_valid_response();
    test_websocket_upgrade_rejects_invalid_accept_value();
    test_websocket_upgrade_rejects_invalid_state_and_controls();
    test_sni_and_certificate_validation();
    test_shipped_relay_trust_bundle_loads();
    test_websocket_upgrade_fragmentation_and_text_rejection();
    test_websocket_pump_grows_and_releases_large_receive_buffers();
    puts("TLS verification tests: ok");
    return 0;
}
