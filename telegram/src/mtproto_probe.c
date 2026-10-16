#define _POSIX_C_SOURCE 200809L
#include "tg_mtproto.h"
#include "tg_mtproto_auth.h"
#include "tg_mtproto_discovery.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#define TG_PROBE_MAX_PACKET (1024u * 1024u)
#define TG_PROBE_MAX_FINGERPRINTS 64u

static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static int wait_fd(int fd, short events, uint64_t deadline) {
    for (;;) {
        uint64_t now = monotonic_ms();
        if (now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        uint64_t left = deadline - now;
        int timeout = left > (uint64_t)INT_MAX ? INT_MAX : (int)left;
        struct pollfd pollfd = {.fd = fd, .events = events};
        int rc = poll(&pollfd, 1, timeout);
        if (rc > 0) {
            if (pollfd.revents & POLLNVAL) {
                errno = EBADF;
                return -1;
            }
            if (pollfd.revents & (events | POLLERR | POLLHUP)) return 0;
            continue;
        }
        if (rc == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (errno != EINTR) return -1;
    }
}

static int transfer_all(int fd, uint8_t *data, size_t len, int writing,
                        uint64_t deadline) {
    size_t used = 0;
    while (used < len) {
        ssize_t n;
        if (writing) {
            int flags = 0;
#ifdef MSG_NOSIGNAL
            flags |= MSG_NOSIGNAL;
#endif
            n = send(fd, data + used, len - used, flags);
        } else {
            n = recv(fd, data + used, len - used, 0);
        }
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (wait_fd(fd, writing ? POLLOUT : POLLIN, deadline) != 0)
                return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

static uint32_t read_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void write_le32(uint8_t bytes[4], uint32_t value) {
    for (size_t i = 0; i < 4; ++i) bytes[i] = (uint8_t)(value >> (8u * i));
}

static uint64_t read_le64(const uint8_t *bytes) {
    return (uint64_t)read_le32(bytes) |
           ((uint64_t)read_le32(bytes + 4) << 32);
}

static void write_le64(uint8_t *bytes, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) bytes[i] = (uint8_t)(value >> (8u * i));
}

static int make_message_id(uint8_t out[8], int32_t time_offset,
                           uint64_t *last_message_id) {
    struct timespec now;
    if (!out || clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0)
        return -1;
    int64_t adjusted = (int64_t)now.tv_sec + time_offset;
    if (adjusted <= 0 || (uint64_t)adjusted > UINT32_MAX) return -1;
    uint64_t seconds = (uint64_t)adjusted;
    uint64_t fraction = ((uint64_t)now.tv_nsec << 32) / UINT64_C(1000000000);
    uint64_t message_id = ((seconds << 32) | fraction) & ~UINT64_C(3);
    if (last_message_id) {
        if (message_id <= *last_message_id) {
            if (*last_message_id > UINT64_MAX - 4) return -1;
            message_id = *last_message_id + 4;
        }
        *last_message_id = message_id;
    }
    write_le64(out, message_id);
    return 0;
}

static int read_tl_bytes(const uint8_t *data, size_t len, size_t *offset,
                         const uint8_t **value, size_t *value_len) {
    if (*offset >= len) return -1;
    size_t prefix, count;
    uint8_t first = data[*offset];
    if (first < 254) {
        prefix = 1;
        count = first;
    } else if (first == 254) {
        if (len - *offset < 4) return -1;
        prefix = 4;
        count = (size_t)data[*offset + 1] |
                ((size_t)data[*offset + 2] << 8) |
                ((size_t)data[*offset + 3] << 16);
        if (count < 254) return -1;
    } else {
        return -1;
    }
    if (count > len - *offset - prefix) return -1;
    *value = data + *offset + prefix;
    *value_len = count;
    size_t encoded = prefix + count;
    size_t padding = (4u - (encoded & 3u)) & 3u;
    if (padding > len - *offset - encoded) return -1;
    *offset += encoded + padding;
    return 0;
}

static int parse_res_pq(const uint8_t *body, size_t len,
                        const uint8_t expected_nonce[16],
                        tg_mtproto_probe_result *out) {
    static const uint8_t vector_magic[4] = {0x15, 0xc4, 0xb5, 0x1c};
    size_t offset = 0;
    const uint8_t *pq;
    size_t pq_len;
    if (len < 4 + 16 + 16 + 1 + 4 + 4 + 8 ||
        read_le32(body) != UINT32_C(0x05162463))
        return -1;
    offset = 4;
    if (memcmp(body + offset, expected_nonce, 16) != 0) return -1;
    memcpy(out->nonce, body + offset, 16);
    offset += 16;
    memcpy(out->server_nonce, body + offset, 16);
    offset += 16;
    if (read_tl_bytes(body, len, &offset, &pq, &pq_len) != 0 ||
        pq_len == 0 || pq_len > sizeof(out->pq) ||
        len - offset < 8 || memcmp(body + offset, vector_magic, 4) != 0)
        return -1;
    memcpy(out->pq, pq, pq_len);
    out->pq_len = pq_len;
    offset += 4;
    uint32_t fingerprints = read_le32(body + offset);
    offset += 4;
    if (!fingerprints || fingerprints > TG_PROBE_MAX_FINGERPRINTS ||
        (size_t)fingerprints > (len - offset) / 8 ||
        len - offset != (size_t)fingerprints * 8)
        return -1;
    return 0;
}

static int parse_plain_response(const uint8_t *packet, size_t len,
                                const uint8_t **body, size_t *body_len) {
    static const uint8_t zero_auth_key_id[8] = {0};
    uint64_t message_id;
    if (!packet || !body || !body_len || len < 20 ||
        memcmp(packet, zero_auth_key_id, sizeof(zero_auth_key_id)) != 0)
        return -1;
    message_id = read_le64(packet + 8);
    if (!message_id || (message_id >> 63) || (message_id & 3u) != 1u)
        return -1;
    uint32_t message_len = read_le32(packet + 16);
    if (!message_len || (size_t)message_len != len - 20) return -1;
    *body = packet + 20;
    *body_len = message_len;
    return 0;
}

static int make_address(const char *text, uint16_t port,
                        struct sockaddr_storage *storage,
                        socklen_t *length) {
    if (!text || !*text || !port) return -1;
    struct sockaddr_in v4 = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, text, &v4.sin_addr) == 1) {
        memset(storage, 0, sizeof(*storage));
        memcpy(storage, &v4, sizeof(v4));
        *length = sizeof(v4);
        return AF_INET;
    }
    struct sockaddr_in6 v6 = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    if (inet_pton(AF_INET6, text, &v6.sin6_addr) == 1) {
        memset(storage, 0, sizeof(*storage));
        memcpy(storage, &v6, sizeof(v6));
        *length = sizeof(v6);
        return AF_INET6;
    }
    return -1;
}

tg_mtproto_probe_status tg_mtproto_probe_res_pq(
    const char *numeric_address, uint16_t port, uint32_t dc_id, int is_media,
    uint32_t timeout_ms, tg_mtproto_probe_result *out) {
    struct sockaddr_storage address;
    socklen_t address_len = 0;
    uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN];
    uint8_t request[40] = {0}, length_bytes[4];
    tg_mtproto_ctr to_server = {0}, from_server = {0};
    uint8_t *body = NULL;
    int fd = -1;
    tg_mtproto_probe_status status = TG_MTPROTO_PROBE_INVALID;
    uint64_t started = monotonic_ms(), deadline;
    uint64_t last_message_id = 0;
    if (!out) return TG_MTPROTO_PROBE_INVALID;
    memset(out, 0, sizeof(*out));
    out->status = TG_MTPROTO_PROBE_INVALID;
    int family = make_address(numeric_address, port, &address, &address_len);
    if (family < 0 || dc_id < 1 || dc_id > 999 ||
        (is_media != 0 && is_media != 1) || timeout_ms == 0 ||
        timeout_ms > 60000)
        goto done;
    out->stage = TG_MTPROTO_PROBE_STAGE_TCP;
    deadline = started + timeout_ms;
    if (RAND_bytes(out->nonce, sizeof(out->nonce)) != 1) {
        status = TG_MTPROTO_PROBE_IO;
        goto done;
    }
    if (tg_mtproto_make_obfuscated2_init(TG_MTPROTO_INTERMEDIATE, dc_id,
                                         is_media, handshake, &to_server,
                                         &from_server) != 0) {
        status = TG_MTPROTO_PROBE_IO;
        goto done;
    }
    fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        status = TG_MTPROTO_PROBE_CONNECT;
        goto done;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        status = TG_MTPROTO_PROBE_IO;
        goto done;
    }
    int connect_rc = connect(fd, (struct sockaddr *)&address, address_len);
    if (connect_rc != 0 && errno != EINPROGRESS) {
        status = errno == ETIMEDOUT ? TG_MTPROTO_PROBE_TIMEOUT
                                    : TG_MTPROTO_PROBE_CONNECT;
        goto done;
    }
    if (connect_rc != 0) {
        if (wait_fd(fd, POLLOUT, deadline) != 0) {
            status = errno == ETIMEDOUT ? TG_MTPROTO_PROBE_TIMEOUT
                                        : TG_MTPROTO_PROBE_CONNECT;
            goto done;
        }
        int error = 0;
        socklen_t error_len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error) {
            if (error) errno = error;
            status = TG_MTPROTO_PROBE_CONNECT;
            goto done;
        }
    }
    out->stage = TG_MTPROTO_PROBE_STAGE_MTPROTO;

    if (make_message_id(request + 8, 0, &last_message_id) != 0) {
        status = TG_MTPROTO_PROBE_IO;
        goto done;
    }
    request[16] = 20;
    memcpy(request + 20, "\xf1\x8e\x7e\xbe", 4);
    memcpy(request + 24, out->nonce, sizeof(out->nonce));
    uint8_t request_len[4] = {sizeof(request), 0, 0, 0};
    if (tg_mtproto_ctr_xor(&to_server, request_len, sizeof(request_len)) != 0 ||
        tg_mtproto_ctr_xor(&to_server, request, sizeof(request)) != 0 ||
        transfer_all(fd, handshake, sizeof(handshake), 1, deadline) != 0 ||
        transfer_all(fd, request_len, sizeof(request_len), 1, deadline) != 0 ||
        transfer_all(fd, request, sizeof(request), 1, deadline) != 0) {
        status = errno == ETIMEDOUT ? TG_MTPROTO_PROBE_TIMEOUT
                                    : TG_MTPROTO_PROBE_IO;
        goto done;
    }
    if (transfer_all(fd, length_bytes, sizeof(length_bytes), 0, deadline) != 0 ||
        tg_mtproto_ctr_xor(&from_server, length_bytes,
                           sizeof(length_bytes)) != 0) {
        status = errno == ETIMEDOUT ? TG_MTPROTO_PROBE_TIMEOUT
                                    : TG_MTPROTO_PROBE_IO;
        goto done;
    }
    uint32_t packet_len = read_le32(length_bytes);
    if (packet_len <= 20 || packet_len > TG_PROBE_MAX_PACKET) goto done;
    body = malloc(packet_len);
    if (!body) {
        status = TG_MTPROTO_PROBE_IO;
        goto done;
    }
    if (transfer_all(fd, body, packet_len, 0, deadline) != 0 ||
        tg_mtproto_ctr_xor(&from_server, body, packet_len) != 0) {
        status = errno == ETIMEDOUT ? TG_MTPROTO_PROBE_TIMEOUT
                                    : TG_MTPROTO_PROBE_IO;
        goto done;
    }
    const uint8_t *response_body = NULL;
    size_t response_body_len = 0;
    if (parse_plain_response(body, packet_len, &response_body,
                             &response_body_len) == 0 &&
        parse_res_pq(response_body, response_body_len, out->nonce, out) == 0) {
        status = TG_MTPROTO_PROBE_OK;
        out->stage = TG_MTPROTO_PROBE_STAGE_RES_PQ;
    } else {
        status = TG_MTPROTO_PROBE_INVALID;
    }
done:
    out->status = status;
    if (started && monotonic_ms() >= started)
        out->latency_ms = monotonic_ms() - started;
    if (fd >= 0) close(fd);
    free(body);
    tg_mtproto_ctr_destroy(&to_server);
    tg_mtproto_ctr_destroy(&from_server);
    OPENSSL_cleanse(handshake, sizeof(handshake));
    OPENSSL_cleanse(request, sizeof(request));
    return status;
}

typedef struct {
    uint8_t data[1024];
    size_t len;
} discovery_writer;

static int discovery_write(discovery_writer *writer, const void *data,
                           size_t len) {
    if (!writer || (len && !data) || writer->len > sizeof(writer->data) ||
        len > sizeof(writer->data) - writer->len)
        return -1;
    if (len) memcpy(writer->data + writer->len, data, len);
    writer->len += len;
    return 0;
}

static int discovery_write_u32(discovery_writer *writer, uint32_t value) {
    uint8_t bytes[4];
    write_le32(bytes, value);
    return discovery_write(writer, bytes, sizeof(bytes));
}

static int discovery_write_u64(discovery_writer *writer, uint64_t value) {
    uint8_t bytes[8];
    write_le64(bytes, value);
    return discovery_write(writer, bytes, sizeof(bytes));
}

static int discovery_write_tl_bytes(discovery_writer *writer,
                                    const uint8_t *value, size_t value_len) {
    uint8_t prefix[4];
    const uint8_t zero[3] = {0};
    size_t prefix_len;
    if (value_len > UINT32_C(0xffffff) || (value_len && !value)) return -1;
    if (value_len < 254) {
        prefix[0] = (uint8_t)value_len;
        prefix_len = 1;
    } else {
        prefix[0] = 254;
        prefix[1] = (uint8_t)value_len;
        prefix[2] = (uint8_t)(value_len >> 8);
        prefix[3] = (uint8_t)(value_len >> 16);
        prefix_len = 4;
    }
    size_t padding = (4u - ((prefix_len + value_len) & 3u)) & 3u;
    return discovery_write(writer, prefix, prefix_len) != 0 ||
                   discovery_write(writer, value, value_len) != 0 ||
                   discovery_write(writer, zero, padding) != 0
               ? -1
               : 0;
}

static int discovery_write_string(discovery_writer *writer,
                                  const char *value) {
    return value ? discovery_write_tl_bytes(
                       writer, (const uint8_t *)value, strlen(value))
                 : -1;
}

static int send_frame(int fd, tg_mtproto_ctr *to_server,
                      const uint8_t *payload, size_t payload_len,
                      uint64_t deadline) {
    uint8_t length_bytes[4];
    uint8_t *copy = NULL;
    int rc = -1;
    if (!to_server || !payload || payload_len < 1 ||
        payload_len > TG_PROBE_MAX_PACKET || payload_len > UINT32_MAX)
        return -1;
    copy = malloc(payload_len);
    if (!copy) return -1;
    memcpy(copy, payload, payload_len);
    write_le32(length_bytes, (uint32_t)payload_len);
    if (tg_mtproto_ctr_xor(to_server, length_bytes, sizeof(length_bytes)) == 0 &&
        tg_mtproto_ctr_xor(to_server, copy, payload_len) == 0 &&
        transfer_all(fd, length_bytes, sizeof(length_bytes), 1, deadline) == 0 &&
        transfer_all(fd, copy, payload_len, 1, deadline) == 0)
        rc = 0;
    OPENSSL_cleanse(length_bytes, sizeof(length_bytes));
    OPENSSL_cleanse(copy, payload_len);
    free(copy);
    return rc;
}

static int read_frame(int fd, tg_mtproto_ctr *from_server,
                      uint64_t deadline, uint8_t **payload,
                      size_t *payload_len) {
    uint8_t length_bytes[4];
    uint8_t *packet = NULL;
    int rc = -1;
    if (!from_server || !payload || !payload_len) return -1;
    *payload = NULL;
    *payload_len = 0;
    if (transfer_all(fd, length_bytes, sizeof(length_bytes), 0, deadline) != 0 ||
        tg_mtproto_ctr_xor(from_server, length_bytes, sizeof(length_bytes)) != 0)
        goto done;
    uint32_t len = read_le32(length_bytes);
    if (len < 20 || len > TG_PROBE_MAX_PACKET) goto done;
    packet = malloc(len);
    if (!packet || transfer_all(fd, packet, len, 0, deadline) != 0 ||
        tg_mtproto_ctr_xor(from_server, packet, len) != 0)
        goto done;
    *payload = packet;
    *payload_len = len;
    packet = NULL;
    rc = 0;
done:
    if (packet) {
        OPENSSL_cleanse(packet, read_le32(length_bytes));
        free(packet);
    }
    OPENSSL_cleanse(length_bytes, sizeof(length_bytes));
    return rc;
}

static int exchange_plain(int fd, tg_mtproto_ctr *to_server,
                          tg_mtproto_ctr *from_server, const uint8_t *body,
                          size_t body_len, uint64_t deadline,
                          uint64_t *last_message_id,
                          uint64_t *request_message_id, uint8_t *response,
                          size_t response_cap, size_t *response_len) {
    uint8_t request[4096] = {0};
    uint8_t *packet = NULL;
    size_t packet_len = 0;
    const uint8_t *response_body = NULL;
    size_t response_body_len = 0;
    int rc = -1;
    if (!body || !body_len || body_len > sizeof(request) - 20 ||
        !response || !response_len || !request_message_id)
        goto done;
    if (make_message_id(request + 8, 0, last_message_id) != 0) goto done;
    *request_message_id = read_le64(request + 8);
    write_le32(request + 16, (uint32_t)body_len);
    memcpy(request + 20, body, body_len);
    if (send_frame(fd, to_server, request, 20 + body_len, deadline) != 0 ||
        read_frame(fd, from_server, deadline, &packet, &packet_len) != 0 ||
        parse_plain_response(packet, packet_len, &response_body,
                             &response_body_len) != 0 ||
        response_body_len > response_cap)
        goto done;
    memcpy(response, response_body, response_body_len);
    *response_len = response_body_len;
    rc = 0;
done:
    if (packet) {
        OPENSSL_cleanse(packet, packet_len);
        free(packet);
    }
    OPENSSL_cleanse(request, sizeof(request));
    return rc;
}

static int build_config_query(discovery_writer *writer) {
    return discovery_write_u32(writer, UINT32_C(0xda9b0d0d)) != 0 ||
                   discovery_write_u32(writer, 227) != 0 ||
                   discovery_write_u32(writer, UINT32_C(0xc1cd5ea9)) != 0 ||
                   discovery_write_u32(writer, 0) != 0 ||
                   discovery_write_u32(writer, 4) != 0 ||
                   discovery_write_string(writer, "OpenWrt") != 0 ||
                   discovery_write_string(writer, "OpenWrt") != 0 ||
                   discovery_write_string(writer, "d2k-tg-0.3") != 0 ||
                   discovery_write_string(writer, "ru") != 0 ||
                   discovery_write_string(writer, "") != 0 ||
                   discovery_write_string(writer, "ru") != 0 ||
                   discovery_write_u32(writer, UINT32_C(0xc4f9186b)) != 0
               ? -1
               : 0;
}

int tg_mtproto_parse_rpc_result(const uint8_t *body, size_t body_len,
                                uint64_t request_message_id,
                                uint32_t outer_seqno, const uint8_t **result,
                                size_t *result_len) {
    const uint32_t rpc_result = UINT32_C(0xf35c6d01);
    const uint32_t msg_container = UINT32_C(0x73f1f8dc);
    const uint32_t new_session_created = UINT32_C(0x9ec20908);
    if (!body || !result || !result_len || body_len < 4) return -1;
    *result = NULL;
    *result_len = 0;
    uint32_t constructor = read_le32(body);
    if (constructor == rpc_result) {
        if ((outer_seqno & 1u) == 0 || body_len < 12 ||
            read_le64(body + 4) != request_message_id)
            return -1;
        *result = body + 12;
        *result_len = body_len - 12;
        return *result_len ? 0 : -1;
    }
    if (constructor == new_session_created)
        return body_len == 28 ? 1 : -1;
    if (constructor != msg_container || (outer_seqno & 1u) != 0 ||
        body_len < 8 || read_le32(body + 4) > 128)
        return -1;
    size_t offset = 8;
    uint32_t count = read_le32(body + 4);
    if (count == 0) return body_len == 8 ? 1 : -1;
    int found = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (offset > body_len || body_len - offset < 16) return -1;
        uint64_t message_id = read_le64(body + offset);
        uint32_t seqno = read_le32(body + offset + 8);
        uint32_t message_len = read_le32(body + offset + 12);
        offset += 16;
        if (!message_id || (message_id & 3u) != 1u ||
            seqno > INT32_MAX || message_len == 0 ||
            message_len > body_len - offset)
            return -1;
        const uint8_t *message = body + offset;
        uint32_t inner_constructor = read_le32(message);
        if (inner_constructor == rpc_result && message_len >= 12 &&
            read_le64(message + 4) == request_message_id) {
            if ((seqno & 1u) == 0 || found) return -1;
            *result = message + 12;
            *result_len = message_len - 12;
            if (!*result_len) return -1;
            found = 1;
        } else if (inner_constructor == new_session_created) {
            if (message_len != 28) return -1;
        }
        offset += message_len;
    }
    if (offset != body_len) return -1;
    return found ? 0 : 1;
}

int tg_mtproto_discover_config(const char *numeric_address, uint16_t port,
                               uint32_t dc_id, uint32_t timeout_ms,
                               uint32_t socket_mark, int64_t now,
                               tg_dc_snapshot *out) {
    struct sockaddr_storage address;
    socklen_t address_len = 0;
    tg_mtproto_auth_state auth = {0};
    tg_mtproto_ctr to_server = {0}, from_server = {0};
    tg_dc_snapshot fetched = {0};
    uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN] = {0};
    uint8_t req_pq[20] = {0}, random2[256] = {0}, random3[272] = {0};
    uint8_t request2[512] = {0}, request3[600] = {0}, response[2048] = {0};
    uint8_t padding[32] = {0}, session_id[8] = {0}, id_bytes[8] = {0};
    uint8_t encrypted_request[2048] = {0};
    uint8_t *encrypted_response = NULL, *plain = NULL;
    size_t response_len = 0, request2_len = 0, request3_len = 0;
    size_t encrypted_response_len = 0, plain_len = 0;
    size_t encrypted_request_len = 0, padding_len = 0;
    const uint8_t *rpc_value = NULL;
    size_t rpc_value_len = 0;
    uint64_t message_id = 0;
    int fd = -1, family, rc = -1;
    uint64_t started = monotonic_ms(), deadline = 0;
    uint64_t last_plain_message_id = 0;
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !numeric_address || !port || dc_id < 1 || dc_id > 999 ||
        timeout_ms == 0 || timeout_ms > 60000 || now <= 0)
        goto done;
    family = make_address(numeric_address, port, &address, &address_len);
    if (family < 0) goto done;
    deadline = started + timeout_ms;
    fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) goto done;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
        goto done;
    if (socket_mark) {
#ifdef SO_MARK
        if (setsockopt(fd, SOL_SOCKET, SO_MARK, &socket_mark,
                       sizeof(socket_mark)) != 0)
            goto done;
#else
        goto done;
#endif
    }
    int connect_rc = connect(fd, (struct sockaddr *)&address, address_len);
    if (connect_rc != 0 && errno != EINPROGRESS) goto done;
    if (connect_rc != 0) {
        if (wait_fd(fd, POLLOUT, deadline) != 0) goto done;
        int error = 0;
        socklen_t error_len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 ||
            error != 0)
            goto done;
    }
    if (RAND_bytes(auth.nonce, sizeof(auth.nonce)) != 1 ||
        tg_mtproto_make_obfuscated2_init(TG_MTPROTO_INTERMEDIATE, dc_id, 0,
                                         handshake, &to_server,
                                         &from_server) != 0 ||
        transfer_all(fd, handshake, sizeof(handshake), 1, deadline) != 0)
        goto done;

    memcpy(req_pq, "\xf1\x8e\x7e\xbe", 4);
    memcpy(req_pq + 4, auth.nonce, sizeof(auth.nonce));
    if (exchange_plain(fd, &to_server, &from_server, req_pq, sizeof(req_pq),
                       deadline, &last_plain_message_id, &message_id, response, sizeof(response),
                       &response_len) != 0 ||
        RAND_bytes(random2, sizeof(random2)) != 1 ||
        tg_mtproto_auth_step2(&auth, response, response_len, random2,
                              request2, sizeof(request2), &request2_len) != 0 ||
        exchange_plain(fd, &to_server, &from_server, request2, request2_len,
                       deadline, &last_plain_message_id, &message_id, response, sizeof(response),
                       &response_len) != 0 ||
        RAND_bytes(random3, sizeof(random3)) != 1 ||
        tg_mtproto_auth_step3(&auth, response, response_len, random3,
                              (int32_t)now, request3, sizeof(request3),
                              &request3_len) != 0 ||
        exchange_plain(fd, &to_server, &from_server, request3, request3_len,
                       deadline, &last_plain_message_id, &message_id, response, sizeof(response),
                       &response_len) != 0 ||
        tg_mtproto_auth_step4(&auth, response, response_len) != 0 ||
        !auth.auth_key_ready || RAND_bytes(session_id, sizeof(session_id)) != 1)
        goto done;

    discovery_writer query = {0};
    if (build_config_query(&query) != 0) goto done;
    if (RAND_bytes(padding, sizeof(padding)) != 1) goto done;
    padding_len = 12 + ((16u - ((32u + query.len + 12u) & 15u)) & 15u);
    discovery_writer inner = {0};
    if (make_message_id(id_bytes, auth.time_offset, NULL) != 0) goto done;
    message_id = read_le64(id_bytes);
    if (discovery_write_u64(&inner, auth.first_salt) != 0 ||
        discovery_write(&inner, session_id, sizeof(session_id)) != 0 ||
        discovery_write_u64(&inner, message_id) != 0 ||
        discovery_write_u32(&inner, 1) != 0 ||
        discovery_write_u32(&inner, (uint32_t)query.len) != 0 ||
        discovery_write(&inner, query.data, query.len) != 0 ||
        inner.len + padding_len > sizeof(inner.data) ||
        tg_mtproto_v2_encrypt(auth.auth_key, inner.data, inner.len, padding,
                              padding_len, encrypted_request,
                              sizeof(encrypted_request),
                              &encrypted_request_len) != 0 ||
        send_frame(fd, &to_server, encrypted_request,
                   encrypted_request_len, deadline) != 0)
        goto done;
    int got_config = 0;
    for (unsigned frame = 0; frame < 16; ++frame) {
        if (read_frame(fd, &from_server, deadline, &encrypted_response,
                       &encrypted_response_len) != 0 ||
            encrypted_response_len < 40 ||
            (plain = malloc(encrypted_response_len - 24)) == NULL ||
            tg_mtproto_v2_decrypt(auth.auth_key, encrypted_response,
                                  encrypted_response_len, plain,
                                  encrypted_response_len - 24, &plain_len) != 0 ||
            plain_len < 32 || read_le64(plain) != auth.first_salt ||
            read_le64(plain + 8) != read_le64(session_id))
            goto done;
        uint64_t server_message_id = read_le64(plain + 16);
        uint32_t server_seqno = read_le32(plain + 24);
        uint32_t body_len = read_le32(plain + 28);
        int parsed = -1;
        if (server_message_id && (server_message_id & 3u) == 1u &&
            body_len <= plain_len - 32) {
            parsed = tg_mtproto_parse_rpc_result(
                plain + 32, body_len, message_id, server_seqno, &rpc_value,
                &rpc_value_len);
        }
        if (parsed == 0) {
            if (rpc_value_len < 4 ||
                tg_mtproto_config_parse(rpc_value, rpc_value_len, now,
                                        &fetched) != 0)
                goto done;
            got_config = 1;
        } else if (parsed < 0) {
            goto done;
        }
        OPENSSL_cleanse(encrypted_response, encrypted_response_len);
        free(encrypted_response);
        encrypted_response = NULL;
        encrypted_response_len = 0;
        OPENSSL_cleanse(plain, plain_len);
        free(plain);
        plain = NULL;
        plain_len = 0;
        if (got_config) break;
    }
    if (!got_config) goto done;
    *out = fetched;
    memset(&fetched, 0, sizeof(fetched));
    rc = 0;
done:
    if (fd >= 0) close(fd);
    if (encrypted_response) {
        OPENSSL_cleanse(encrypted_response, encrypted_response_len);
        free(encrypted_response);
    }
    if (plain) {
        OPENSSL_cleanse(plain, encrypted_response_len > 24
                                   ? encrypted_response_len - 24
                                   : 0);
        free(plain);
    }
    tg_mtproto_ctr_destroy(&to_server);
    tg_mtproto_ctr_destroy(&from_server);
    tg_mtproto_auth_clear(&auth);
    tg_dc_snapshot_destroy(&fetched);
    OPENSSL_cleanse(handshake, sizeof(handshake));
    OPENSSL_cleanse(req_pq, sizeof(req_pq));
    OPENSSL_cleanse(random2, sizeof(random2));
    OPENSSL_cleanse(random3, sizeof(random3));
    OPENSSL_cleanse(request2, sizeof(request2));
    OPENSSL_cleanse(request3, sizeof(request3));
    OPENSSL_cleanse(response, sizeof(response));
    OPENSSL_cleanse(padding, sizeof(padding));
    OPENSSL_cleanse(session_id, sizeof(session_id));
    OPENSSL_cleanse(encrypted_request, sizeof(encrypted_request));
    OPENSSL_cleanse(id_bytes, sizeof(id_bytes));
    return rc;
}
