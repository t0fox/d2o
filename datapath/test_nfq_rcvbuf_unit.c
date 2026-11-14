/* test_nfq_rcvbuf_unit.c — buffer-limit and privileged override decisions. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>

static int force_allowed;
static int forced_calls;
static int normal_calls;
static int observed_rcvbuf;
static int fails;

static int nfq_test_setsockopt(int fd, int level, int option,
                               const void *value, socklen_t len);
static int nfq_test_getsockopt(int fd, int level, int option,
                               void *value, socklen_t *len);

#define setsockopt nfq_test_setsockopt
#define getsockopt nfq_test_getsockopt
#include "nfq.c"
#undef getsockopt
#undef setsockopt

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "ПРОВАЛ: %s\n", msg); \
        fails++; \
    } \
} while (0)

static int nfq_test_setsockopt(int fd, int level, int option,
                               const void *value, socklen_t len) {
    (void)fd;
    if (level != SOL_SOCKET || len != sizeof(int)) {
        errno = EINVAL;
        return -1;
    }
    int requested = 0;
    memcpy(&requested, value, sizeof requested);
    if (option == SO_RCVBUFFORCE) {
        forced_calls++;
        if (!force_allowed) {
            errno = EPERM;
            return -1;
        }
        observed_rcvbuf = requested * 2;
        return 0;
    }
    if (option == SO_RCVBUF) {
        normal_calls++;
        observed_rcvbuf = 425984; /* doubled net.core.rmem_max = 212992 */
        return 0;
    }
    errno = ENOPROTOOPT;
    return -1;
}

static int nfq_test_getsockopt(int fd, int level, int option,
                               void *value, socklen_t *len) {
    (void)fd;
    if (level != SOL_SOCKET || option != SO_RCVBUF || *len < sizeof(int)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(value, &observed_rcvbuf, sizeof observed_rcvbuf);
    *len = sizeof observed_rcvbuf;
    return 0;
}

/* A socket can report an asynchronous error after its receive queue drains. */
static void test_error_only_wakeup(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int peer = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0 && peer >= 0, "cannot create UDP sockets");
    if (fd < 0 || peer < 0) goto done;
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(addr);
    if (bind(peer, (struct sockaddr *)&addr, sizeof(addr)) ||
        getsockname(peer, (struct sockaddr *)&addr, &len) ||
        connect(fd, (struct sockaddr *)&addr, len)) {
        CHECK(0, "cannot prepare UDP peer");
        goto done;
    }
    close(peer);
    peer = -1;
    CHECK(send(fd, "x", 1, 0) == 1, "cannot send UDP datagram");
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    CHECK(poll(&pfd, 1, 1000) == 1 && pfd.revents == POLLERR,
          "expected an error without readable data");
    if (d2k_nfq_read_event(pfd.revents)) {
        d2k_nfq q = {.fd = fd};
        uint8_t buf[8];
        CHECK(d2k_nfq_recv(&q, buf, sizeof(buf), NULL, 0) == -1,
              "pending socket error not consumed");
        CHECK(poll(&pfd, 1, 0) == 0, "error still keeps poll awake");
        CHECK(d2k_nfq_recv(&q, buf, sizeof(buf), NULL, 0) == 0,
              "empty read must return without blocking");
    } else {
        CHECK(0, "poll error without POLLIN skipped by the event loop");
    }
done:
    if (peer >= 0) close(peer);
    if (fd >= 0) close(fd);
}

static void test_verdict_timing(void) {
    d2k_nfq q = {0};
    uint32_t id = 23;
    d2k_nfq_note_packet(&q, id, 0, 1);
    note_verdict(&q, id, D2K_NF_ACCEPT, 0);
    CHECK(d2k_nfq_take_window(&q).userspace_samples == 0, "disabled timing");
    d2k_nfq_timing(&q, 1);
    d2k_nfq_note_packet(&q, id, 0, 1);
    note_verdict(&q, id, D2K_NF_DROP, 0);
    d2k_nfq_window window = d2k_nfq_take_window(&q);
    CHECK(window.drops == 1 && window.userspace_samples == 1 && window.no_timestamp == 1,
          "deferred verdict can use monotonic receive time without NFQA_TIMESTAMP");
    CHECK(window.samples == 0, "missing kernel timestamp cannot become a zero-delay sample");
    d2k_nfq_note_packet(&q, id, 0, 1);
    d2k_nfq_note_packet(&q, id + TIMING_SLOTS, 0, 1);
    note_verdict(&q, id, D2K_NF_ACCEPT, 0);
    note_verdict(&q, id + TIMING_SLOTS, D2K_NF_ACCEPT, 1);
    window = d2k_nfq_take_window(&q);
    CHECK(window.userspace_samples == 1 && window.replacements == 1 && window.drops == 0,
          "a reused timing slot must match the full packet ID");
}

int main(void) {
    const int requested = 4 * 1024 * 1024;
    int actual = 0;

    force_allowed = 1;
    forced_calls = normal_calls = 0;
    CHECK(set_rcvbuf(7, requested, &actual) == 0,
          "привилегированный сокет не принял запрошенный буфер");
    CHECK(actual == 2 * requested,
          "успешный SO_RCVBUFFORCE не подтвердился через getsockopt");
    CHECK(forced_calls == 1 && normal_calls == 0,
          "после успешного SO_RCVBUFFORCE вызван ограниченный SO_RCVBUF");

    force_allowed = 0;
    forced_calls = normal_calls = 0;
    CHECK(set_rcvbuf(7, requested, &actual) == 1,
          "ограниченный SO_RCVBUF не помечен как меньше запроса");
    CHECK(actual == 425984,
          "эффективный ограниченный размер не прочитан через getsockopt");
    CHECK(forced_calls == 1 && normal_calls == 1,
          "при отказе force не использован обычный SO_RCVBUF");

    test_error_only_wakeup();
    test_verdict_timing();
    if (fails) return 1;
    puts("NFQUEUE receive-buffer, error-only wakeup and verdict sampling: OK");
    return 0;
}
