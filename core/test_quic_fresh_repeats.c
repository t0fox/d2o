#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "d2k_quicprobe.h"
#include "d2k_quic.h"
#include "d2k_quichello.h"
#include "d2k_quic_arms.h"
#include "d2k_quicwire.h"
#include "test_quic_vector.h"

#define REPEATS 3
#define PREFIX_COPIES 2
#define PACKETS_PER_REPEAT (PREFIX_COPIES + 1)
#define TOTAL_PACKETS (REPEATS * PACKETS_PER_REPEAT)
#define MAX_PACKET 2048

typedef struct {
    int fd;
    uint8_t packets[REPEATS][MAX_PACKET];
    size_t lengths[REPEATS];
    int received;
} control_receiver;

static void *receive_control_packets(void *arg) {
    control_receiver *r = arg;
    for (int i = 0; i < REPEATS; i++) {
        ssize_t n = recv(r->fd, r->packets[i], sizeof r->packets[i], 0);
        if (n <= 0) break;
        r->lengths[i] = (size_t)n;
        r->received++;
    }
    return NULL;
}

static size_t resolve_no_extra_addrs(const char *sni,
    char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    (void)sni; (void)out; (void)cap;
    return 0;
}

static const uint8_t *find_bytes(const uint8_t *hay, size_t hay_len,
                                 const uint8_t *needle, size_t needle_len) {
    if (needle_len == 0 || needle_len > hay_len) return NULL;
    for (size_t i = 0; i <= hay_len - needle_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) return hay + i;
    }
    return NULL;
}

static int donor_neutral_sni(const char *sni) {
    if (strlen(sni) != 23 || sni[0] != 'z' || strcmp(sni + 11, ".example.com") != 0) {
        return 0;
    }
    for (int i = 1; i <= 10; i++) {
        if (!isxdigit((unsigned char)sni[i])) return 0;
    }
    return 1;
}

typedef int (*neutral_send_fn)(uint16_t port, int *sent);

/* Ships the 3 repeats of one neutral-name question to the local receiver and
   checks the donor neutralName() discipline (probe.go:230): every repeat
   carries its own z<10 hex>.example.com, never a fixed decoy, and its own DCID. */
static int check_neutral_repeats(const char *what, neutral_send_fn send_question) {
    int fails = 0;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        puts("FAIL neutral control socket");
        return 1;
    }
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    struct sockaddr_in addr = {.sin_family = AF_INET};
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        puts("FAIL neutral control bind");
        return 1;
    }
    socklen_t addr_len = sizeof addr;
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        close(fd);
        puts("FAIL neutral control getsockname");
        return 1;
    }

    control_receiver r = {.fd = fd};
    pthread_t thread;
    if (pthread_create(&thread, NULL, receive_control_packets, &r) != 0) {
        close(fd);
        puts("FAIL neutral control receiver thread");
        return 1;
    }

    int old_allow_local = d2k_quic_allow_local;
    uint32_t old_wait_ms = d2k_quic_wait_ms;
    d2k_quic_resolve_fn old_resolve = d2k_quic_resolve_hook;
    d2k_quic_allow_local = 1;
    d2k_quic_wait_ms = 30;
    d2k_quic_resolve_hook = resolve_no_extra_addrs;
    int sent = 0;
    int built = send_question(ntohs(addr.sin_port), &sent);
    d2k_quic_resolve_hook = old_resolve;
    d2k_quic_wait_ms = old_wait_ms;
    d2k_quic_allow_local = old_allow_local;

    (void)pthread_join(thread, NULL);
    close(fd);
    if (built != 0 || sent != REPEATS || r.received != REPEATS) {
        printf("FAIL %s built=%d sent=%d received=%d of %d\n", what, built, sent,
               r.received, REPEATS);
        return 1;
    }

    char seen_sni[REPEATS][256] = {{0}};
    uint8_t seen_dcid[REPEATS][20]; /* RFC 9000 permits CID lengths up to 20. */
    size_t seen_dcid_len[REPEATS] = {0};
    for (int i = 0; i < REPEATS; i++) {
        uint8_t hello[1024];
        size_t hello_len = 0;
        d2k_qw_hdr hdr;
        if (d2k_quic_sni(r.packets[i], r.lengths[i], seen_sni[i], sizeof seen_sni[i]) != 0 ||
            !donor_neutral_sni(seen_sni[i])) {
            printf("FAIL control repeat %d lacks donor neutral SNI\n", i);
            fails++;
            continue;
        }
        if (d2k_qw_hdr_parse(r.packets[i], r.lengths[i], 0, &hdr) != 0 ||
            hdr.dcid_len > sizeof seen_dcid[i]) {
            printf("FAIL control repeat %d QUIC header\n", i);
            fails++;
            continue;
        }
        memcpy(seen_dcid[i], r.packets[i] + hdr.dcid_off, hdr.dcid_len);
        seen_dcid_len[i] = hdr.dcid_len;
        if (d2k_quic_client_hello(r.packets[i], r.lengths[i], hello,
                                  sizeof hello, &hello_len) != 0 || hello_len == 0) {
            printf("FAIL control repeat %d ClientHello\n", i);
            fails++;
            continue;
        }
        const uint8_t *sni_at = find_bytes(hello, hello_len,
            (const uint8_t *)seen_sni[i], strlen(seen_sni[i]));
        if (!sni_at) {
            printf("FAIL control repeat %d SNI bytes not in ClientHello\n", i);
            fails++;
        }
    }
    for (int i = 0; i < REPEATS; i++) {
        for (int j = i + 1; j < REPEATS; j++) {
            if (strcmp(seen_sni[i], seen_sni[j]) == 0) {
                printf("FAIL control repeats %d and %d reused neutral SNI\n", i, j);
                fails++;
            }
            if (seen_dcid_len[i] == seen_dcid_len[j] &&
                memcmp(seen_dcid[i], seen_dcid[j], seen_dcid_len[i]) == 0) {
                printf("FAIL control repeats %d and %d reused QUIC DCID\n", i, j);
                fails++;
            }
        }
    }
    if (fails) {
        printf("FAIL %s freshness: %d\n", what, fails);
        return 1;
    }
    printf("fresh neutral QUIC %s repeats: passed\n", what);
    return 0;
}

static int send_control_hook(uint16_t port, int *sent) {
    static const char profile_sni[] = "c0000000000.example.com";
    uint8_t control_bytes[MAX_PACKET];
    size_t control_len = 0;
    if (d2k_quic_hello_rename(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                              profile_sni, control_bytes, sizeof control_bytes,
                              &control_len) != 0) {
        return -1;
    }
    d2k_hello control = {control_bytes, control_len, NULL, 0, 0, 0};
    (void)d2k_quic_ask_control_hook("127.0.0.1", port, NULL, 0, control, 30, 0,
                                    REPEATS, NULL, NULL, sent, NULL);
    return 0;
}

/* Fragment survival (donor arms.go:204-205): buildInitial(neutralName(), ...)
   inside the per-attempt closure, so each repeat has a fresh neutral name --
   never the scheduler decoy (sched.c SCHED_DECOY "disk.rzd.ru") or the
   control snapshot's name. The caller passes NO name (NULL) for the control
   question; the wire layer draws the names. The raw-IP fragment send needs
   CAP_NET_RAW/Linux, so this loopback case asks the same control question
   unfragmented: the name is chosen before the send path is. */
static int send_survival_control(uint16_t port, int *sent) {
    d2k_quic_arm_question q = {.addr = "127.0.0.1", .control = 1};
    (void)d2k_quic_ask_arm_hook(&q, NULL, port, 30, 0, sent);
    return 0;
}

static int test_neutral_control_is_fresh_per_attempt(void) {
    int fails = 0;
    fails += check_neutral_repeats("control", send_control_hook);
    fails += check_neutral_repeats("fragment survival control", send_survival_control);
    return fails;
}

typedef struct {
    int fd;
    uint8_t packets[TOTAL_PACKETS][MAX_PACKET];
    size_t lengths[TOTAL_PACKETS];
    int received;
} receiver;

static void *receive_packets(void *arg) {
    receiver *r = arg;
    for (int i = 0; i < TOTAL_PACKETS; i++) {
        ssize_t n = recv(r->fd, r->packets[i], sizeof r->packets[i], 0);
        if (n <= 0) break;
        r->lengths[i] = (size_t)n;
        r->received++;
    }
    return NULL;
}

int main(void) {
    int fails = 0;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    struct sockaddr_in addr = {.sin_family = AF_INET};
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        close(fd);
        return 1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        perror("bind");
        close(fd);
        return 1;
    }
    socklen_t addr_len = sizeof addr;
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        perror("getsockname");
        close(fd);
        return 1;
    }

    receiver r = {.fd = fd};
    pthread_t thread;
    if (pthread_create(&thread, NULL, receive_packets, &r) != 0) {
        perror("pthread_create");
        close(fd);
        return 1;
    }

    d2k_quic_allow_local = 1;
    static const uint8_t decoy[] = {0xFA, 0xCE};
    d2k_quic_arm_question question = {
        .addr = "127.0.0.1", .blob = decoy, .blob_len = sizeof decoy,
        .copies = PREFIX_COPIES
    };
    int sent = 0;
    d2k_tally tally = d2k_quic_ask_arm_hook(&question, "fresh.example",
        ntohs(addr.sin_port), 50, 0, &sent);

    (void)pthread_join(thread, NULL);
    close(fd);

    if (r.received != TOTAL_PACKETS || sent != REPEATS || tally.fail != REPEATS) {
        printf("FAIL repeats sent=%d received=%d unanswered=%d\n", sent, r.received,
               tally.fail);
        fails++;
    }

    uint8_t hellos[REPEATS][1024];
    size_t hello_lens[REPEATS] = {0};
    char sni[256];
    for (int attempt = 0; attempt < REPEATS; attempt++) {
        int base = attempt * PACKETS_PER_REPEAT;
        for (int copy = 0; copy < PREFIX_COPIES; copy++) {
            if (r.lengths[base + copy] != sizeof decoy ||
                memcmp(r.packets[base + copy], decoy, sizeof decoy) != 0) {
                printf("FAIL repeat %d lost decoy packet %d\n", attempt, copy);
                fails++;
            }
        }
        int initial = base + PREFIX_COPIES;
        if (d2k_quic_client_hello(r.packets[initial], r.lengths[initial],
                                  hellos[attempt], sizeof hellos[attempt], &hello_lens[attempt]) != 0 ||
            d2k_quic_sni(r.packets[initial], r.lengths[initial], sni, sizeof sni) != 0 ||
            strcmp(sni, "fresh.example") != 0) {
            printf("FAIL repeat %d did not carry a valid fresh.example Initial\n", attempt);
            fails++;
        }
    }
    if (r.received == TOTAL_PACKETS) {
        for (int i = 0; i < REPEATS; i++) {
            for (int j = i + 1; j < REPEATS; j++) {
                if (hello_lens[i] == hello_lens[j] &&
                    memcmp(hellos[i], hellos[j], hello_lens[i]) == 0) {
                    printf("FAIL repeats %d and %d reused the same ClientHello\n", i, j);
                    fails++;
                }
            }
        }
    }

    if (test_neutral_control_is_fresh_per_attempt() != 0) fails++;
    if (fails) return 1;
    puts("fresh QUIC arm repeats: passed");
    return 0;
}
