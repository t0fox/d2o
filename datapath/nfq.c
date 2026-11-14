/* nfq.c — системные вызовы вокруг очереди. Только Linux.
 *
 * Отличие от замерщика этапа 0: настройка очереди идёт с NLM_F_ACK и ответ
 * ЧИТАЕТСЯ. Замерщик на Go молча копил пакеты, потому что посылал неверный тип
 * атрибута, получал EINVAL и не смотрел на него. «Отправили» и «ядро приняло»
 * — разные события, и различать их обязательно.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <poll.h>
#include <time.h>

#include "d2k_nfq.h"
#include "d2k_nl.h"

enum { TIMING_SLOTS = 128 };
typedef struct {
    uint32_t id;
    uint64_t kernel_ns, read_ns;
} packet_time;

struct d2k_nfq {
    int      fd;
    uint16_t queue;
    uint32_t seq;
    uint64_t lost;
    d2k_nfq_window window;
    int timing;
    packet_time packet_times[TIMING_SLOTS];
};

static void say(char *err, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void say(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

static int nl_write(int fd, const uint8_t *msg, size_t len) {
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    for (;;) {
        ssize_t n = sendto(fd, msg, len, 0, (struct sockaddr *)&sa, sizeof sa);
        if (n >= 0) {
            return (size_t)n == len ? 0 : -1;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
}

/* Ждёт подтверждения на запрос с NLM_F_ACK.
 * 0 — ядро приняло, -1 — отвергло либо ответа нет. */
static int await_ack(int fd, uint32_t seq, char *err, size_t errcap) {
    uint8_t buf[4096];
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;

    for (int tries = 0; tries < 8; tries++) {
        int pr = poll(&pfd, 1, 1000);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            say(err, errcap, "poll при ожидании подтверждения: %s", strerror(errno));
            return -1;
        }
        if (pr == 0) {
            say(err, errcap, "ядро не подтвердило настройку очереди за секунду");
            return -1;
        }
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            say(err, errcap, "recv при ожидании подтверждения: %s", strerror(errno));
            return -1;
        }

        d2k_nl_iter it;
        d2k_nl_msg m;
        d2k_nl_iter_init(&it, buf, (size_t)n);
        while (d2k_nl_next(&it, &m)) {
            int32_t e = 0;
            if (d2k_nl_errno(&m, &e) != 0) {
                continue;   /* не наш ответ — ждём дальше */
            }
            if (m.seq != seq) {
                continue;
            }
            if (e == 0) {
                return 0;
            }
            say(err, errcap, "ядро отвергло настройку очереди: %s", strerror(-e));
            return -1;
        }
    }
    say(err, errcap, "подтверждение настройки очереди не пришло");
    return -1;
}

static int send_and_ack(d2k_nfq *q, const uint8_t *msg, size_t len, uint32_t seq,
                        char *err, size_t errcap) {
    if (len == 0) {
        say(err, errcap, "сообщение настройки не собралось");
        return -1;
    }
    if (nl_write(q->fd, msg, len) != 0) {
        say(err, errcap, "отправка настройки: %s", strerror(errno));
        return -1;
    }
    return await_ack(q->fd, seq, err, errcap);
}

/* SO_RCVBUF is silently capped by net.core.rmem_max. The datapath requests a
   multi-megabyte queue, so use the privileged override when available and
   report the effective value instead of assuming the request was honored. */
static int set_rcvbuf(int fd, int requested, int *effective) {
    int v = requested;
    int rc = -1;
#ifdef SO_RCVBUFFORCE
    rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &v, sizeof v);
#endif
    if (rc != 0 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v) != 0) {
        return -1;
    }

    socklen_t len = sizeof v;
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, &len) != 0) {
        return -1;
    }
    if (effective) {
        *effective = v;
    }
    return v >= requested ? 0 : 1;
}

d2k_nfq *d2k_nfq_open(const d2k_nfq_cfg *cfg, char *err, size_t errcap) {
    if (!cfg) {
        say(err, errcap, "нет настроек очереди");
        return NULL;
    }
    d2k_nfq *q = calloc(1, sizeof *q);
    if (!q) {
        say(err, errcap, "нет памяти");
        return NULL;
    }
    q->queue = cfg->queue;
    q->seq = 1;

    q->fd = socket(AF_NETLINK, SOCK_RAW, D2K_NETLINK_NETFILTER);
    if (q->fd < 0) {
        say(err, errcap, "socket(NETLINK_NETFILTER): %s", strerror(errno));
        free(q);
        return NULL;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    /* nl_pid = 0: адрес назначает ядро. Свой номер выбирать нельзя — на
       роутере рядом живёт nfqws соседнего продукта, и совпадение адреса
       развело бы два процесса по одному сокету. */
    if (bind(q->fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        say(err, errcap, "bind netlink: %s", strerror(errno));
        close(q->fd);
        free(q);
        return NULL;
    }

    if (cfg->rcvbuf > 0) {
        int effective = 0;
        int rc = set_rcvbuf(q->fd, cfg->rcvbuf, &effective);
        /* Невозможность увеличить буфер не выключает очередь: fail-open
           сохраняет трафик. Но скрытый лимит должен быть виден в журнале. */
        if (rc < 0) {
            fprintf(stderr, "d2kd: не удалось настроить SO_RCVBUF NFQUEUE: %s\n",
                    strerror(errno));
        } else if (rc > 0) {
            fprintf(stderr,
                    "d2kd: SO_RCVBUF NFQUEUE ограничен: запрос %d, ядро установило %d\n",
                    cfg->rcvbuf, effective);
        }
    }

    uint8_t msg[256];
    uint32_t seq;
    size_t n;

    /* PF_BIND намеренно не посылается: с ядра 3.8 команда — пустышка, а
       целевое ядро 4.9. Замерщик этапа 0 обходился без неё на настоящем
       устройстве. */

    seq = q->seq++;
    n = d2k_nl_cfg_cmd(msg, sizeof msg, cfg->queue, seq,
                       D2K_NFQNL_CFG_CMD_BIND, AF_INET);
    if (send_and_ack(q, msg, n, seq, err, errcap) != 0) {
        close(q->fd);
        free(q);
        return NULL;
    }

    uint32_t flags = cfg->fail_open ? D2K_NFQA_CFG_F_FAIL_OPEN : 0;
    /* Маска перечисляет флаги, которыми мы вообще распоряжаемся. GSO указан в
       маске и НЕ указан в значении: он должен быть выключен явно. С GSO ядро
       отдаёт склеенный суперпакет, а это не то, что уйдёт на провод, — резать
       его по границам сегментов мы не умеем и делать вид не будем. */
    uint32_t mask = D2K_NFQA_CFG_F_FAIL_OPEN | D2K_NFQA_CFG_F_GSO;

    seq = q->seq++;
    n = d2k_nl_cfg_params(msg, sizeof msg, cfg->queue, seq,
                          cfg->copy_range, D2K_NFQNL_COPY_PACKET,
                          cfg->maxlen, flags, mask);
    if (send_and_ack(q, msg, n, seq, err, errcap) != 0) {
        close(q->fd);
        free(q);
        return NULL;
    }

    return q;
}

void d2k_nfq_close(d2k_nfq *q) {
    if (!q) {
        return;
    }
    if (q->fd >= 0) {
        uint8_t msg[256];
        size_t n = d2k_nl_cfg_cmd(msg, sizeof msg, q->queue, q->seq++,
                                  D2K_NFQNL_CFG_CMD_UNBIND, AF_INET);
        /* Ответ не ждём: мы закрываемся, и закрытие сокета отвяжет очередь в
           любом случае. Отвязка послана из вежливости к ядру. */
        if (n) {
            (void)nl_write(q->fd, msg, n);
        }
        close(q->fd);
    }
    free(q);
}

int d2k_nfq_fd(const d2k_nfq *q) {
    return q ? q->fd : -1;
}

uint32_t d2k_nfq_port(const d2k_nfq *q) {
    struct sockaddr_nl addr;
    socklen_t len = sizeof(addr);
    return getsockname(q->fd, (struct sockaddr *)&addr, &len) == 0 &&
           len == sizeof(addr) && addr.nl_family == AF_NETLINK ? addr.nl_pid : 0;
}

void d2k_nfq_timing(d2k_nfq *q, int enabled) {
    if (q->timing == enabled) return;
    q->timing = enabled;
    memset(q->packet_times, 0, sizeof(q->packet_times));
    q->window = (d2k_nfq_window){0};
}

void d2k_nfq_note_packet(d2k_nfq *q, uint32_t id, uint64_t kernel_ns, uint64_t read_ns) {
    if (!q->timing) return;
    q->packet_times[id % TIMING_SLOTS] = (packet_time){id, kernel_ns, read_ns};
}

d2k_nfq_window d2k_nfq_take_window(d2k_nfq *q) {
    d2k_nfq_window window = q->window;
    q->window = (d2k_nfq_window){0};
    return window;
}

static void note_verdict(d2k_nfq *q, uint32_t id, uint32_t verdict, int replaced) {
    if (!q->timing) return;
    if (verdict == D2K_NF_DROP) q->window.drops++;
    if (replaced) q->window.replacements++;
    packet_time *slot = &q->packet_times[id % TIMING_SLOTS];
    if (slot->id == id && slot->read_ns) {
        struct timespec ts;
        uint64_t kernel_ns = slot->kernel_ns, read_ns = slot->read_ns;
        slot->read_ns = 0;
        const uint64_t second = UINT64_C(1000000000);
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            uint64_t now = (uint64_t)ts.tv_sec * second + (uint64_t)ts.tv_nsec;
            if (now >= read_ns) {
                uint64_t us = (now - read_ns) / 1000;
                q->window.userspace_samples++;
                if (us > q->window.userspace_max_us) q->window.userspace_max_us = us;
            }
        }
        if (kernel_ns && clock_gettime(CLOCK_REALTIME, &ts) == 0 && ts.tv_sec >= 0) {
            uint64_t now = (uint64_t)ts.tv_sec * second + (uint64_t)ts.tv_nsec;
            /* Reject missing, future and clock-step outliers. */
            if (now >= kernel_ns && now - kernel_ns <= 60 * second) {
                uint64_t us = (now - kernel_ns) / 1000;
                q->window.samples++;
                if (us > q->window.max_us) q->window.max_us = us;
                return;
            }
        }
    }
    q->window.no_timestamp++;
}

ssize_t d2k_nfq_recv(d2k_nfq *q, uint8_t *buf, size_t cap, char *err, size_t errcap) {
    if (!q || !buf || cap == 0) {
        say(err, errcap, "нет буфера для чтения");
        return -1;
    }
    ssize_t n = recv(q->fd, buf, cap, MSG_DONTWAIT);
    if (n >= 0) {
        return n;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return 0;
    }
    if (errno == ENOBUFS) {
        /* Ядро не успело отдать — сообщения потеряны. Сокет жив, читать
           дальше можно, но часть трафика мы не видели. */
        q->lost++;
        return -2;
    }
    say(err, errcap, "recv из очереди: %s", strerror(errno));
    return -1;
}

int d2k_nfq_verdict(d2k_nfq *q, uint32_t pkt_id, uint32_t verdict,
                    char *err, size_t errcap) {
    if (!q) {
        return -1;
    }
    uint8_t msg[64];
    size_t n = d2k_nl_verdict(msg, sizeof msg, q->queue, q->seq++, pkt_id, verdict);
    if (n == 0) {
        say(err, errcap, "вердикт не собрался");
        return -1;
    }
    if (nl_write(q->fd, msg, n) != 0) {
        say(err, errcap, "отправка вердикта: %s", strerror(errno));
        return -1;
    }
    note_verdict(q, pkt_id, verdict, 0);
    return 0;
}

int d2k_nfq_verdict_payload(d2k_nfq *q, uint32_t pkt_id, uint32_t verdict,
                            const uint8_t *payload, size_t len, char *err, size_t errcap) {
    if (!q) {
        return -1;
    }
    uint8_t msg[64 + 2048];
    size_t n = d2k_nl_verdict_payload(msg, sizeof msg, q->queue, q->seq++, pkt_id, verdict,
                                      payload, len);
    if (n == 0) {
        say(err, errcap, "вердикт с заменой не собрался");
        return -1;
    }
    if (nl_write(q->fd, msg, n) != 0) {
        say(err, errcap, "отправка вердикта с заменой: %s", strerror(errno));
        return -1;
    }
    note_verdict(q, pkt_id, verdict, 1);
    return 0;
}

uint64_t d2k_nfq_lost(const d2k_nfq *q) {
    return q ? q->lost : 0;
}
