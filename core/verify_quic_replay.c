/* verify_quic_replay.c — повтор снятой пачки QUIC клиента под планом.
 *
 * Отдельным файлом, а не в verify.c: функция тянет перезапечатку пачки
 * (quicsnap_reseal.c) и привязку ответа к соединению (quicprobe.c), а verify.o
 * линкуется во многие цели, где этих модулей нет. Нужна только планировщику
 * (sched.c, крючок d2k_sched_quic_replay_ver_hook). */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "d2k_quicprobe.h"
#include "d2k_quicsnap.h"
#include "d2k_verify.h"

static int64_t replay_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

d2k_ver_result d2k_verify_quic_replay_on(int use_fd, const char *ip, uint16_t port,
    const uint8_t *pack, size_t pack_len, int deadline_ms) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;
    snprintf(r.reason, sizeof r.reason, "повтор не начинался");
    d2k_qsnap in, out;
    static __thread uint8_t fresh[D2K_SHAPE_MAX];
    size_t fresh_len = 0;
    if (!pack || !ip || !ip[0] || d2k_qsnap_parse(pack, pack_len, &in) != 0 ||
        d2k_qsnap_recid(&in, fresh, sizeof fresh, &fresh_len) != 0 ||
        d2k_qsnap_parse(fresh, fresh_len, &out) != 0) {
        if (use_fd >= 0) close(use_fd);
        snprintf(r.reason, sizeof r.reason,
                 "нет снятой пачки QUIC клиента — повторять нечего");
        return r;
    }
    r.family = strchr(ip, ':') ? 6 : 4;
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof ss);
    if (r.family == 6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port ? port : 443);
        if (inet_pton(AF_INET6, ip, &a->sin6_addr) != 1) { sl = 0; } else { sl = sizeof *a; }
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(port ? port : 443);
        if (inet_pton(AF_INET, ip, &a->sin_addr) != 1) { sl = 0; } else { sl = sizeof *a; }
    }
    int fd = use_fd >= 0 ? use_fd : socket(r.family == 6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || sl == 0 || connect(fd, (struct sockaddr *)&ss, sl) != 0) {
        if (fd >= 0) close(fd);
        snprintf(r.reason, sizeof r.reason, "нет UDP для повтора пачки клиента");
        return r;
    }
    r.fd = fd;
    struct sockaddr_storage me;
    socklen_t ml = sizeof me;
    if (getsockname(fd, (struct sockaddr *)&me, &ml) == 0) {
        if (me.ss_family == AF_INET6) {
            const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)&me;
            memcpy(r.local_addr, &a->sin6_addr, 16);
            r.local_port = ntohs(a->sin6_port);
        } else {
            const struct sockaddr_in *a = (const struct sockaddr_in *)&me;
            memcpy(r.local_addr, &a->sin_addr, 4);
            memcpy(r.local_ip4, &a->sin_addr, 4);
            r.local_port = ntohs(a->sin_port);
        }
    }
    r.level = D2K_VER_TRANSPORT;
    r.budget = D2K_BUDGET_NOT_APPLICABLE;
    snprintf(r.budget_note, sizeof r.budget_note,
             "повтор пачки QUIC клиента: без его ключей соединение не продолжить");
    /* Весь полёт, как его слал клиент: та же раскладка по датаграммам, один
       свежий DCID на все (иначе сервер увидит обрывки двух соединений). */
    for (size_t i = 0; i < out.n; i++) {
        if (send(fd, out.dg[i], out.len[i], 0) != (ssize_t)out.len[i]) {
            snprintf(r.reason, sizeof r.reason, "датаграмма пачки не ушла: %s", strerror(errno));
            return r;
        }
    }
    int64_t until = replay_now_ms() + (deadline_ms > 0 ? deadline_ms : 3000);
    size_t foreign = 0;
    for (;;) {
        int64_t left = until - replay_now_ms();
        if (left <= 0) break;
        struct pollfd pf = {fd, POLLIN, 0};
        if (poll(&pf, 1, (int)left) <= 0) break;
        uint8_t buf[1600];
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        /* Засчитывается только ответ НАШЕМУ соединению: Initial сервера,
           раскрываемый ключами из нашего DCID и адресованный нашему SCID, или
           Retry с верным тегом (qp_verify_bound). Чужое, VN и мусор —
           не доказательство, что коробка пропустила полёт. */
        if (d2k_quic_verify_bound(buf, (size_t)n, (d2k_hello){fresh, fresh_len, NULL, 0, 0, 0}) == 0) {
            r.level = D2K_VER_HANDSHAKE;
            r.replay_proof = 1;
            snprintf(r.reason, sizeof r.reason,
                     "сервер ответил на повтор пачки QUIC клиента (%zu датаграмм): уровень "
                     "рукопожатия, прикладной не измерен", out.n);
            return r;
        }
        foreign++;
    }
    if (foreign) {
        snprintf(r.reason, sizeof r.reason,
                 "на повтор пачки QUIC клиента пришло %zu датаграмм, ни одна не наша", foreign);
    } else {
        snprintf(r.reason, sizeof r.reason,
                 "на повтор пачки QUIC клиента ответа нет (тишина)");
    }
    return r;
}
