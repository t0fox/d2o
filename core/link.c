/* link.c — связь с датапатом по управляющему сокету (см. d2k_link.h).
 *
 * Клиентская сторона AF_UNIX-сокета, который слушает датапат (d2k_ctl.h,
 * datapath/ctl.c). Кадр читается по длине, поля — побайтно, тем же приёмом,
 * что put_key в datapath/ctlsrv.c: наложение структуры на буфер здесь
 * запрещено по той же причине (выравнивание, дыра, непереносимость на
 * MIPS/ARM).
 *
 * Один статический буфер на приём И на отправку, не два и не на стеке:
 *   - не на стеке — 64 КБ (D2K_CTL_FRAME_MAX) на стеке трогать незачем на
 *     mipsel-роутере, где размер стека потока не гарантирован щедрым;
 *   - один на оба направления — модуль обслуживает РОВНО ОДНО подключение в
 *     ОДНОМ потоке (тот же инвариант, что и у самого датапата: "датапат
 *     обслуживает одного хозяина, а не является сервером общего
 *     пользования", d2k_ctl.h), поэтому приём и отправка никогда не идут
 *     параллельно, и делить память незачем.
 * Не реентерабельно относительно другого потока ОС — не для этого протокола
 * писалось. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "d2k_link.h"
/* Единственный источник D2K_KEY_WIRE_LEN — см. большой комментарий у него в
 * datapath/include/d2k_ctlsrv.h про то, почему это не sizeof(d2k_key) и не
 * литерал. Заголовок тянет за собой d2k_raw.h/d2k_session.h/d2k_plan.h/
 * d2k_plans.h транзитивно, но отсюда не зовётся ни одна их функция —
 * используется только сам #define, поэтому лишней линковки с датапатом не
 * образуется (компилируется декларация, не вызывается символ). */
#include "d2k_ctlsrv.h"

#define HDR 6u /* [длина u32 BE][тип u16 BE] — как в datapath/ctl.c */

static uint8_t g_scratch[D2K_CTL_FRAME_MAX + HDR];

/* Absence is unknown, a truncated extension is malformed. This context is
 * still cannot by itself establish live/application success. */
static int execution_context(d2k_ev *out, const uint8_t *p, size_t n) {
    if (!n) return 0;
    if (n != D2K_CTL_EXECUTION_LEN ||
        d2k_ctl_binding_read(&out->execution_binding,p+8,D2K_CTL_BINDING_LEN)) return -1;
    for (unsigned b=0;b<8;b++) out->execution_id=(out->execution_id<<8)|p[b];
    return 0;
}

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

/* Ждёт данные на fd не дольше ms миллисекунд — та же семантика, что у
 * poll(2): отрицательное ms — ждать неограниченно, 0 — не ждать вовсе.
 * Возвращает 0 (таймаут), >0 (есть что читать) или -1 (ошибка, причина в
 * err). */
static int wait_readable(int fd, int ms, char *err, size_t errcap) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    for (;;) {
        pfd.revents = 0;
        int pr = poll(&pfd, 1, ms);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            say(err, errcap, "poll: %s", strerror(errno));
            return -1;
        }
        return pr;
    }
}

/* Дочитывает РОВНО n байт или отказывает. Once начатое чтение кадра не
 * ограничено wait_ms заново (см. d2k_link_next в d2k_link.h про то, почему):
 * на локальном сокете между двумя нашими же процессами кадр, начавший
 * приходить и не дописанный, — это порванное соединение, а не тайм-аут. */
static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR) {
            continue;
        }
        return -1; /* 0 — собеседник закрылся; <0 — ошибка сокета */
    }
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t n) {
    /* A disconnected local daemon is an I/O error, not permission to kill
       its caller with SIGPIPE. Do not change process-wide signal policy. */
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#elif defined(SO_NOSIGPIPE)
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one) != 0) { return -1; }
#endif
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(fd, buf + sent, n - sent, flags);
        if (w > 0) {
            sent += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/* Разбирает hex в out (не более outcap байт). Нечётная длина — забота
 * вызывающего (проверяется отдельно, чтобы дать её причину в err точнее, чем
 * общее "недопустимый символ"). Возвращает число разобранных байт, или -1,
 * если встретился недопустимый символ либо байт не поместился в outcap. */
static long hex_decode(const char *hex, uint8_t *out, size_t outcap) {
    size_t n = 0;
    while (hex[0] && hex[1]) {
        int hi = hex_nibble((unsigned char)hex[0]);
        int lo = hex_nibble((unsigned char)hex[1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        if (n >= outcap) {
            return -1;
        }
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return (long)n;
}

int d2k_link_open(const char *sock_path, char *err, size_t errcap) {
    if (!sock_path || !*sock_path) {
        say(err, errcap, "путь управляющего сокета пуст");
        return -1;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof sa.sun_path) {
        say(err, errcap, "путь сокета длиннее %zu байт", sizeof sa.sun_path - 1);
        return -1;
    }
    strcpy(sa.sun_path, sock_path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        say(err, errcap, "socket(AF_UNIX): %s", strerror(errno));
        return -1;
    }
    /* AF_UNIX: connect() ставится в очередь listen()'а сразу, ответа
     * accept() на другой стороне не ждёт — гонки со стендом, который ещё не
     * дошёл до цикла с accept(), здесь нет (см. комментарий в d2k_link.h). */
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        say(err, errcap, "connect %s: %s", sock_path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

void d2k_link_close(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

int d2k_link_peer_closed(int fd) {
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int pr;
    do {
        pr = poll(&pfd, 1, 0);
    } while (pr < 0 && errno == EINTR);
    if (pr < 0) {
        return -1;
    }
    if (pr == 0) {
        return 0;
    }
    if (pfd.revents & POLLNVAL) {
        errno = EBADF;
        return -1;
    }
    return (pfd.revents & (POLLHUP | POLLERR)) ? 1 : 0;
}

int d2k_link_next(int fd, d2k_ev *out, int wait_ms, char *err, size_t errcap) {
    if (!out) {
        say(err, errcap, "нет места для события");
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (fd < 0) {
        say(err, errcap, "сокет не открыт");
        return -1;
    }

    int pr = wait_readable(fd, wait_ms, err, errcap);
    if (pr < 0) {
        return -1;
    }
    if (pr == 0) {
        return 1; /* тайм-аут: событие — сообщение, а не обязательство */
    }

    uint8_t hdr[HDR];
    if (read_exact(fd, hdr, sizeof hdr) != 0) {
        say(err, errcap, "заголовок кадра не дочитался: соединение закрылось");
        return -1;
    }
    uint32_t plen = (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 |
                    (uint32_t)hdr[2] << 8 | hdr[3];
    uint16_t type = (uint16_t)((uint16_t)hdr[4] << 8 | hdr[5]);
    if (plen < 2 || plen > (uint32_t)D2K_CTL_FRAME_MAX) {
        say(err, errcap, "кадр с невозможной длиной %u", (unsigned)plen);
        return -1;
    }
    size_t body_len = (size_t)plen - 2;
    if (read_exact(fd, g_scratch, body_len) != 0) {
        say(err, errcap, "тело кадра не дочиталось целиком: соединение закрылось");
        return -1;
    }
    if (body_len < D2K_KEY_WIRE_LEN) {
        say(err, errcap, "кадр короче ключа потока (%zu байт)", body_len);
        return -1;
    }

    out->kind = type;
    if (g_scratch[0] != 4 && g_scratch[0] != 6) {
        say(err, errcap, "неизвестное семейство ключа потока: %u", g_scratch[0]);
        return -1;
    }
    out->family = g_scratch[0];
    if (out->family == 4) {
        for (size_t i = 4; i < 16; ++i) {
            if (g_scratch[1 + i] || g_scratch[17 + i]) {
                say(err, errcap, "ненулевой хвост IPv4-адреса в ключе потока");
                return -1;
            }
        }
    }
    memcpy(out->low_ip, g_scratch + 1, 16);
    memcpy(out->high_ip, g_scratch + 17, 16);
    out->low_port = (uint16_t)((uint16_t)g_scratch[33] << 8 | g_scratch[34]);
    out->high_port = (uint16_t)((uint16_t)g_scratch[35] << 8 | g_scratch[36]);
    out->transport = g_scratch[37];

    const uint8_t *rest = g_scratch + D2K_KEY_WIRE_LEN;
    size_t rlen = body_len - D2K_KEY_WIRE_LEN;

    switch (type) {
    case D2K_EV_HELLO:
        if (rlen < 1) {
            say(err, errcap, "приветствие без длины имени");
            return -1;
        }
        {
            /* namelen — один байт, поэтому не больше 255, а name[256] с
               запасом на NUL хватает без дополнительной проверки границы. */
            size_t nl = rest[0];
            if (rlen < 1 + nl) {
                say(err, errcap, "имя короче объявленной длины");
                return -1;
            }
            memcpy(out->name, rest + 1, nl);
            out->name[nl] = '\0';
        }
        break;
    case D2K_EV_HTTP_RESPONSE:
    case D2K_EV_HTTP_PORTAL:
        if(out->kind==D2K_EV_HTTP_RESPONSE) {
            if(rlen<18)return -1;
            rlen-=18;const uint8_t *meta=rest+rlen;
            out->live_http_status=(uint16_t)((unsigned)meta[0]<<8|meta[1]);
            for(unsigned i=0;i<8;i++) {
                out->live_body_bytes=(out->live_body_bytes<<8)|meta[2+i];
                out->live_request_no=(out->live_request_no<<8)|meta[10+i];
            }
            if(!out->live_request_no || rest[0]<1 || rest[0]>4 || out->live_http_status>599 ||
               (rest[0]==1 && out->live_http_status<200))return -1;
        }
        if (rlen < 2 || rlen < 2u + rest[1]) {
            say(err, errcap, "вставка HTTP без признака или с обрезанным именем");
            return -1;
        }
        out->code = rest[0];
        memcpy(out->name, rest + 2, rest[1]);
        out->name[rest[1]] = '\0';
        {
            size_t off = 2u + rest[1];
            if(out->kind==D2K_EV_HTTP_RESPONSE && rlen<off+50+D2K_CTL_BINDING_LEN)return -1;
            if (rlen != off && rlen < off + 50) {
                say(err, errcap, "вставка HTTP с обрезанным контекстом исполнения");
                return -1;
            }
            if (rlen >= off + 50) {
                size_t path_len = (size_t)rest[off + 48] << 8 | rest[off + 49];
                if(out->kind==D2K_EV_HTTP_RESPONSE && rlen!=off+50+path_len+D2K_CTL_BINDING_LEN)return -1;
                if (path_len >= sizeof out->live_http_path || (rlen != off + 50 + path_len && rlen != off + 50 + path_len + D2K_CTL_BINDING_LEN)) {
                    say(err, errcap, "вставка HTTP с обрезанным контекстом запроса");
                    return -1;
                }
                for (size_t i = 0; i < 8; i++)
                    out->live_execution = (out->live_execution << 8) | rest[off + i];
                memcpy(out->plan_id, rest + off + 8, 16);
                memcpy(out->trial_id, rest + off + 24, 16);
                for (size_t i = 0; i < 8; i++)
                    out->live_request_ms = (out->live_request_ms << 8) | rest[off + 40 + i];
                memcpy(out->live_http_path, rest + off + 50, path_len);
                out->live_http_path[path_len] = '\0';
                if(rlen==off+50+path_len+D2K_CTL_BINDING_LEN &&
                   d2k_ctl_binding_read(&out->execution_binding,rest+off+50+path_len,D2K_CTL_BINDING_LEN))return -1;
            }
        }
        break;
    case D2K_EV_SUSPECT:
        if (rlen < 1) {
            say(err, errcap, "подозрение без кода причины");
            return -1;
        }
        out->code = rest[0];
        /* Подробности необязательны по длине, но датапат их шлёт всегда
           (ctlsrv.c, D2K_JRN_SUSPECT: код плюс пять байт). Проверяем длину, а
           не предполагаем её: событие без подробностей — законный вход
           (старый датапат), и терять из-за него весь разбор нельзя. */
        if (rlen >= 6) {
            out->ttl = rest[1];
            out->ref_ttl = rest[2];
            out->tos = rest[3];
            out->ipid = (uint16_t)((uint16_t)rest[4] << 8 | rest[5]);
        }
        if (rlen >= 7) {
            /* Применялся ли план к этому потоку. Отсутствие байта — «не
               сказано», и менять по нему смысл подозрения нельзя. */
            out->planned = rest[6];
        }
        if (rlen >= 8) out->client_shape = rest[7];
        /* v12: число при записи, u16 BE (D2K_SUSPECT_TCP_STALL — оценка
           пакетов с данными). Нет байт — ноль, «не сказано». */
        if (rlen >= 10) out->num = (uint32_t)rest[8] << 8 | rest[9];
        break;
    case D2K_EV_STATS:
        /* Счётчики необязательны по длине: старый датапат их не слал вовсе, и
           терять из-за этого разбор события нельзя. */
        if (rlen >= 8) {
            out->dropped = (uint32_t)rest[0] << 24 | (uint32_t)rest[1] << 16 |
                           (uint32_t)rest[2] << 8  | rest[3];
            out->sent    = (uint32_t)rest[4] << 24 | (uint32_t)rest[5] << 16 |
                           (uint32_t)rest[6] << 8  | rest[7];
        }
        break;
    case D2K_EV_EXCHANGE:
        if (rlen < 6) {
            say(err, errcap, "обмен короче типа записи и длины");
            return -1;
        }
        out->code = rest[0]; /* тип ПЕРВОЙ TLS-записи — липкое поле, НЕ порог успеха (см. d2k_link.h) */
        out->seen_types = rest[1]; /* маска встреченных типов — вход d2k_ev_outer_appdata */
        out->num = (uint32_t)rest[2] << 24 | (uint32_t)rest[3] << 16 |
                   (uint32_t)rest[4] << 8 | rest[5];
        /* ПРИЁМКА ВОПРОСА. Байт необязателен по длине — тем же приёмом, что
           идентификатор плана и счётчики выше: старый датапат его не слал, и
           терять из-за этого разбор события нельзя. Нет байта — ноль, то есть
           «сервер не отвечал ServerHello», и это честный ответ: приёмка
           требует ДОКАЗАТЕЛЬСТВА, а не отсутствия опровержения. */
        if (rlen >= 7) {
            out->server_hello = rest[6];
        }
        /* ПРИМЕНЯЛСЯ ЛИ ПЛАН К ЭТОМУ ОБМЕНУ — тем же опциональным приёмом,
           что server_hello: нет байта — ноль (D2K_LINK_PLANNED_UNKNOWN), и
           гашения замера по неизвестному обмену не будет. */
        if (rlen >= 8) {
            out->planned = rest[7];
        }
        break;
    case D2K_EV_CLIENT_TCP:
        /* Набор опций TCP клиента перед его SHAPE (замысел 2026-10-23,
           п. 5.1). Нулевая длина — известный пустой набор; длиннее заголовка
           TCP не бывает — отказ, а не усечение. */
        if (rlen > sizeof out->tcp_options) {
            say(err, errcap, "набор опций TCP клиента длиннее 40 байт (%zu)", rlen);
            return -1;
        }
        memcpy(out->tcp_options, rest, rlen);
        out->tcp_options_len = rlen;
        break;
    case D2K_EV_SHAPE:
        if (rlen > sizeof out->shape) {
            say(err, errcap, "форма приветствия длиннее буфера (%zu байт)", rlen);
            return -1;
        }
        memcpy(out->shape, rest, rlen);
        out->shape_len = rlen;
        break;
    case D2K_EV_ACK:
        if (rlen < 4) {
            say(err, errcap, "подтверждение короче типа команды, признака успеха и причины");
            return -1;
        }
        out->code = (uint16_t)((uint16_t)rest[0] << 8 | rest[1]);
        out->num = (uint32_t)rest[2] << 8 | rest[3]; /* (ok<<8)|reason, см. d2k_link.h */
        if (rlen >= 4 + D2K_TRIAL_ID_LEN) {
            memcpy(out->trial_id, rest + 4, D2K_TRIAL_ID_LEN);
        }
        if(out->code==D2K_CMD_SET_NAME_BOUND &&
           (rlen!=4+D2K_TRIAL_ID_LEN+D2K_CTL_BINDING_LEN ||
            d2k_ctl_binding_read(&out->execution_binding,rest+4+D2K_TRIAL_ID_LEN,D2K_CTL_BINDING_LEN))) return -1;
        break;
    case D2K_EV_APPLIED:
        /* Новый код подтверждения исполнения требует полный ID. Старый
           PREPARED (0x0003) — отдельное событие, не доказательство. */
        if (rlen < D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN) {
            say(err, errcap, "исполнение без полного Plan ID/trial ID");
            return -1;
        }
        memcpy(out->plan_id, rest, D2K_PLAN_ID_LEN);
        if (rlen >= D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN) {
            memcpy(out->trial_id, rest + D2K_PLAN_ID_LEN, D2K_TRIAL_ID_LEN);
        }
        if (execution_context(out, rest + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN,
                              rlen - D2K_PLAN_ID_LEN - D2K_TRIAL_ID_LEN)) {
            say(err, errcap, "повреждён контекст исполнения APPLIED");
            return -1;
        }
        break;
    case D2K_EV_PROTO:
        if (rlen > 6) {
            unsigned len = rest[6];
            if (!len || len > 64 || rlen != 7u + len) { return -1; }
            for (unsigned i = 0; i < len; i++) {
                unsigned char c = rest[7+i];
                int alnum = (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9');
                if (!alnum && !(i && (c=='.'||c=='_'||c=='-'))) { return -1; }
            }
            memcpy(out->release_id, rest+7, len);
        }
        /* ВЕРСИЯ ПРОВОДА. Короче двух байт — версия не объявлена, и это не
           повод считать, что всё в порядке: контроллер обязан отказаться
           работать так же, как при чужой версии. */
        if (rlen >= 2) {
            out->num = (uint32_t)rest[0] << 8 | rest[1];
        }
        /* Предел отправки — четыре байта следом. Его может не быть: старый
           датапат слал только версию, и терять из-за этого разбор события
           нельзя. Нет байтов — ноль, то есть «предел не объявлен». */
        if (rlen >= 6) {
            out->send_maxlen = (uint32_t)rest[2] << 24 | (uint32_t)rest[3] << 16 |
                               (uint32_t)rest[4] << 8 | rest[5];
        }
        break;
    case D2K_EV_REFUSED:
        /* КОД ПРИЧИНЫ, если он приехал. Байт необязателен по длине по той же
           причине, что идентификатор плана выше: старый датапат слал один
           ключ, и терять из-за этого разбор события нельзя. Нет байта — ноль,
           то есть «причина не кодирована», и это честный ответ, а не выдумка.

           Ради этого байта событие и переделывали: без него локальный отказ
           отправки приходил контроллеру неотличимо от «коробка не поддалась»,
           и наша поломка записывалась свойством чужого устройства
           (docs/decisions/0006-proof-boundaries.md). */
        if (rlen >= 1) {
            out->code = rest[0];
        }
        if (rlen < 1 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN) {
            say(err, errcap, "отказ без полного Plan ID/trial ID");
            return -1;
        }
        memcpy(out->plan_id, rest + 1, D2K_PLAN_ID_LEN);
        memcpy(out->trial_id, rest + 1 + D2K_PLAN_ID_LEN, D2K_TRIAL_ID_LEN);
        if (rlen > 1+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN)
            out->client_shape = rest[1+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN];
        if (rlen > 2+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN &&
            execution_context(out, rest + 2+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN,
                              rlen - 2-D2K_PLAN_ID_LEN-D2K_TRIAL_ID_LEN)) {
            say(err, errcap, "повреждён контекст исполнения REFUSED");
            return -1;
        }
        break;
    default:
        /* Вид события, которого этот модуль пока не разбирает глубже, —
           событие сообщение, а не обязательство: незнакомый вид не повод
           отказывать, ключ и kind уже разобраны. */
        break;
    }
    return 0;
}

int d2k_link_set_name(int fd, const char *name, uint8_t transport,
                      const char *plan_text, uint8_t shape, char *err, size_t errcap) {
    return d2k_link_set_name_probe(fd, name, transport, plan_text, shape, 0, err, errcap);
}

/* Ноль в sport_be означает постоянный SET_NAME. Ненулевой порт делает команду пробной
   (D2K_CMD_SET_NAME_PROBE): такой план достанется ровно одному потоку. */
int d2k_link_set_name_probe(int fd, const char *name, uint8_t transport,
                            const char *plan_text, uint8_t shape,
                            uint16_t sport_be, char *err, size_t errcap) {
    return d2k_link_set_name_family(fd, name, transport, plan_text, shape,
                                    sport_be, 4, err, errcap);
}

static int send_name_plan(int fd, const char *name, uint8_t transport,
                             const char *plan_text, uint8_t shape,
                             uint16_t sport_be, uint8_t family,
                             char *err, size_t errcap, uint16_t cmd,
                             const uint8_t *area_id) {
    if (family != 4 && family != 6) {
        say(err, errcap, "семейство адресов должно быть 4 или 6");
        return -1;
    }
    if (fd < 0) {
        say(err, errcap, "сокет не открыт");
        return -1;
    }
    if (!name || !*name) {
        say(err, errcap, "имя цели пусто");
        return -1;
    }
    size_t nl = strlen(name);
    if (nl > 255) {
        say(err, errcap, "имя цели длиной %zu байт длиннее 255", nl);
        return -1;
    }
    if (transport != 6 && transport != 17) {
        /* Проверяется, но НЕ едет отдельным полем на проводе — см. большой
           комментарий у d2k_link_set_name в d2k_link.h про то, почему у
           SET_NAME сегодня нет места под транспорт. */
        say(err, errcap, "транспорт %u не 6 (TCP) и не 17 (UDP)", (unsigned)transport);
        return -1;
    }
    if (!plan_text) {
        plan_text = "";
    }
    size_t hexlen = strlen(plan_text);
    if (hexlen % 2 != 0) {
        say(err, errcap, "план не hex: нечётное число символов (%zu)", hexlen);
        return -1;
    }
    size_t extra = sport_be ? 2u : 0u;                  /* местный порт, если пробный */
    size_t seq_len = (cmd == D2K_CMD_SET_SUFFIX || cmd == D2K_CMD_SET_NAME_PROBE || cmd == D2K_CMD_SET_NAME_BOUND)
                         ? D2K_TRIAL_ID_LEN : 0;
    size_t plan_cap = sizeof g_scratch - HDR - 3 - nl - extra - seq_len;
    if (hexlen / 2 > plan_cap) {
        say(err, errcap, "план длиннее предела кадра");
        return -1;
    }

    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl;
    memcpy(g_scratch + o, name, nl);
    o += nl;
    /* ФОРМА ПРИВЕТСТВИЯ — байтом ПЕРЕД планом, а не после.
       Длина плана в теле не объявлена: план это «всё, что осталось». Поле
       после него было бы съедено как часть плана. */
    g_scratch[o++] = shape;
    g_scratch[o++] = family;
    if (sport_be) {
        memcpy(g_scratch + o, &sport_be, 2);
        o += 2;
    }
    long planlen = hex_decode(plan_text, g_scratch + o, sizeof g_scratch - o);
    if (planlen < 0) {
        say(err, errcap, "план не hex: недопустимый символ");
        return -1;
    }
    o += (size_t)planlen;
    if (seq_len) {
        memset(g_scratch+o, 0, seq_len);
        if (area_id) memcpy(g_scratch+o, area_id, seq_len);
        o += seq_len;
    }

    size_t body_len = o - HDR;
    if (body_len > (size_t)D2K_CTL_FRAME_MAX - 2) {
        /* То же ограничение, что и в d2k_ctl_poll на приёме: кадр длиннее
           предела датапат не разберёт, а порвёт соединение как "врущую
           длину" — лучше отказать здесь, не тратя единственное подключение. */
        say(err, errcap, "команда длиннее предела кадра");
        return -1;
    }
    uint32_t plen = (uint32_t)(2 + body_len);
    g_scratch[0] = (uint8_t)(plen >> 24);
    g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);
    g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(cmd >> 8);
    g_scratch[5] = (uint8_t)cmd;

    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда SET_NAME не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_set_name_family(int fd, const char *name, uint8_t transport,
    const char *plan_text, uint8_t shape, uint16_t sport_be, uint8_t family,
    char *err, size_t errcap) {
    return send_name_plan(fd, name, transport, plan_text, shape, sport_be, family,
        err, errcap, sport_be ? D2K_CMD_SET_NAME_PROBE : D2K_CMD_SET_NAME, NULL);
}

int d2k_link_set_name_bound(int fd,const char *name,uint8_t transport,
    const char *plan_text,uint8_t shape,uint8_t family,const uint8_t token[16],char *err,size_t cap) {
    if(!token)return -1;
    return send_name_plan(fd,name,transport,plan_text,shape,0,family,err,cap,D2K_CMD_SET_NAME_BOUND,token);
}

int d2k_link_del_name_bound(int fd,const char *name,uint8_t transport,
    const d2k_binding_context *binding,char *err,size_t cap) {
    if(fd<0 || !name || !*name || strlen(name)>255 || (transport!=6 && transport!=17) ||
       !d2k_binding_known(binding) || binding->kind!=D2K_BIND_NAME || binding->temporary) return -1;
    size_t nl=strlen(name),o=HDR;
    g_scratch[o++]=(uint8_t)nl;memcpy(g_scratch+o,name,nl);o+=nl;
    g_scratch[o++]=transport;d2k_ctl_binding_write(g_scratch+o,binding);o+=D2K_CTL_BINDING_LEN;
    uint32_t n=(uint32_t)(o-4);
    for(unsigned i=0;i<4;i++)g_scratch[i]=(uint8_t)(n>>(24-8*i));
    g_scratch[4]=D2K_CMD_DEL_NAME_BOUND>>8;g_scratch[5]=(uint8_t)D2K_CMD_DEL_NAME_BOUND;
    if(write_all(fd,g_scratch,o)) {say(err,cap,"conditional name delete failed: %s",strerror(errno));return -1;}
    return 0;
}

int d2k_link_set_name_probe_trial(int fd, const char *name, uint8_t transport,
    const char *plan_text, uint8_t shape, uint16_t sport_be, uint8_t family,
    const uint8_t trial_id[D2K_TRIAL_ID_LEN], char *err, size_t errcap) {
    if (!sport_be) {
        say(err, errcap, "пробная установка без местного порта");
        return -1;
    }
    return send_name_plan(fd, name, transport, plan_text, shape, sport_be, family,
        err, errcap, D2K_CMD_SET_NAME_PROBE, trial_id);
}

static int area_context_valid(uint8_t transport, uint8_t shape, uint8_t family) {
    return (family == 4 || family == 6) &&
        ((transport == 6 && (shape == 1 || shape == 2 || shape == 6)) ||
         (transport == 17 && shape == 3));
}

int d2k_link_set_suffix_family(int fd, const char *name, uint8_t transport,
    const char *plan_text, uint8_t shape, uint8_t family, char *err, size_t errcap) {
    if (!area_context_valid(transport, shape, family)) {
        say(err, errcap, "неверный контекст семейства доменов"); return -1;
    }
    return send_name_plan(fd, name, transport, plan_text, shape, 0, family,
        err, errcap, D2K_CMD_SET_SUFFIX, NULL);
}

int d2k_link_set_https(int fd, const char *name, uint32_t ttl_s, char *err, size_t errcap) {
    size_t nl = name ? strlen(name) : 0;
    if (fd < 0 || nl == 0 || nl > 253) {
        say(err, errcap, "имя для HTTPS пусто или длиннее 253");
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl; memcpy(g_scratch + o, name, nl); o += nl;
    g_scratch[o++] = (uint8_t)(ttl_s >> 24); g_scratch[o++] = (uint8_t)(ttl_s >> 16);
    g_scratch[o++] = (uint8_t)(ttl_s >> 8); g_scratch[o++] = (uint8_t)ttl_s;
    uint32_t plen = (uint32_t)(o - HDR + 2);
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_SET_HTTPS >> 8); g_scratch[5] = (uint8_t)D2K_CMD_SET_HTTPS;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "SET_HTTPS не отправился: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_set_stall_budgets(int fd, const uint16_t *b, size_t n, char *err, size_t errcap) {
    if (fd < 0 || n > D2K_STALL_BUDGETS_MAX || (n && !b)) {
        say(err, errcap, "бюджетов потока больше %d или нет сокета", D2K_STALL_BUDGETS_MAX);
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) {
        if (!b[i]) { say(err, errcap, "нулевой бюджет потока"); return -1; }
        g_scratch[o++] = (uint8_t)(b[i] >> 8);
        g_scratch[o++] = (uint8_t)b[i];
    }
    uint32_t plen = (uint32_t)(o - HDR + 2);
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_SET_STALL_BUDGETS >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_SET_STALL_BUDGETS;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "SET_STALL_BUDGETS не отправился: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int send_area_key(int fd, uint16_t cmd, const char *name,
    uint8_t transport, uint8_t shape, uint8_t family, char *err, size_t errcap,
    const uint8_t *area_id) {
    if (fd < 0 || !name || !*name || strlen(name) > 253 ||
        !area_context_valid(transport, shape, family)) {
        say(err, errcap, "неверный ключ семейства доменов"); return -1;
    }
    size_t nl = strlen(name), o = HDR;
    g_scratch[o++] = (uint8_t)nl; memcpy(g_scratch+o, name, nl); o += nl;
    g_scratch[o++] = transport; g_scratch[o++] = shape; g_scratch[o++] = family;
    memset(g_scratch+o, 0, D2K_TRIAL_ID_LEN);
    if (area_id) memcpy(g_scratch+o, area_id, D2K_TRIAL_ID_LEN);
    o += D2K_TRIAL_ID_LEN;
    uint32_t plen = (uint32_t)(o-HDR+2);
    g_scratch[0] = (uint8_t)(plen>>24); g_scratch[1] = (uint8_t)(plen>>16);
    g_scratch[2] = (uint8_t)(plen>>8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(cmd>>8); g_scratch[5] = (uint8_t)cmd;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда семейства не отправилась: %s", strerror(errno)); return -1;
    }
    return 0;
}

int d2k_link_del_suffix_family(int fd, const char *name, uint8_t transport,
    uint8_t shape, uint8_t family, char *err, size_t errcap) {
    return send_area_key(fd, D2K_CMD_DEL_SUFFIX, name, transport, shape, family, err, errcap, NULL);
}
int d2k_link_set_bypass_family(int fd, const char *name, uint8_t transport,
    uint8_t shape, uint8_t family, char *err, size_t errcap) {
    return send_area_key(fd, D2K_CMD_SET_BYPASS, name, transport, shape, family, err, errcap, NULL);
}
int d2k_link_del_bypass_family(int fd, const char *name, uint8_t transport,
    uint8_t shape, uint8_t family, char *err, size_t errcap) {
    return send_area_key(fd, D2K_CMD_DEL_BYPASS, name, transport, shape, family, err, errcap, NULL);
}

int d2k_link_area_identified(int fd, uint16_t cmd, const char *name,
    uint8_t transport, uint8_t shape, uint8_t family, const char *plan_text,
    const uint8_t id[D2K_TRIAL_ID_LEN], char *err, size_t errcap) {
    if (!id || !area_context_valid(transport, shape, family)) return -1;
    if (cmd == D2K_CMD_SET_SUFFIX)
        return send_name_plan(fd, name, transport, plan_text, shape, 0, family,
            err, errcap, cmd, id);
    if (cmd != D2K_CMD_DEL_SUFFIX && cmd != D2K_CMD_SET_BYPASS && cmd != D2K_CMD_DEL_BYPASS)
        return -1;
    return send_area_key(fd, cmd, name, transport, shape, family, err, errcap, id);
}


/* Форма адресной привязки (v7): только измеренный протокол — TLS 1.3/1.2,
   ECH, QUIC, STUN/голос. Ноль и дедушкино право означали бы «подходит всем
   протоколам IP» (задача 16, D2K_SPEC §5); такая команда не собирается. */
static int addr_shape_ok(uint8_t shape) {
    return shape == 1 || shape == 2 || shape == D2K_LINK_SHAPE_QUIC ||
           shape == D2K_LINK_SHAPE_VOICE || shape == D2K_LINK_SHAPE_ECH_TCP;
}

int d2k_link_set_addr(int fd, const uint8_t ip4[4], uint8_t shape,
                      const char *plan_text, char *err, size_t errcap) {
    return d2k_link_set_addr_family(fd, ip4, 4, shape, plan_text, err, errcap);
}

int d2k_link_set_addr_family(int fd, const uint8_t *ip4, uint8_t family,
    uint8_t shape, const char *plan_text, char *err, size_t errcap) {
    if (fd < 0 || (family != 4 && family != 6)) {
        say(err, errcap, "сокет не открыт");
        return -1;
    }
    if (!ip4) {
        say(err, errcap, "адрес цели не задан");
        return -1;
    }
    if (!addr_shape_ok(shape)) {
        say(err, errcap, "у адресной привязки нет формы протокола (%u)", (unsigned)shape);
        return -1;
    }
    if (!plan_text) {
        plan_text = "";
    }
    size_t hexlen = strlen(plan_text);
    if (hexlen % 2 != 0) {
        say(err, errcap, "план не hex: нечётное число символов (%zu)", hexlen);
        return -1;
    }

    size_t o = HDR;
    g_scratch[o++] = family;
    memset(g_scratch + o, 0, 16);
    memcpy(g_scratch + o, ip4, family == 6 ? 16 : 4);
    o += 16;
    g_scratch[o++] = shape;
    long planlen = hex_decode(plan_text, g_scratch + o, sizeof g_scratch - o);
    if (planlen < 0) {
        say(err, errcap, "план не hex: недопустимый символ");
        return -1;
    }
    o += (size_t)planlen;

    size_t body_len = o - HDR;
    if (body_len > (size_t)D2K_CTL_FRAME_MAX - 2) {
        say(err, errcap, "команда длиннее предела кадра");
        return -1;
    }
    uint32_t plen = (uint32_t)(2 + body_len);
    g_scratch[0] = (uint8_t)(plen >> 24);
    g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);
    g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_SET_ADDR >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_SET_ADDR;

    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда SET_ADDR не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* Адреса — 4 байта для IPv4 и 16 для IPv6: параметры объявлены указателями,
   а не [4], иначе GCC видит чтение 16 байт за границей объявленного массива. */
static int addr_probe_flow_bytes(uint8_t *p, const uint8_t *src_ip4, uint16_t src_port_be,
                                 const uint8_t *dst_ip4, uint16_t dst_port_be,
                                 uint8_t transport, uint8_t family) {
    /* src_port_be 0 — голосовой опыт на любой клиентский порт (задача 15). */
    if (!src_ip4 || !dst_ip4 || !dst_port_be || transport != 17 ||
        (family != 4 && family != 6)) { return -1; }
    memset(p, 0, 38);
    p[0] = family;
    memcpy(p + 1, src_ip4, family == 6 ? 16 : 4);
    memcpy(p + 17, dst_ip4, family == 6 ? 16 : 4);
    memcpy(p + 33, &src_port_be, 2);
    memcpy(p + 35, &dst_port_be, 2);
    p[37] = transport;
    return 0;
}

int d2k_link_set_addr_probe(int fd, const uint8_t src_ip4[4], uint16_t src_port_be,
                            const uint8_t dst_ip4[4], uint16_t dst_port_be,
                            uint8_t transport, const uint8_t trial_id[D2K_TRIAL_ID_LEN],
                            uint32_t lease_ms, const char *plan_hex,
                            char *err, size_t errcap) {
    return d2k_link_set_addr_probe_family(fd, src_ip4, src_port_be, dst_ip4,
        dst_port_be, transport, 4, trial_id, lease_ms, plan_hex, err, errcap);
}

int d2k_link_set_addr_probe_family(int fd, const uint8_t *src_ip4, uint16_t src_port_be,
    const uint8_t *dst_ip4, uint16_t dst_port_be, uint8_t transport, uint8_t family,
    const uint8_t trial_id[D2K_TRIAL_ID_LEN], uint32_t lease_ms,
    const char *plan_hex, char *err, size_t errcap) {
    if (fd < 0 || !trial_id || !lease_ms || lease_ms > D2K_ADDR_PROBE_LEASE_MAX_MS || !plan_hex ||
        addr_probe_flow_bytes(g_scratch + HDR, src_ip4, src_port_be,
                              dst_ip4, dst_port_be, transport, family) != 0) {
        say(err, errcap, "аргументы SET_ADDR_PROBE негодны");
        return -1;
    }
    uint8_t any = 0;
    for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) { any |= trial_id[i]; }
    if (!any) { say(err, errcap, "trial_id не может быть нулевым"); return -1; }
    size_t o = HDR + 38;
    memcpy(g_scratch + o, trial_id, D2K_TRIAL_ID_LEN); o += D2K_TRIAL_ID_LEN;
    g_scratch[o++] = (uint8_t)(lease_ms >> 24);
    g_scratch[o++] = (uint8_t)(lease_ms >> 16);
    g_scratch[o++] = (uint8_t)(lease_ms >> 8);
    g_scratch[o++] = (uint8_t)lease_ms;
    size_t hexlen = strlen(plan_hex);
    if (hexlen & 1u) { say(err, errcap, "план SET_ADDR_PROBE не hex"); return -1; }
    long decoded = hex_decode(plan_hex, g_scratch + o, sizeof g_scratch - o);
    if (decoded < 0) { say(err, errcap, "план SET_ADDR_PROBE не hex"); return -1; }
    o += (size_t)decoded;
    size_t body_len = o - HDR;
    if (body_len > (size_t)D2K_CTL_FRAME_MAX - 2) { say(err, errcap, "SET_ADDR_PROBE длиннее кадра"); return -1; }
    uint32_t plen = (uint32_t)(2 + body_len);
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_SET_ADDR_PROBE >> 8); g_scratch[5] = (uint8_t)D2K_CMD_SET_ADDR_PROBE;
    if (write_all(fd, g_scratch, o) != 0) { say(err, errcap, "SET_ADDR_PROBE: %s", strerror(errno)); return -1; }
    return 0;
}

int d2k_link_del_addr_probe(int fd, const uint8_t src_ip4[4], uint16_t src_port_be,
                            const uint8_t dst_ip4[4], uint16_t dst_port_be,
                            uint8_t transport, const uint8_t trial_id[D2K_TRIAL_ID_LEN],
                            char *err, size_t errcap) {
    return d2k_link_del_addr_probe_family(fd, src_ip4, src_port_be, dst_ip4,
        dst_port_be, transport, 4, trial_id, err, errcap);
}

int d2k_link_del_addr_probe_family(int fd, const uint8_t *src_ip4, uint16_t src_port_be,
    const uint8_t *dst_ip4, uint16_t dst_port_be, uint8_t transport, uint8_t family,
    const uint8_t trial_id[D2K_TRIAL_ID_LEN], char *err, size_t errcap) {
    if (fd < 0 || !trial_id || addr_probe_flow_bytes(g_scratch + HDR, src_ip4,
        src_port_be, dst_ip4, dst_port_be, transport, family) != 0) {
        say(err, errcap, "аргументы DEL_ADDR_PROBE негодны"); return -1;
    }
    uint8_t any = 0;
    for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) { any |= trial_id[i]; }
    if (!any) { say(err, errcap, "trial_id не может быть нулевым"); return -1; }
    size_t o = HDR + 38;
    memcpy(g_scratch + o, trial_id, D2K_TRIAL_ID_LEN); o += D2K_TRIAL_ID_LEN;
    uint32_t plen = (uint32_t)(2 + o - HDR);
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8); g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_DEL_ADDR_PROBE >> 8); g_scratch[5] = (uint8_t)D2K_CMD_DEL_ADDR_PROBE;
    if (write_all(fd, g_scratch, o) != 0) { say(err, errcap, "DEL_ADDR_PROBE: %s", strerror(errno)); return -1; }
    return 0;
}

int d2k_link_arm_shape(int fd, const char *name, uint8_t transport,
                       char *err, size_t errcap) {
    return d2k_link_arm_shape_family(fd, name, transport, 4, err, errcap);
}

int d2k_link_arm_shape_family(int fd, const char *name, uint8_t transport,
                              uint8_t family, char *err, size_t errcap) {
    /* Своё тело, а не send_name_only: за именем едет ТРАНСПОРТ. Снимок
       приветствия датапат хранит отдельно на транспорт, и без этого байта он
       отдал бы QUIC-задаче байты TLS (d2k_session_want_shape). */
    if (fd < 0 || (family != 4 && family != 6) || (transport != 6 && transport != 17)) {
        say(err, errcap, "сокет не открыт");
        return -1;
    }
    if (!name) { name = ""; }
    size_t nl = strlen(name);
    if (nl > 255) {
        say(err, errcap, "имя цели длиной %zu байт длиннее 255", nl);
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl;
    memcpy(g_scratch + o, name, nl);
    o += nl;
    g_scratch[o++] = transport;
    g_scratch[o++] = family;

    size_t body_len = o - HDR;
    uint32_t plen = (uint32_t)(2 + body_len);
    g_scratch[0] = (uint8_t)(plen >> 24);
    g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);
    g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_ARM_SHAPE >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_ARM_SHAPE;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда ARM_SHAPE не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_del_name_family(int fd, const char *name, uint8_t transport,
                             uint8_t shape, uint8_t family,
                             char *err, size_t errcap) {
    /* v9: ключ постоянной записи целиком — имя, транспорт, форма, семейство.
       Пробы этой командой не снимаются (задача 21). */
    if (fd < 0 || !name || (family != 4 && family != 6) ||
        (transport != 6 && transport != 17) || shape == 0) {
        say(err, errcap, "сокет, транспорт, форма или семейство снятия не заданы");
        return -1;
    }
    size_t nl = strlen(name);
    if (nl == 0 || nl > 255) {
        say(err, errcap, "недопустимая длина имени снятия");
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl;
    memcpy(g_scratch + o, name, nl); o += nl;
    g_scratch[o++] = transport;
    g_scratch[o++] = shape;
    g_scratch[o++] = family;
    uint32_t plen = (uint32_t)(2 + (o - HDR));
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);  g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_DEL_NAME >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_DEL_NAME;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "команда DEL_NAME не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_del_name_probe(int fd, const char *name, uint8_t transport,
                            uint8_t shape, uint16_t sport_be,
                            char *err, size_t errcap) {
    return d2k_link_del_name_probe_family(fd, name, transport, shape, sport_be, 4, err, errcap);
}

int d2k_link_del_name_probe_family(int fd, const char *name, uint8_t transport,
                                   uint8_t shape, uint16_t sport_be, uint8_t family,
                                   char *err, size_t errcap) {
    (void)transport; /* transport is represented by the wire shape */
    if (fd < 0 || !name || sport_be == 0 || (family != 4 && family != 6)) {
        say(err, errcap, "сокет, имя или порт пробного плана не задан");
        return -1;
    }
    size_t nl = strlen(name);
    if (nl == 0 || nl > 255) {
        say(err, errcap, "недопустимая длина имени пробного плана");
        return -1;
    }
    size_t o = HDR;
    g_scratch[o++] = (uint8_t)nl;
    memcpy(g_scratch + o, name, nl); o += nl;
    g_scratch[o++] = shape;
    g_scratch[o++] = family;
    memcpy(g_scratch + o, &sport_be, 2); o += 2;
    uint32_t plen = (uint32_t)(2 + (o - HDR));
    g_scratch[0] = (uint8_t)(plen >> 24); g_scratch[1] = (uint8_t)(plen >> 16);
    g_scratch[2] = (uint8_t)(plen >> 8);  g_scratch[3] = (uint8_t)plen;
    g_scratch[4] = (uint8_t)(D2K_CMD_DEL_NAME_PROBE >> 8);
    g_scratch[5] = (uint8_t)D2K_CMD_DEL_NAME_PROBE;
    if (write_all(fd, g_scratch, o) != 0) {
        say(err, errcap, "DEL_NAME_PROBE не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int d2k_link_del_addr(int fd, const uint8_t ip4[4], uint8_t shape,
                      char *err, size_t errcap) {
    return d2k_link_del_addr_family(fd, ip4, 4, shape, err, errcap);
}

int d2k_link_del_addr_family(int fd, const uint8_t *ip4, uint8_t family,
    uint8_t shape, char *err, size_t errcap) {
    if (fd < 0 || !ip4 || (family != 4 && family != 6)) {
        say(err, errcap, "сокет не открыт или адрес цели не задан");
        return -1;
    }
    if (!addr_shape_ok(shape)) {
        say(err, errcap, "у адресной привязки нет формы протокола (%u)", (unsigned)shape);
        return -1;
    }
    uint8_t frame[HDR + 18] = {0, 0, 0, 20,
        (uint8_t)(D2K_CMD_DEL_ADDR >> 8), (uint8_t)D2K_CMD_DEL_ADDR};
    frame[HDR] = family;
    memcpy(frame + HDR + 1, ip4, family == 6 ? 16 : 4);
    frame[HDR + 17] = shape;
    if (write_all(fd, frame, sizeof frame) != 0) {
        say(err, errcap, "команда DEL_ADDR не отправилась: %s", strerror(errno));
        return -1;
    }
    return 0;
}


int d2k_ev_outer_appdata(const d2k_ev *ev) {
    /* ВНЕШНИЙ тип записи, а не тип ПЕРВОЙ записи (code — липкое поле, см.
     * большой комментарий у seen_types в d2k_link.h) и не любые вернувшиеся
     * байты. Внешним типом 23 в TLS 1.3 едет и второй полёт рукопожатия
     * (RFC 8446 §5.2), поэтому ответ этой функции — наблюдение уровня 2
     * (§4.2), а порог каталога живёт в планировщике (см. объявление в
     * d2k_link.h). Зеркало Go-донора HasAppData: маска, а не сравнение с
     * одним значением — иначе uint8_t seen_types молча продвинулся бы до
     * uint16_t и сравнился с типом записи, что почти всегда даёт ложь без
     * единого предупреждения компилятора. ev == NULL — не событие, внешнего
     * типа 23 в нём нет по определению, а не неопределённое поведение. */
    if (!ev) {
        return 0;
    }
    return (ev->seen_types & (uint8_t)(1u << (D2K_TLS_APPLICATION_DATA - 20))) != 0 ? 1 : 0;
}
