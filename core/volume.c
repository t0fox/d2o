/* volume.c — направленные измерения объёма. См. d2k_volume.h.
 *
 * ЛЕСТНИЦА ИСХОДЯЩЕГО ОБЪЁМА: десять запросов по одному соединению, со второго
 * — с мусорным заголовком. Мусор в заголовке остаётся единственным способом
 * накачать соединение СВОИМ объёмом, не завися от того, что отдаёт мишень.
 *
 * Отдельная RX-пара identity/gzip ниже измеряет тело ответа и требует двух
 * совпавших обрывов плюс полного gzip-контроля. Направления не смешиваются:
 * TX-ступень и RX-обрыв возвращаются отдельными полями и попадают в каталог
 * под разными видами приметы.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp — имя подсказки против предъявляемого SNI */
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"   /* d2k_mark_hook — метка ставится тем же путём, что везде */
#include "d2k_catalog.h" /* общий допуск для сопоставления RX-объёмов */
#include "d2k_tls13.h"
#include "d2k_tls12.h"
#include "d2k_volume.h"
#include "d2k_verify.h"

/* Восемь секунд на подключение и на рукопожатие — из пробы донора
   (z2k-detect/internal/tcp16), замер на этой линии. */
#define CONNECT_MS   8000
#define HANDSHAKE_MS 8000

/* Пауза между запросами. Без неё десять запросов уходят одной очередью, и
   коробка видит поток иначе, чем видит его браузер: вердикт плывёт. */
#define CHUNK_DELAY_MS 50
#define RESPONSE_PROBE_GAP_MS 500

/* Ожидание ответа считается от ИЗМЕРЕННОГО RTT, а не берётся с потолка. Живой
   ответ приходит за один RTT; «нет ответа» — это неподходящее имя, на котором
   коробка молчит, и с фиксированным потолком каждый мимо-кандидат стоил бы
   полные секунды. Нижняя граница защищает от слишком оптимистичного замера на
   первом пакете, верхняя — от линии с большим RTT. */
#define READ_MIN_MS  1500
#define READ_MAX_MS  12000

/* A partial encrypted record is visible even before the first HTTP header.
   This is suspicion, not a verdict. Unknown versions, replayed hellos and
   local limits cannot establish the application record context. */
static int rx_wire_partial(const d2k_ver_result *r) {
    return r && r->level == D2K_VER_HANDSHAKE && r->name_ok == 1 &&
        !r->status && !r->replay_proof && !r->local_limit &&
        (r->negotiated_tls == 0x0303 || r->negotiated_tls == 0x0304) &&
        r->rx_tls_record_missing &&
        r->rx_tls_wire_bytes >= (uint64_t)D2K_VOL_MIN_KB * 1024;
}

int d2k_volume_rx_partial(const d2k_ver_result *r) {
    return rx_wire_partial(r) || (r && r->status >= 200 && r->status < 300 && !r->body_complete &&
        r->body_encoding == 0 && r->body_framing_valid &&
        r->body_has_length != r->body_chunked &&
        r->body_bytes >= (uint64_t)D2K_VOL_MIN_KB * 1024 &&
        (!r->body_has_length || r->body_expected > r->body_bytes));
}

/* ДВА ИЗМЕРЕНИЯ ГОВОРЯТ ОБ ОДНОМ. Оба оборваны, оба в ОДНОМ домене
   (ciphertext либо HTTP-тело), и контекст домена совпал: согласованная версия
   TLS для записи, HTTP framing для тела. Байты здесь не сравниваются — это
   дело d2k_volume_rx_evidence, которое и держит допуск. */
int d2k_volume_rx_pair_agrees(const d2k_ver_result *a, const d2k_ver_result *b) {
    if (!a || !b || !d2k_volume_rx_partial(a) || !d2k_volume_rx_partial(b)) { return 0; }
    if (rx_wire_partial(a) != rx_wire_partial(b)) { return 0; }
    if (rx_wire_partial(a)) { return a->negotiated_tls == b->negotiated_tls; }
    return a->body_has_length == b->body_has_length && a->body_chunked == b->body_chunked;
}

/* ОДНО ИЗМЕРЕНИЕ ОБОРВАЛОСЬ, ВТОРОЕ ДОШЛО ДО КОНЦА — РАСХОЖДЕНИЕ, А НЕ
   ОПРОВЕРЖЕНИЕ. Поле 12.10.2026, www.tampermonkey.net: /style.css с VPS —
   30182 байта, с линии — 15963, восемь прогонов подряд байт в байт, молча,
   без RST и FIN сервера. RX-зонд при этом видел «identity-1 partial=15627;
   identity-2 HTTP 200 body=22094 complete=1» и возвращался ни с чем: три
   эпизода подряд печатали «позднее закрытие не подтвердилось парными
   измерениями» и уходили в покой на десять минут.

   Дошедший повтор — шум линии, и вердикт по нему не выносится так же, как не
   выносится по одному обрыву (§«подозрение не равно блокировке»). Поэтому
   заказывается ТРЕТИЙ identity-прогон, и пара считается сошедшейся только
   если обрыв подтвердился на нём: вердикт всё равно стоит на ДВУХ обрывах.

   Поводом служит именно противоречие, а не всякая несошедшаяся пара: ответ
   завершился кодом 2xx и САМ прошёл измеряемую полосу, то есть сказал о
   полосе «прошла». Пустое измерение (нет TCP, нет статуса) не противоречит
   ничему, а завершённый ответ меньше полосы — непроверенный бюджет
   (rx_short), и лишнего прогона ни то, ни другое не заказывает. */
int d2k_volume_rx_needs_repeat(const d2k_ver_result *a, const d2k_ver_result *b) {
    if (!a || !b) { return 0; }
    if (!d2k_volume_rx_partial(a) || d2k_volume_rx_partial(b)) { return 0; }
    return b->status >= 200 && b->status < 300 && b->body_complete &&
           b->body_framing_valid &&
           b->body_bytes >= (uint64_t)D2K_VOL_MIN_KB * 1024;
}

int d2k_volume_rx_evidence(const d2k_ver_result *a,
                           const d2k_ver_result *b,
                           const d2k_ver_result *gzip,
                           d2k_vol_result *out) {
    const uint64_t min_bytes = (uint64_t)D2K_VOL_MIN_KB * 1024;
    if (!a || !b || !gzip || !out) { return 0; }
    if (rx_wire_partial(a) || rx_wire_partial(b)) {
        if (!rx_wire_partial(a) || !rx_wire_partial(b) ||
            a->negotiated_tls != b->negotiated_tls ||
            gzip->negotiated_tls != a->negotiated_tls ||
            gzip->level != D2K_VER_APPLICATION || gzip->name_ok != 1 ||
            gzip->local_limit || gzip->status < 200 || gzip->status >= 300 ||
            !gzip->body_complete || !gzip->body_framing_valid ||
            gzip->body_encoding != 1 || !gzip->body_bytes ||
            !gzip->rx_tls_wire_bytes || gzip->rx_tls_record_missing ||
            gzip->rx_tls_wire_bytes >= a->rx_tls_wire_bytes ||
            gzip->rx_tls_wire_bytes >= b->rx_tls_wire_bytes) return 0;
        uint64_t lo = a->rx_tls_wire_bytes < b->rx_tls_wire_bytes
            ? a->rx_tls_wire_bytes : b->rx_tls_wire_bytes;
        uint64_t hi = a->rx_tls_wire_bytes > b->rx_tls_wire_bytes
            ? a->rx_tls_wire_bytes : b->rx_tls_wire_bytes;
        if (hi - lo > (uint64_t)D2K_VOLUME_SLACK * 1024) return 0;
        out->rx_cut = 1; out->rx_wire_basis = 1;
        uint64_t kb = (lo + (hi - lo) / 2) / 1024;
        out->rx_at_kb = kb > INT_MAX ? INT_MAX : (int)kb;
        out->rx_expected_kb = 0; out->rx_compressed_complete = 1;
        unsigned pa = a->data_packets, pb = b->data_packets;
        unsigned pk = pa && pb ? (pa < pb ? pa : pb) : (pa ? pa : pb);
        out->rx_cut_packets = pk > INT_MAX ? INT_MAX : (int)pk;
        snprintf(out->reason, sizeof out->reason,
            "TLS RX дважды оборвался внутри записи около %d КБ; меньший gzip завершился",
            out->rx_at_kb);
        return 1;
    }
    if (a->status < 200 || a->status >= 300 || b->status < 200 || b->status >= 300 ||
        a->body_complete || b->body_complete || a->body_encoding != 0 ||
        !a->body_framing_valid || !b->body_framing_valid ||
        b->body_encoding != 0 || a->body_bytes < min_bytes || b->body_bytes < min_bytes ||
        a->body_has_length != b->body_has_length || a->body_chunked != b->body_chunked ||
        (!a->body_has_length && !a->body_chunked) ||
        (a->body_has_length && a->body_chunked)) { return 0; }
    if (a->body_has_length && (a->body_expected <= a->body_bytes ||
                               b->body_expected <= b->body_bytes)) { return 0; }
    uint64_t delta = a->body_bytes > b->body_bytes
                   ? a->body_bytes - b->body_bytes : b->body_bytes - a->body_bytes;
    if (delta > (uint64_t)D2K_VOLUME_SLACK * 1024) { return 0; }
    if (gzip->status < 200 || gzip->status >= 300 || !gzip->body_framing_valid ||
        gzip->body_encoding != 1 || gzip->body_bytes == 0) { return 0; }
    /* ДВЕ ПРИМЕТЫ ОДНОГО И ТОГО ЖЕ: ОБРЫВ ПО БАЙТАМ И ОБРЫВ ПО ПАКЕТАМ.
       Байтовая — identity рвётся, а gzip той же страницы, меньший по
       объёму, доходит. Пакетная (поле 04.10, task-55-facts §1.2: Cloudflare
       режет поток после ~25 пакетов с данными обеих сторон, 25–27 в 18/18
       потоках, при 5,9–29,6 КБ): gzip, которому самому нужно больше
       бюджета, рвётся тоже, но на ТОМ ЖЕ числе пакетов. rua.gr 04.10:
       identity 22229/22280, gzip 20817 не дошёл — прежнее правило читало
       это как «блока нет». Пакеты считает ядро (TCP_INFO data_segs); не
       посчитаны все три — остаётся только байтовое правило. */
    int packet_budget = 0;
    if (!gzip->body_complete) {
        unsigned pa = a->data_packets, pb = b->data_packets, pg = gzip->data_packets;
        unsigned lo = pa, hi = pa;
        if (!pa || !pb || !pg) { return 0; }
        if (pb < lo) lo = pb;
        if (pb > hi) hi = pb;
        if (pg < lo) lo = pg;
        if (pg > hi) hi = pg;
        if (hi - lo > D2K_VOLUME_PACKET_SLACK) { return 0; }
        packet_budget = 1;
    }

    out->rx_cut = 1; out->rx_wire_basis = 0;
    uint64_t midpoint = (a->body_bytes < b->body_bytes ? a->body_bytes : b->body_bytes)
                      + delta / 2;
    uint64_t cut_kb = midpoint / 1024;
    out->rx_at_kb = cut_kb > INT_MAX ? INT_MAX : (int)cut_kb;
    out->rx_expected_kb = 0;
    if (a->body_has_length && a->body_expected <= (uint64_t)INT_MAX * 1024) {
        out->rx_expected_kb = (int)(a->body_expected / 1024);
    }
    out->rx_compressed_complete = !packet_budget;
    /* Бюджет потока коробки (задача 55): пакеты с данными обеих сторон, на
       которых identity оборвался. Из двух посчитанных — меньший: коробка
       режет не позже него. Не посчитан ни один — 0, бюджета не выдумываем.
       При пакетной примете в счёт идёт и обрыв gzip. */
    unsigned pa = a->data_packets, pb = b->data_packets;
    unsigned pk = pa && pb ? (pa < pb ? pa : pb) : (pa ? pa : pb);
    if (packet_budget && gzip->data_packets < pk) { pk = gzip->data_packets; }
    out->rx_cut_packets = pk > INT_MAX ? INT_MAX : (int)pk;
    if (packet_budget) {
        snprintf(out->reason, sizeof out->reason,
                 "identity (около %d КБ) и gzip оборвались на одном бюджете: ~%u пакетов "
                 "с данными на поток", out->rx_at_kb, pk);
    } else if (out->rx_expected_kb > 0) {
        snprintf(out->reason, sizeof out->reason,
                 "identity-тело повторно оборвалось около %d/%d КБ; gzip завершился",
                 out->rx_at_kb, out->rx_expected_kb);
    } else {
        snprintf(out->reason, sizeof out->reason,
                 "chunked identity-тело повторно оборвалось около %d КБ; gzip завершился",
                 out->rx_at_kb);
    }
    return 1;
}

const char *d2k_vol_verdict_name(d2k_vol_verdict v) {
    switch (v) {
    case D2K_VOL_CUT:    return "обрыв по объёму";
    case D2K_VOL_PASSED: return "объём прошёл";
    case D2K_VOL_SHORT:  return "объём не набран — вердикта нет";
    default:             return "мишень не ответила";
    }
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void nap_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    (void)nanosleep(&ts, NULL);
}

static int clamp_ms(int64_t v, int lo, int hi) {
    if (v < lo) { return lo; }
    if (v > hi) { return hi; }
    return (int)v;
}

/* Набивка: печатные символы, потому что она едет в ЗАГОЛОВКЕ HTTP, а туда
   произвольные байты класть нельзя — сервер отверг бы запрос, и мы мерили бы
   это вместо блока. Из /dev/urandom, а не постоянная строка: одинаковый мусор
   в десяти запросах коробка вправе схлопнуть как повтор. */
static void fill_pad(char *out, size_t n) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    FILE *f = fopen("/dev/urandom", "rb");
    for (size_t i = 0; i < n; i++) {
        int c = f ? fgetc(f) : -1;
        if (c < 0) { c = (int)(i * 31 + 7); }
        out[i] = alphabet[(unsigned)c % (sizeof alphabet - 1)];
    }
    if (f) { fclose(f); }
}

static int connect_bounded(const char *ip, uint16_t port, uint32_t mark,
                           char *reason, size_t cap) {
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int family;
    memset(&addr, 0, sizeof addr);
    struct sockaddr_in *a4 = (struct sockaddr_in *)&addr;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&addr;
    if (inet_pton(AF_INET, ip, &a4->sin_addr) == 1) {
        family = AF_INET; a4->sin_family = AF_INET;
        a4->sin_port = htons(port); addrlen = sizeof *a4;
    } else if (inet_pton(AF_INET6, ip, &a6->sin6_addr) == 1) {
        family = AF_INET6; a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port); addrlen = sizeof *a6;
    } else {
        snprintf(reason, cap, "адрес \"%s\" не разбирается", ip);
        return -1;
    }
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) { snprintf(reason, cap, "сокет: %s", strerror(errno)); return -1; }
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    if (mark != 0 && d2k_mark_hook(fd, mark) != 0) {
        /* Метка не поставилась — проба пойдёт ПО ОБЩИМ ПРАВИЛАМ, то есть
           через уже поставленный план. Это меряло бы работу плана, а не линию,
           и молча так делать нельзя. */
        snprintf(reason, cap, "метка 0x%x не поставилась: %s", (unsigned)mark, strerror(errno));
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        snprintf(reason, cap, "неблокирующий режим: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, addrlen) != 0) {
        if (errno != EINPROGRESS) {
            snprintf(reason, cap, "нет TCP: %s", strerror(errno));
            close(fd);
            return -1;
        }
        struct pollfd p;
        p.fd = fd; p.events = POLLOUT; p.revents = 0;
        if (poll(&p, 1, CONNECT_MS) <= 0) {
            snprintf(reason, cap, "нет TCP: не подключились за %d мс", CONNECT_MS);
            close(fd);
            return -1;
        }
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0 || soerr != 0) {
            snprintf(reason, cap, "нет TCP: %s", strerror(soerr ? soerr : errno));
            close(fd);
            return -1;
        }
    }
    (void)fcntl(fd, F_SETFL, flags);
    return fd;
}

/* Читает заголовки ответа до пустой строки. 0 — прочитано, -1 — обрыв. */
static int drain_head_tls(d2k_tls *t, d2k_tls12 *t12, int wait_ms, char *reason, size_t cap) {
    char line[4096];
    size_t n = 0;
    int seen_cr = 0;
    int64_t deadline = now_ms() + wait_ms;
    for (;;) {
        int64_t left = deadline - now_ms();
        if (left <= 0) { snprintf(reason, cap, "ответа нет"); return -1; }
        uint8_t c;
        long r = t12 ? d2k_tls12_read(t12, &c, 1, (int)left, reason, cap)
                     : d2k_tls_read(t, &c, 1, (int)left, reason, cap);
        if (r <= 0) {
            if (r == 0) { snprintf(reason, cap, "соединение закрыто"); }
            return -1;
        }
        if (c == '\n') {
            if (n == 0 || (n == 1 && seen_cr)) { return 0; } /* пустая строка */
            n = 0;
            seen_cr = 0;
            continue;
        }
        seen_cr = (c == '\r');
        if (n + 1 < sizeof line) { line[n++] = (char)c; }
    }
}

static int drain_head_plain(int fd, int wait_ms, char *reason, size_t cap) {
    size_t n = 0;
    int seen_cr = 0;
    int64_t deadline = now_ms() + wait_ms;
    for (;;) {
        if (now_ms() >= deadline) { snprintf(reason, cap, "ответа нет"); return -1; }
        struct pollfd p;
        p.fd = fd; p.events = POLLIN; p.revents = 0;
        int pr = poll(&p, 1, (int)(deadline - now_ms()));
        if (pr <= 0) { snprintf(reason, cap, "ответа нет"); return -1; }
        uint8_t c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r <= 0) {
            snprintf(reason, cap, r == 0 ? "соединение закрыто" : "чтение: %s", strerror(errno));
            return -1;
        }
        if (c == '\n') {
            if (n == 0 || (n == 1 && seen_cr)) { return 0; }
            n = 0; seen_cr = 0;
            continue;
        }
        seen_cr = (c == '\r');
        n++;
    }
}

/* ДРУГОЙ ПУБЛИЧНЫЙ ПУТЬ ТОГО ЖЕ ИМЕНИ, КОГДА МЕРИТЬ БЫЛО НЕЧЕМ.
   Поле 12.10.2026: на «/» style.sndcdn.com отдаёт завершённый 403 с телом 243
   байта, api-v2.soundcloud.com — 401 с пустым телом (то же и с VPS: так
   отвечает сам сервер, это не блок), а НАСТОЯЩИЙ ресурс того же имени
   режется — /css/soehne-*.css: 301328 байт с VPS против 15985 с линии.

   РАЗМЕР РЕСУРСА ЗАРАНЕЕ НЕИЗВЕСТЕН: подсказка даёт только путь, поэтому
   «обещает объём больше полосы» по ней заявить нельзя — объём выясняет само
   измерение. Условие повтора — не обещанный объём, а то, что мерить было
   нечем: ответ ЗАВЕРШЁН и меньше полосы, то есть про обрыв не сказал ничего.

   Имя подсказки обязано совпасть с предъявляемым SNI: адрес и имя у зонда
   свои, и чужой хост мы спросили бы не у того сервера; цель из подсказки не
   выдумывается. Путь проверяет тот же строгий d2k_resource_path_ok — только
   публичный .css, без запросов и токенов. Путь, который только что мерили,
   пропускаем: повторять его нечем. */
static int resource_retry_path(const d2k_ver_result *a, const char *sni,
                               const char *path, char *out, size_t cap) {
    size_t n = a->n_resources > D2K_RESOURCE_COUNT ? D2K_RESOURCE_COUNT : a->n_resources;
    for (size_t i = 0; i < n; i++) {
        const d2k_resource *r = &a->resources[i];
        if (!r->host[0] || strcasecmp(r->host, sni) != 0) { continue; }
        if (!d2k_resource_path_ok(r->path)) { continue; }
        if (path && !strcmp(path, r->path)) { continue; }
        if (strlen(r->path) >= cap) { continue; }
        snprintf(out, cap, "%s", r->path);
        return 1;
    }
    return 0;
}

/* Повторяем один и тот же запрос, если TLS согласован, а HTTP-ответ ещё не
   дал измеримых данных. Настоящий частичный ответ не повторяем: его измеряют
   парой ниже. */
static d2k_ver_result rx_probe(const char *ip, uint16_t port, const char *sni,
                               size_t hello_wire, int tls12, int encoding,
                               uint32_t mark, const char *path) {
    d2k_ver_result r = d2k_verify_probe_path_on(-1, ip, port, sni, 6000,
                                                hello_wire, tls12, encoding, mark, path);
    int early = r.status >= 200 && r.status < 300 && !r.body_complete &&
                r.body_bytes < (uint64_t)D2K_VOL_MIN_KB * 1024;
    if ((r.status == 0 || early) && r.level == D2K_VER_HANDSHAKE && r.name_ok == 1 &&
        (r.negotiated_tls == 0x0303 || r.negotiated_tls == 0x0304) &&
        !r.local_limit && !d2k_volume_rx_partial(&r)) {
        d2k_verify_close(&r);
        nap_ms(RESPONSE_PROBE_GAP_MS);
        r = d2k_verify_probe_path_on(-1, ip, port, sni, 6000,
                                     hello_wire, tls12, encoding, mark, path);
    }
    return r;
}

/* Входящее измерение — другой вопрос, чем лестница исходящих HEAD выше.
   Ищем воспроизводимую асимметрию: два identity-ответа с одним framing видом
   обрываются на близком объёме, а gzip-представление той же страницы доходит
   до конца. Chunked ответы допустимы: у них полного размера заранее нет.
   Ответ без Content-Length и без chunked framing не классифицируем — там
   локальный timeout нельзя отличить от конца/медленной отдачи. Все сокеты
   помечены measure_mark и не проходят через пробуемый план.

   Возвращает 1, только если мерить было нечем (ответ завершён и меньше
   полосы) И тот же ответ назвал другой публичный путь этого имени: он
   копируется в retry. Повтором распоряжается probe_response_volume. */
static int measure_response_volume(d2k_vol_result *res, const char *ip,
                                   uint16_t port, const char *sni, int tls12,
                                   size_t hello_wire, uint32_t mark, const char *path,
                                   char *retry, size_t retry_cap) {
    if (!res || !ip || !sni || !sni[0] || port == 80) { return 0; }
    d2k_ver_result a = rx_probe(ip, port, sni, hello_wire, tls12, 0, mark, path);
    res->rx_tls_unavailable = a.level == D2K_VER_TRANSPORT && a.status == 0;
    if (a.body_complete && a.status >= 200 && a.status < 300 &&
        a.http_outcome != D2K_HTTP_BLOCKED && a.http_outcome != D2K_HTTP_LEGAL_DENIAL) {
        res->rx_direct_complete = a.level == D2K_VER_APPLICATION;
        memcpy(res->resources, a.resources, sizeof res->resources);
        res->n_resources = a.n_resources;
    }
    snprintf(res->rx_reason, sizeof res->rx_reason,
             "identity-1 HTTP %d, тело %llu/%llu, complete=%d, TLS=%04x wire=%llu missing=%u: %.60s",
             a.status, (unsigned long long)a.body_bytes,
             (unsigned long long)a.body_expected, a.body_complete, a.negotiated_tls,
             (unsigned long long)a.rx_tls_wire_bytes, a.rx_tls_record_missing, a.reason);
    if (!d2k_volume_rx_partial(&a)) {
        if ((a.status == 0 || !a.body_complete) && a.level == D2K_VER_HANDSHAKE &&
            a.name_ok == 1 && (a.negotiated_tls == 0x0303 || a.negotiated_tls == 0x0304) &&
            !res->rx_direct_complete && !res->rx_tls_unavailable && !a.local_limit) {
            res->rx_unmeasured = 1;
        }
        /* ЗАВЕРШЁННЫЙ ОТВЕТ МЕНЬШЕ ПОЛОСЫ — БЮДЖЕТ НЕ ПРОВЕРЕН. Отличаем
           «обрыв не воспроизвёлся» от «мерить было нечем»: ответ дошёл до
           конца, но до D2K_VOL_MIN_KB ему не хватило объёма, поэтому про
           обрыв он не говорит ничего. Страница отказа доступа (401/403) и
           просто короткий документ попадают сюда одинаково. */
        if (a.status > 0 && a.body_complete &&
            a.body_bytes < (uint64_t)D2K_VOL_MIN_KB * 1024) {
            res->rx_short = 1;
            res->rx_short_bytes = a.body_bytes;
            if (retry && retry_cap &&
                resource_retry_path(&a, sni, path, retry, retry_cap)) {
                d2k_verify_close(&a);
                return 1;
            }
        }
        d2k_verify_close(&a);
        return 0;
    }
    if (rx_wire_partial(&a)) res->rx_partial_wire_bytes = a.rx_tls_wire_bytes;
    else res->rx_partial_bytes = a.body_bytes;
    nap_ms(RESPONSE_PROBE_GAP_MS);
    d2k_ver_result b = rx_probe(ip, port, sni, hello_wire, tls12, 0, mark, path);
    snprintf(res->rx_reason, sizeof res->rx_reason,
             "identity-1 partial=%llu/%llu TLS=%04x wire=%llu missing=%u; "
             "identity-2 HTTP %d body=%llu complete=%d TLS=%04x wire=%llu missing=%u: %.40s",
             (unsigned long long)a.body_bytes, (unsigned long long)a.body_expected,
             a.negotiated_tls, (unsigned long long)a.rx_tls_wire_bytes, a.rx_tls_record_missing,
             b.status, (unsigned long long)b.body_bytes, b.body_complete,
             b.negotiated_tls, (unsigned long long)b.rx_tls_wire_bytes, b.rx_tls_record_missing,
             b.reason);
    const char *settled_by_third = "";
    if (!d2k_volume_rx_pair_agrees(&a, &b)) {
        if (!d2k_volume_rx_needs_repeat(&a, &b)) {
            d2k_verify_close(&a);
            d2k_verify_close(&b);
            return 0;
        }
        /* Повтор дошёл до конца, пройдя полосу: измерения РАСХОДЯТСЯ. Судит
           третий identity-прогон того же домена — см. d2k_volume_rx_needs_repeat. */
        nap_ms(RESPONSE_PROBE_GAP_MS);
        d2k_ver_result c = rx_probe(ip, port, sni, hello_wire, tls12, 0, mark, path);
        int agreed = d2k_volume_rx_pair_agrees(&a, &c);
        snprintf(res->rx_reason, sizeof res->rx_reason,
                 "identity-1 partial=%llu wire=%llu; identity-2 HTTP %d body=%llu "
                 "дошёл до конца; identity-3 HTTP %d body=%llu wire=%llu missing=%u: "
                 "обрыв подтверждён=%d",
                 (unsigned long long)a.body_bytes,
                 (unsigned long long)a.rx_tls_wire_bytes, b.status,
                 (unsigned long long)b.body_bytes, c.status,
                 (unsigned long long)c.body_bytes,
                 (unsigned long long)c.rx_tls_wire_bytes,
                 c.rx_tls_record_missing, agreed);
        d2k_verify_close(&b);
        if (!agreed) {
            d2k_verify_close(&a);
            d2k_verify_close(&c);
            return 0;
        }
        b = c;
        /* Журнал обязан показывать, что пару решило ТРЕТЬЕ измерение, иначе
           строку gzip-шага не отличить от сошедшейся с первого раза пары. */
        settled_by_third = "; пару решил identity-3";
    }
    nap_ms(RESPONSE_PROBE_GAP_MS);
    d2k_ver_result gz = rx_probe(ip, port, sni, hello_wire, tls12, 1, mark, path);
    snprintf(res->rx_reason, sizeof res->rx_reason,
             "identity %llu/%llu (пакетов %u/%u); gzip HTTP %d, тело %llu, complete=%d, "
             "encoding=%d, пакетов %u; TLS RX wire=%llu/%llu/%llu missing=%u/%u/%u%s",
             (unsigned long long)a.body_bytes, (unsigned long long)b.body_bytes,
             a.data_packets, b.data_packets,
             gz.status, (unsigned long long)gz.body_bytes, gz.body_complete, gz.body_encoding,
             gz.data_packets, (unsigned long long)a.rx_tls_wire_bytes,
             (unsigned long long)b.rx_tls_wire_bytes, (unsigned long long)gz.rx_tls_wire_bytes,
             a.rx_tls_record_missing, b.rx_tls_record_missing, gz.rx_tls_record_missing,
             settled_by_third);
    (void)d2k_volume_rx_evidence(&a, &b, &gz, res);
    /* ПУТЬ ИЗМЕРЕНИЯ ИДЁТ НАВЕРХ ПОЛЕМ, А НЕ ТОЛЬКО СТРОКОЙ ЖУРНАЛА. Обрыв
       доказан на том пути, который спрашивал ЭТОТ замер (у повтора он свой —
       из подсказки): кандидата и следующий эпизод надо отправить туда же,
       иначе «/» того же хоста отдаст короткий 403 и подтвердить план объёмом
       будет нечем. Умолчательный «/» не называем — его знает вызывающий. */
    if (res->rx_cut && path && path[0]) {
        snprintf(res->measured_path, sizeof res->measured_path, "%s", path);
    }
    d2k_verify_close(&a);
    d2k_verify_close(&b);
    d2k_verify_close(&gz);
    return 0;
}

/* ОДИН ПОВТОР ПО НАЗВАННОЙ ПРИЧИНЕ: на первом пути мерить было нечем. Не
   лестница — повторное измерение само либо входит в полосу, либо честно
   возвращает тот же непроверенный бюджет; третий путь спрашивать не о чем,
   это был бы перебор вместо замера. */
static void probe_response_volume(d2k_vol_result *res, const char *ip,
                                  uint16_t port, const char *sni, int tls12,
                                  size_t hello_wire, uint32_t mark, const char *path) {
    char retry[sizeof ((d2k_resource *)0)->path];
    retry[0] = '\0';
    if (!measure_response_volume(res, ip, port, sni, tls12, hello_wire, mark, path,
                                 retry, sizeof retry)) { return; }
    uint64_t was = res->rx_short_bytes;
    res->rx_short = 0;
    res->rx_short_bytes = 0;
    res->rx_unmeasured = 0;
    nap_ms(RESPONSE_PROBE_GAP_MS);
    (void)measure_response_volume(res, ip, port, sni, tls12, hello_wire, mark, retry,
                                  NULL, 0);
    /* ПОВТОР НЕ ДОШЁЛ ДО TLS — БЮДЖЕТ ТАК И НЕ ПРОВЕРЕН. Непроверенный
       бюджет первого ответа остаётся в силе: он сказал правду о себе, а
       повтор не сказал ничего. Без этого один неудавшийся повтор отменял бы
       честный rx_short и возвращался ложным «обрыв не воспроизвёлся».
       Завершённый ответ повтора ВЫШЕ полосы — наоборот, настоящее
       отрицательное измерение: его не подменяем. */
    if ((res->rx_tls_unavailable || res->rx_unmeasured) &&
        !res->rx_cut && !res->rx_short) {
        res->rx_short = 1;
        res->rx_short_bytes = was;
        res->rx_unmeasured = 0;
    }
    /* Журнал обязан называть путь повтора: иначе обрыв прочитают как обрыв
       на «/», которого там не было. Причина складывается в два приёма и с
       явными границами — целиком она в буфер не влезает (gcc ловит это как
       format-truncation, цель cross). */
    char lead[104], measured[sizeof res->rx_reason];
    snprintf(lead, sizeof lead, "повтор по %.40s (было %llu байт)",
             retry, (unsigned long long)was);
    snprintf(measured, sizeof measured, "%s", res->rx_reason);
    snprintf(res->rx_reason, sizeof res->rx_reason, "%.102s: %.150s", lead, measured);
}

d2k_vol_result d2k_volume_probe_path(const char *ip, uint16_t port, const char *sni,
                                int plain, int tls12, size_t hello_wire,
                                uint32_t mark, const char *path) {
    d2k_vol_result res;
    memset(&res, 0, sizeof res);
    res.verdict = D2K_VOL_UNREACHABLE;
    snprintf(res.reason, sizeof res.reason, "проба не начиналась");
    if (!ip || !ip[0]) {
        snprintf(res.reason, sizeof res.reason, "адрес цели не задан");
        return res;
    }

    int64_t started = now_ms();
    int fd = connect_bounded(ip, port, mark, res.reason, sizeof res.reason);
    if (fd < 0) { return res; }

    d2k_tls *tls = NULL;
    d2k_tls12 *tls_legacy = NULL;
    if (!plain) {
        char err[160];
        const char *name = (sni && sni[0]) ? sni : NULL;
        int handshake = tls12
            ? d2k_tls12_connect(fd, name, HANDSHAKE_MS, hello_wire,
                                &tls_legacy, err, sizeof err)
            : d2k_tls_connect(fd, name, HANDSHAKE_MS, hello_wire,
                              &tls, err, sizeof err);
        if (handshake != 0) {
            /* Причина обрезается по месту, а не тянет за собой размер буфера:
               «нет TLS: » плюс хвост — читателю нужна суть, а не полный текст
               чужой ошибки (gcc ловит это как format-truncation, цель cross). */
            snprintf(res.reason, sizeof res.reason, "нет TLS: %.140s", err);
            close(fd);
            /* TX handshake failure is not a result of the independent
               GET-body measurement, which uses the client's own context. */
            probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark, path);
            return res;
        }
    }
    res.rtt_ms = (int)(now_ms() - started);

    const char *host = (sni && sni[0]) ? sni : ip;
    char pad[D2K_VOL_CHUNK + 1];
    fill_pad(pad, D2K_VOL_CHUNK);
    pad[D2K_VOL_CHUNK] = '\0';

    /* Пока RTT не измерен на самом запросе — ждём по потолку. */
    int read_timeout = READ_MAX_MS;

    for (int i = 0; i < D2K_VOL_STEPS; i++) {
        char req[D2K_VOL_CHUNK + 512];
        int n;
        if (i == 0) {
            n = snprintf(req, sizeof req,
                         "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                         "Connection: keep-alive\r\n\r\n", host);
        } else {
            n = snprintf(req, sizeof req,
                         "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                         "Connection: keep-alive\r\nX-Pad: %s\r\n\r\n", host, pad);
        }
        if (n <= 0 || (size_t)n >= sizeof req) {
            snprintf(res.reason, sizeof res.reason, "запрос не поместился");
            if (tls) { d2k_tls_free(tls); }
            if (tls_legacy) { d2k_tls12_free(tls_legacy); }
            close(fd);
            if (!plain) {
                probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark, path);
            }
            return res;
        }

        int sent_kb = i * D2K_VOL_CHUNK / 1024;
        int64_t req_start = now_ms();
        char err[160];
        int bad = 0;
        if (tls || tls_legacy) {
            int written = tls_legacy
                ? d2k_tls12_write(tls_legacy, (const uint8_t *)req, (size_t)n, err, sizeof err)
                : d2k_tls_write(tls, (const uint8_t *)req, (size_t)n, err, sizeof err);
            if (written != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                bad = 1;
            } else if (drain_head_tls(tls, tls_legacy, read_timeout, err, sizeof err) != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                bad = 1;
            }
        } else {
            ssize_t w = send(fd, req, (size_t)n, 0);
            if (w != n) {
                snprintf(res.reason, sizeof res.reason, "запрос не ушёл: %s", strerror(errno));
                bad = 1;
            } else if (drain_head_plain(fd, read_timeout, err, sizeof err) != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                bad = 1;
            }
        }
        if (bad) {
            res.at_kb = sent_kb;
            if (i == 0) {
                /* Умерли на первом же запросе — мишень недоступна, а не блок. */
                res.verdict = D2K_VOL_UNREACHABLE;
            } else if (sent_kb >= D2K_VOL_MIN_KB) {
                res.verdict = D2K_VOL_CUT;
            } else {
                res.verdict = D2K_VOL_SHORT;
            }
            if (tls) { d2k_tls_free(tls); }
            if (tls_legacy) { d2k_tls12_free(tls_legacy); }
            close(fd);
            if (!plain) {
                probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark, path);
            }
            return res;
        }
        if (i == 0) {
            /* RTT известен — дальше ждём втрое дольше него, в разумных
               границах: «нет ответа» распознаётся втрое быстрее прежнего. */
            read_timeout = clamp_ms((now_ms() - req_start) * 3, READ_MIN_MS, READ_MAX_MS);
        }
        nap_ms(CHUNK_DELAY_MS);
    }

    res.verdict = D2K_VOL_PASSED;
    res.at_kb = D2K_VOL_STEPS * D2K_VOL_CHUNK / 1024;
    snprintf(res.reason, sizeof res.reason, "лестница пройдена целиком");
    if (tls) { d2k_tls_free(tls); }
    if (tls_legacy) { d2k_tls12_free(tls_legacy); }
    close(fd);
    if (!plain) {
        probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark, path);
    }
    return res;
}

d2k_vol_result d2k_volume_probe(const char *ip, uint16_t port, const char *sni,
    int plain, int tls12, size_t hello_wire, uint32_t mark) {
    return d2k_volume_probe_path(ip, port, sni, plain, tls12, hello_wire, mark, NULL);
}
