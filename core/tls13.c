/* tls13.c — минимальный клиент TLS 1.3. См. d2k_tls13.h: зачем он есть и чего
 * он намеренно не делает.
 *
 * КЛЮЧЕВОЕ РАСПИСАНИЕ (RFC 8446 §7.1) целиком:
 *
 *   early   = HKDF-Extract(salt=0,      IKM=0)
 *   derived = Derive-Secret(early,      "derived", "")
 *   hs      = HKDF-Extract(salt=derived, IKM=ECDHE)
 *   c_hs    = Derive-Secret(hs, "c hs traffic", CH..SH)
 *   s_hs    = Derive-Secret(hs, "s hs traffic", CH..SH)
 *   derived2= Derive-Secret(hs,         "derived", "")
 *   master  = HKDF-Extract(salt=derived2, IKM=0)
 *   c_ap    = Derive-Secret(master, "c ap traffic", CH..server Finished)
 *   s_ap    = Derive-Secret(master, "s ap traffic", CH..server Finished)
 *
 * Транскрипт — SHA-256 по СООБЩЕНИЯМ рукопожатия (без заголовков записей и без
 * шифрования), и порядок в нём тот, в каком они пришли на провод.
 *
 * ЧТО МЫ НЕ ПРОВЕРЯЕМ И ПОЧЕМУ ЭТО НАЗВАНО ЗДЕСЬ, А НЕ СКРЫТО: подпись
 * сертификата, цепочку доверия, имя в сертификате и Finished сервера. Сессия
 * служит ОДНОЙ цели — протолкнуть по линии десятки килобайт и посмотреть, на
 * каком объёме её оборвут. Подмена сервера этому измерению не мешает: коробка
 * на линии и есть предмет измерения. Проверять Finished было бы дёшево, но
 * бессмысленно без проверки подписи, а та требует X.509 и цепочки доверия —
 * это отдельный модуль, которого у проекта нет и который эта задача не
 * оправдывает.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_crypto.h"
#include "d2k_tls13.h"
#include "d2k_tls13core.h"
#include "d2k_tls12.h"
#include "d2k_diagnostics.h"

#define REC_CCS       20
#define REC_ALERT     21
#define REC_HANDSHAKE 22
#define REC_APPDATA   23

#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2
#define HS_FINISHED     20
#define HS_CERTIFICATE  11

/* Предел одной записи TLS (RFC 8446 §5.1: 2^14 открытого текста плюс накладные). */
#define REC_MAX 18432

struct d2k_tls {
    int      fd;
    uint64_t rx_wire_bytes;
    uint32_t rx_record_missing;
    uint8_t  c_key[16], c_iv[12];
    uint8_t  s_key[16], s_iv[12];
    uint64_t c_seq, s_seq;
    /* Каждый параллельный зонд владеет своим транскриптом. Не static и не
       большой буфер на стеке рабочего потока роутера. */
    uint8_t  transcript[REC_MAX * 4];
    /* Сверка имени из сертификата сервера: 1 совпало, 0 не совпало,
       -1 сказать нечего. См. большой комментарий у cert_name_ok. */
    int      peer_name;
    int      ech_accepted;
    uint8_t  raw[REC_MAX], wire[REC_MAX + 5];

    /* Остаток прочитанного, ещё не отданный вызывающему. */
    uint8_t  plain[REC_MAX];
    size_t   plain_len, plain_off;
    /* Сервер выбрал TLS 1.2 на наше приветствие с обеими версиями: сессию
       ведёт клиент 1.2, чтение и запись идут через него. */
    d2k_tls12 *v12;
    int diag_memory_tracked;
};
static void tls_dispose(d2k_tls *t){
    if(t){d2k_diag_memory_release(D2K_DIAG_MEM_TLS13_SESSION,sizeof *t,t->diag_memory_tracked);free(t);}
}

static void say(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) { return; }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Читает ровно n байт с потолком по времени. 0 — прочитано, -1 — отказ. */
static int read_exact(d2k_tls *t, uint8_t *buf, size_t n, int body, int64_t deadline,
                      char *err, size_t errcap) {
    size_t got = 0;
    t->rx_record_missing = body ? (uint32_t)n : 0;
    while (got < n) {
        int64_t left = deadline - now_ms();
        if (left <= 0) {
            say(err, errcap, "не дождались %zu байт за отведённое время", n - got);
            return -1;
        }
        struct pollfd p;
        p.fd = t->fd; p.events = POLLIN; p.revents = 0;
        int pr = poll(&p, 1, (int)(left > 1000 ? 1000 : left));
        if (pr < 0) {
            if (errno == EINTR) { continue; }
            say(err, errcap, "poll: %s", strerror(errno));
            return -1;
        }
        if (pr == 0) { continue; }
        ssize_t r = recv(t->fd, buf + got, n - got, 0);
        if (r == 0) {
            say(err, errcap, "соединение закрыто на %zu-м байте из %zu", got, n);
            return -1;
        }
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) { continue; }
            say(err, errcap, "чтение: %s", strerror(errno));
            return -1;
        }
        got += (size_t)r;
        t->rx_wire_bytes += (uint64_t)r;
        if(body)t->rx_record_missing=(uint32_t)(n-got);
    }
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t n, char *err, size_t errcap) {
    size_t sent = 0;
    while (sent < n) {
#ifdef MSG_NOSIGNAL
        ssize_t w = send(fd, buf + sent, n - sent, MSG_NOSIGNAL);
#else
        ssize_t w = send(fd, buf + sent, n - sent, 0);
#endif
        if (w <= 0) {
            if (w < 0 && (errno == EINTR || errno == EAGAIN)) { continue; }
            say(err, errcap, "запись: %s", strerror(errno));
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/* Случайные байты из ядра. Своего генератора не заводим: 32 байта на сессию —
   не та частота, ради которой стоит держать собственный поток случайности, а
   предсказуемый client_random сделал бы сессию воспроизводимой для того, кто
   слушает линию. */
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }

/* --- работа с записями --------------------------------------------------- */

static void nonce_of(const uint8_t iv[12], uint64_t seq, uint8_t out[12]) {
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++) {
        out[11 - i] ^= (uint8_t)(seq >> (8 * i));
    }
}

/* Читает ОДНУ запись. type/payload/len — наружу. Для зашифрованных записей
   снимает защиту и отдаёт ВНУТРЕННИЙ тип (RFC 8446 §5.2: настоящий тип —
   последний ненулевой байт открытого текста). */
static int read_record(d2k_tls *t, int encrypted, uint8_t *type,
                       uint8_t *payload, size_t cap, size_t *len,
                       int64_t deadline, char *err, size_t errcap) {
    uint8_t hdr[5];
    if (read_exact(t, hdr, 5, 0, deadline, err, errcap) != 0) { return -1; }
    /* На TLS/443 сетевой узел иногда отвечает открытым HTTP (на Rutracker
       Cloudflare прислал HTTP/1.1 400). Не интерпретировать P/ из HTTP/ как
       TLS length=20527: это другой протокол, а не oversized TLS record. */
    if (memcmp(hdr, "HTTP/", 5) == 0) {
        say(err, errcap,
            "не TLS: открытый HTTP-ответ вместо TLS (заголовок %02x %02x %02x %02x %02x)",
            hdr[0], hdr[1], hdr[2], hdr[3], hdr[4]);
        return -1;
    }
    size_t rlen = get16(hdr + 3);
    if (rlen == 0 || rlen > REC_MAX) {
        say(err, errcap,
            "не TLS-заголовок %02x %02x %02x %02x %02x: длина %zu вне предела",
            hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], rlen);
        return -1;
    }
    uint8_t *raw = t->raw;
    if (read_exact(t, raw, rlen, 1, deadline, err, errcap) != 0) { return -1; }

    if (hdr[0] == REC_CCS) {
        /* Смена шифра в TLS 1.3 — пустая формальность совместимости
           (RFC 8446 §5), содержимого не несёт и в транскрипт не идёт. */
        *type = REC_CCS;
        *len = 0;
        return 0;
    }
    if (!encrypted || hdr[0] != REC_APPDATA) {
        if (rlen > cap) { say(err, errcap, "запись не помещается"); return -1; }
        memcpy(payload, raw, rlen);
        *type = hdr[0];
        *len = rlen;
        return 0;
    }

    uint8_t nonce[12];
    nonce_of(t->s_iv, t->s_seq, nonce);
    if (rlen < 17 || rlen - 16 > cap) {
        say(err, errcap, "зашифрованная запись длиной %zu не разбирается", rlen);
        return -1;
    }
    if (d2k_aes128_gcm_decrypt(t->s_key, nonce, hdr, 5, raw, rlen, payload) != 0) {
        say(err, errcap, "тег записи не сошёлся (номер %llu)", (unsigned long long)t->s_seq);
        return -1;
    }
    t->s_seq++;
    size_t n = rlen - 16;
    while (n > 0 && payload[n - 1] == 0) { n--; }   /* набивка нулями, §5.2 */
    if (n == 0) {
        say(err, errcap, "запись без внутреннего типа");
        return -1;
    }
    *type = payload[n - 1];
    *len = n - 1;
    return 0;
}

static int write_record(d2k_tls *t, uint8_t type, const uint8_t *data, size_t n,
                        char *err, size_t errcap) {
    if (n + 1 + 16 > REC_MAX) { say(err, errcap, "запись длиннее предела"); return -1; }
    uint8_t *buf = t->wire;
    uint8_t inner[REC_MAX];
    memcpy(inner, data, n);
    inner[n] = type;                               /* настоящий тип внутри, §5.2 */

    buf[0] = REC_APPDATA;                          /* снаружи всегда 23, §5.2 */
    put16(buf + 1, 0x0303);
    put16(buf + 3, (uint16_t)(n + 1 + 16));

    uint8_t nonce[12];
    nonce_of(t->c_iv, t->c_seq, nonce);
    uint8_t tag[16];
    if (d2k_aes128_gcm_encrypt(t->c_key, nonce, buf, 5, inner, n + 1, buf + 5, tag) != 0) {
        say(err, errcap, "не зашифровалось");
        return -1;
    }
    memcpy(buf + 5 + n + 1, tag, 16);
    t->c_seq++;
    return write_all(t->fd, buf, 5 + n + 1 + 16, err, errcap);
}

static int traffic_keys(const uint8_t secret[32], uint8_t key[16], uint8_t iv[12]) {
    if (d2k_hkdf_expand_label(secret, "key", key, 16) != 0) { return -1; }
    return d2k_hkdf_expand_label(secret, "iv", iv, 12);
}

static int tls_connect_internal(int fd, const char *sni, int deadline_ms,
    size_t want_wire, const d2k_ech_config *ech,
    int client_alpn, const uint8_t *alpn_list, size_t alpn_len,
    d2k_tls **out, char *err, size_t errcap) {
    if (err && errcap) { err[0] = '\0'; }
    if (fd < 0 || !out) { say(err, errcap, "нечем поднимать сессию"); return -1; }
    *out = NULL;
    int64_t deadline = now_ms() + (deadline_ms > 0 ? deadline_ms : 8000);

    uint8_t priv[32], pub[32], rnd[32];
    if (d2k_t13_random(priv, 32) != 0 || d2k_t13_random(rnd, 32) != 0) {
        say(err, errcap, "нет случайности: /dev/urandom недоступен");
        return -1;
    }
    if (d2k_x25519_base(pub, priv) != 0) {
        say(err, errcap, "открытый ключ не посчитался");
        return -1;
    }

    /* Транскрипт: сообщения рукопожатия подряд, без заголовков записей. */
    d2k_tls *t = calloc(1, sizeof *t);
    if (!t) { d2k_diag_memory_alloc_failure(D2K_DIAG_MEM_TLS13_SESSION);say(err, errcap, "не хватило памяти"); return -1; }
    t->diag_memory_tracked=d2k_diag_memory_acquire(D2K_DIAG_MEM_TLS13_SESSION,sizeof *t);
    t->fd = fd;
    t->peer_name = -1;   /* пока не смотрели — «сказать нечего», а не «нет» */
    uint8_t *tr = t->transcript;
    size_t tr_len = 0;

    /* Две с половиной тысячи, а не тысяча: приветствие теперь добивается до
       длины клиентского, а снимок приветствия с провода бывает до 2048 байт
       (d2k_ev.shape). */
    uint8_t ch[4096], inner[2048];
    size_t inner_len = 0;
    d2k_t13_ch_opts cho;
    memset(&cho, 0, sizeof cho);
    cho.sni = sni;
    cho.pub = pub;
    cho.random = rnd;
    cho.session_id_len = 32;      /* совместимость: так ходит браузер по TCP */
    /* ALPN — ФОРМА КЛИЕНТА, а не удобная фиксированная (задача 37, F3).
       Прежде здесь всегда стоял http/1.1, и сервер не-HTTP протокола (MQTT
       поверх TLS) отвечал тревогой 120 на КАЖДОЕ испытание: план пропускал
       приветствие, а зонд спрашивал не тот протокол. Без client_alpn —
       прежний HTTP-зонд. */
    if (client_alpn) {
        cho.alpn = NULL;
        cho.alpn_wire = alpn_len ? alpn_list : NULL;
        cho.alpn_wire_len = alpn_len;
    } else {
        cho.alpn = "http/1.1";
    }
    /* Добивка у ядра считается БЕЗ заголовка записи — его тут пять байт. */
    cho.pad_to = want_wire > 5 ? want_wire - 5 : 0;
    /* И 1.3, и 1.2, как браузер (поле 07.10.2026: сервера «только 1.2»
       отвечали тревогой 70). ECH — только 1.3 по определению. */
    cho.offer_tls12 = ech == NULL;
    size_t ch_len;
    if (ech) {
        uint8_t hpke_priv[32], outer_random[32];
        if (d2k_t13_random(hpke_priv, 32) || d2k_t13_random(outer_random, 32)) {
            say(err, errcap, "нет случайности для ECH"); tls_dispose(t); return -1;
        }
        ch_len = d2k_t13_ech_build(&cho, ech, hpke_priv, outer_random,
            ch, sizeof ch, inner, sizeof inner, &inner_len);
        memset(hpke_priv, 0, sizeof hpke_priv);
    } else ch_len = d2k_t13_ch_build(&cho, ch, sizeof ch);
    if (ch_len == 0) { say(err, errcap, "приветствие не собралось"); tls_dispose(t); return -1; }

    uint8_t rec[5 + sizeof ch];
    rec[0] = REC_HANDSHAKE;
    put16(rec + 1, 0x0301);                        /* legacy_record_version */
    put16(rec + 3, (uint16_t)ch_len);
    memcpy(rec + 5, ch, ch_len);
    if (write_all(fd, rec, 5 + ch_len, err, errcap) != 0) { tls_dispose(t); return -1; }
    memcpy(tr, ech ? inner : ch, ech ? inner_len : ch_len);
    tr_len = ech ? inner_len : ch_len;

    /* ServerHello — открытым текстом. */
    uint8_t sh[REC_MAX];
    size_t sh_len = 0;
    uint8_t type = 0;
    for (;;) {
        if (read_record(t, 0, &type, sh, sizeof sh, &sh_len, deadline, err, errcap) != 0) {
            tls_dispose(t);
            return -1;
        }
        if (type == REC_CCS) { continue; }
        if (type == REC_ALERT) {
            say(err, errcap, "сервер прервал рукопожатие тревогой %u",
                sh_len >= 2 ? (unsigned)sh[1] : 0u);
            tls_dispose(t);
            return -1;
        }
        if (type != REC_HANDSHAKE || sh_len < 4 || sh[0] != HS_SERVER_HELLO) {
            say(err, errcap, "вместо ServerHello пришло другое (тип %u)", (unsigned)type);
            tls_dispose(t);
            return -1;
        }
        break;
    }
    if (!ech && d2k_t13_sh_version(sh, sh_len) == 0x0303) {
        /* Сервер выбрал 1.2: рукопожатие доводит клиент 1.2 с тем же
           приветствием и уже прочитанной записью сервера. */
        int64_t left = deadline - now_ms();
        d2k_tls12 *v = NULL;
        if (d2k_tls12_resume(fd, sni, left > 0 ? (int)left : 1, rnd, ch, ch_len,
                             sh, sh_len, &v, err, errcap) != 0) {
            tls_dispose(t);
            return -1;
        }
        t->v12 = v;
        t->peer_name = d2k_tls12_peer_name(v);
        *out = t;
        return 0;
    }
    if (ech && !d2k_t13_ech_accepted(inner, inner_len, sh, sh_len)) {
        say(err, errcap, "ECH не принят сервером: публичное имя не подтверждает origin");
        tls_dispose(t); return -1;
    }
    t->ech_accepted = ech != NULL;
    memcpy(tr + tr_len, sh, sh_len);
    tr_len += sh_len;

    const uint8_t *peer = NULL;
    if (d2k_t13_sh_parse(sh, sh_len, &peer, err, errcap) != 0) {
        tls_dispose(t);
        return -1;
    }

    uint8_t shared[32];
    if (d2k_x25519(shared, priv, peer) != 0) {
        say(err, errcap, "общий секрет не посчитался (точка малого порядка)");
        tls_dispose(t);
        return -1;
    }

    uint8_t hs[32], c_hs[32], s_hs[32];
    if (d2k_t13_schedule_hs(shared, tr, tr_len, c_hs, s_hs, hs) != 0 ||
        traffic_keys(c_hs, t->c_key, t->c_iv) != 0 ||
        traffic_keys(s_hs, t->s_key, t->s_iv) != 0) {
        say(err, errcap, "ключи рукопожатия не собрались"); tls_dispose(t); return -1;
    }
    t->c_seq = t->s_seq = 0;

    /* Флайт сервера: всё под ключами рукопожатия, до его Finished включительно.
       Содержимое не проверяем (см. шапку файла), но в транскрипт кладём — от
       него зависят прикладные ключи. */
    for (;;) {
        uint8_t msg[REC_MAX];
        size_t mlen = 0;
        if (read_record(t, 1, &type, msg, sizeof msg, &mlen, deadline, err, errcap) != 0) {
            tls_dispose(t);
            return -1;
        }
        if (type == REC_CCS) { continue; }
        if (type == REC_ALERT) {
            say(err, errcap, "сервер прервал рукопожатие тревогой %u",
                mlen >= 2 ? (unsigned)msg[1] : 0u);
            tls_dispose(t);
            return -1;
        }
        if (type != REC_HANDSHAKE) {
            say(err, errcap, "в рукопожатии запись типа %u", (unsigned)type);
            tls_dispose(t);
            return -1;
        }
        if (tr_len + mlen > sizeof t->transcript) {
            say(err, errcap, "транскрипт рукопожатия длиннее предела");
            tls_dispose(t);
            return -1;
        }
        memcpy(tr + tr_len, msg, mlen);
        tr_len += mlen;

        /* Одна запись может нести несколько сообщений — ищем Finished среди
           них по заголовкам, а не по первому байту записи. */
        int done = 0;
        size_t o = 0;
        uint8_t mt = 0;
        while (d2k_t13_flight_next(msg, mlen, &o, &mt, NULL, NULL)) {
            if (mt == D2K_T13_FINISHED) { done = 1; }
        }
        if (done) { break; }
    }

    if (ech) {
        size_t at = 0, previous = 0;
        uint8_t mt = 0, expected[32];
        const uint8_t *body = NULL;
        size_t blen = 0;
        int finished_ok = 0;
        while (d2k_t13_flight_next(tr, tr_len, &at, &mt, &body, &blen)) {
            if (mt == D2K_T13_FINISHED) {
                if (blen == 32 && !d2k_t13_finished_mac(s_hs, tr, previous, expected)) {
                    unsigned diff = 0;
                    for (size_t i = 0; i < 32; i++) diff |= body[i] ^ expected[i];
                    finished_ok = diff == 0;
                }
                break;
            }
            previous = at;
        }
        if (!finished_ok) {
            say(err, errcap, "ECH: серверный Finished не подтверждён"); tls_dispose(t); return -1;
        }
    }

    /* ИМЯ СЕРВЕРА — из транскрипта, а не из отдельной записи: сообщение
       рукопожатия вправе быть разрезано между записями, и разбор по одной
       записи нашёл бы половину сертификата. Транскрипт же собран подряд и
       без заголовков записей — по нему сообщения ходятся заголовками. */
    if (sni && sni[0]) {
        size_t o = 0;
        uint8_t mt = 0;
        const uint8_t *body = NULL;
        size_t blen = 0;
        while (d2k_t13_flight_next(tr, tr_len, &o, &mt, &body, &blen)) {
            if (mt == D2K_T13_CERTIFICATE) {
                t->peer_name = d2k_t13_cert_name_ok(body, blen, sni);
                break;
            }
        }
    }

    /* Прикладные ключи считаются от транскрипта ДО нашего Finished. */
    uint8_t c_ap[32], s_ap[32];
    if (d2k_t13_schedule_ap(hs, tr, tr_len, c_ap, s_ap) != 0) {
        say(err, errcap, "прикладные ключи не собрались"); tls_dispose(t); return -1;
    }

    /* Наш Finished — под ключами РУКОПОЖАТИЯ, поэтому шлём до смены ключей. */
    uint8_t verify[32];
    if (d2k_t13_finished_mac(c_hs, tr, tr_len, verify) != 0) {
        say(err, errcap, "ключ подтверждения не собрался"); tls_dispose(t); return -1;
    }
    uint8_t fin[4 + 32];
    fin[0] = D2K_T13_FINISHED; fin[1] = 0; fin[2] = 0; fin[3] = 32;
    memcpy(fin + 4, verify, 32);

    /* Пустая смена шифра перед Finished — совместимость со «средними ящиками»
       (RFC 8446 §D.4). Ровно то, что шлёт браузер; без неё часть сетевого
       оборудования рвёт сессию, и мы измеряли бы это вместо блока по объёму. */
    uint8_t ccs[6] = { REC_CCS, 0x03, 0x03, 0x00, 0x01, 0x01 };
    if (write_all(fd, ccs, sizeof ccs, err, errcap) != 0) { tls_dispose(t); return -1; }
    if (write_record(t, REC_HANDSHAKE, fin, sizeof fin, err, errcap) != 0) {
        tls_dispose(t);
        return -1;
    }

    /* Смена на прикладные ключи — в обе стороны, счётчики с нуля (§5.3). */
    if (traffic_keys(c_ap, t->c_key, t->c_iv) != 0 ||
        traffic_keys(s_ap, t->s_key, t->s_iv) != 0) {
        say(err, errcap, "прикладные ключи не развернулись"); tls_dispose(t); return -1;
    }
    t->c_seq = t->s_seq = 0;

    *out = t;
    return 0;
}

int d2k_tls_connect(int fd, const char *sni, int deadline_ms, size_t want_wire,
                    d2k_tls **out, char *err, size_t errcap) {
    return tls_connect_internal(fd, sni, deadline_ms, want_wire, NULL, 0, NULL, 0,
                                out, err, errcap);
}

int d2k_tls_connect_alpn(int fd, const char *sni, int deadline_ms, size_t want_wire,
                         const uint8_t *alpn_list, size_t alpn_len,
                         d2k_tls **out, char *err, size_t errcap) {
    return tls_connect_internal(fd, sni, deadline_ms, want_wire, NULL, 1,
                                alpn_list, alpn_len, out, err, errcap);
}

int d2k_tls_connect_ech(int fd, const char *origin, const d2k_ech_config *config,
    int deadline_ms, size_t want_wire, d2k_tls **out, char *err, size_t errcap) {
    if (!config || !origin || !origin[0]) {
        if (out) *out = NULL;
        say(err, errcap, "ECH требует origin и конфигурацию"); return -1;
    }
    return tls_connect_internal(fd, origin, deadline_ms, want_wire, config, 0, NULL, 0,
                                out, err, errcap);
}

int d2k_tls_ech_accepted(const d2k_tls *t) { return t && t->ech_accepted; }

int d2k_tls_write(d2k_tls *t, const uint8_t *buf, size_t n, char *err, size_t errcap) {
    if (!t) { say(err, errcap, "сессии нет"); return -1; }
    if (t->v12) { return d2k_tls12_write(t->v12, buf, n, err, errcap); }
    while (n > 0) {
        size_t take = n > 16384 ? 16384 : n;
        if (write_record(t, REC_APPDATA, buf, take, err, errcap) != 0) { return -1; }
        buf += take;
        n -= take;
    }
    return 0;
}

long d2k_tls_read(d2k_tls *t, uint8_t *buf, size_t cap, int wait_ms,
                  char *err, size_t errcap) {
    if (!t) { say(err, errcap, "сессии нет"); return -1; }
    if (t->v12) { return d2k_tls12_read(t->v12, buf, cap, wait_ms, err, errcap); }
    if (t->plain_off < t->plain_len) {
        size_t take = t->plain_len - t->plain_off;
        if (take > cap) { take = cap; }
        memcpy(buf, t->plain + t->plain_off, take);
        t->plain_off += take;
        return (long)take;
    }
    int64_t deadline = now_ms() + (wait_ms > 0 ? wait_ms : 8000);
    for (;;) {
        uint8_t type = 0;
        size_t len = 0;
        if (read_record(t, 1, &type, t->plain, sizeof t->plain, &len,
                        deadline, err, errcap) != 0) {
            return -1;
        }
        if (type == REC_CCS) { continue; }
        if (type == REC_ALERT) {
            /* close_notify (уровень 1, описание 0) — законный конец потока, а
               не отказ: сервер сказал «я всё». Остальные тревоги — отказ. */
            if (len >= 2 && t->plain[1] == 0) { return 0; }
            say(err, errcap, "тревога %u", len >= 2 ? (unsigned)t->plain[1] : 0u);
            return -1;
        }
        if (type == REC_HANDSHAKE) {
            continue; /* билеты возобновления — нам не нужны, пропускаем */
        }
        if (type != REC_APPDATA) { continue; }
        t->plain_len = len;
        t->plain_off = 0;
        if (len == 0) { continue; }
        size_t take = len > cap ? cap : len;
        memcpy(buf, t->plain, take);
        t->plain_off = take;
        return (long)take;
    }
}

int d2k_tls_peer_name(const d2k_tls *t) { return t ? t->peer_name : -1; }

void d2k_tls_free(d2k_tls *t) {
    if (t && t->v12) { d2k_tls12_free(t->v12); }
    tls_dispose(t);
}

uint64_t d2k_tls_rx_wire_bytes(const d2k_tls *t) { return t ? t->rx_wire_bytes + (t->v12 ? d2k_tls12_rx_wire_bytes(t->v12) : 0) : 0; }
uint32_t d2k_tls_rx_record_missing(const d2k_tls *t) { return t ? (t->v12 ? d2k_tls12_rx_record_missing(t->v12) : t->rx_record_missing) : 0; }

uint16_t d2k_tls_version(const d2k_tls *t) { return t ? (t->v12 ? 0x0303 : 0x0304) : 0; }
