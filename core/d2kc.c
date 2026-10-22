/* d2kc.c — контроллер d2k на C: цикл событий поверх планировщика.
 *
 * Заменяет Go-процесс `d2k serve` (cmd/d2k, internal/controller). Делает ровно
 * три вещи и ничего сверх: держит связь с датапатом, отдаёт его события
 * планировщику (core/sched.c) и время от времени сохраняет каталог на диск.
 * Подбор, развилка по транспорту и запись знания — там, не здесь.
 *
 * ЦИКЛ НЕ БЛОКИРУЕТСЯ. poll() на двух дескрипторах: связь с датапатом и
 * будилка планировщика (рабочий поток, закончив сетевой оракул, пишет в неё
 * байт). Потолок ожидания — период тика: задачам нужно время, а не только
 * события (истёкшие сроки, отдых после неудачи), ровно та же причина, по
 * которой Go-сторона завела тикер рядом с событиями.
 *
 * КАТАЛОГ ПИШЕТСЯ АТОМАРНО. d2k_catalog_save пишет прямо в файл (см. её
 * doc-комментарий: атомарность в её контракт не входит и принадлежит тому,
 * кто решает КОГДА писать) — значит здесь: пишем во временный файл рядом,
 * fsync, rename. Оборванная запись каталога стоила бы всего накопленного
 * знания разом, а падение питания на роутере — обычное дело.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "../runtime/d2k_runtime.h"
#include "d2k_crypto.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "d2k_sched.h"
#include "d2k_httpsprobe.h"
#include "d2k_httpsearch.h"
#include "d2k_plantlv.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include "d2k_link.h"

/* Переходник к перенесённому измерителю (detect/bridge.c). Объявлен здесь, а
 * не в заголовке ядра: ядро о detect/ не знает и знать не должно — связь
 * односторонняя, её ставит тот, кто собирает бинарник. */
/* Просит перенесённый измеритель бросить всё, что он сейчас меряет. Нужен на
 * остановке: без него выход ждал окончания замера — до десятков минут. */
void d2k_detect_stop_all(void);

d2k_vres d2k_detect_sched_tcp(const char *ip, uint16_t port,
                              d2k_hello trigger, d2k_hello control,
                              uint32_t mark, int repeats,
                              uint32_t gap_us, uint32_t wait_ms,
                              const volatile sig_atomic_t *stop);
/* Только базовый вопрос того же измерителя (задача 32): им планировщик
 * подтверждает блокировку на рукопожатии, прежде чем пробовать свои планы. */
d2k_vres d2k_detect_sched_tcp_base(const char *ip, uint16_t port,
                                   d2k_hello trigger, d2k_hello control,
                                   uint32_t mark, int repeats,
                                   uint32_t gap_us, uint32_t wait_ms,
                                   const volatile sig_atomic_t *stop);
/* Нейтральный байт перепроверки мёртвого адреса (задача 54). */
int d2k_detect_sched_tcp_ack(const char *ip, uint16_t port, uint32_t mark,
                             const volatile sig_atomic_t *stop, int *probes);
d2k_vres d2k_detect_sched_tcp_seeded(const char *ip, uint16_t port,
                                     d2k_hello trigger, d2k_hello control,
                                     uint32_t mark, int repeats,
                                     uint32_t gap_us, uint32_t wait_ms,
                                     const volatile sig_atomic_t *stop,
                                     const d2k_base_seed *seed);
d2k_vres d2k_detect_sched_tcp_white(const char *ip, uint16_t port,
                                    d2k_hello trigger, d2k_hello control, d2k_hello white,
                                    uint32_t mark, int repeats,
                                    uint32_t gap_us, uint32_t wait_ms,
                                    const volatile sig_atomic_t *stop);
d2k_vres d2k_detect_sched_tcp_seeded_white(const char *ip, uint16_t port,
                                           d2k_hello trigger, d2k_hello control, d2k_hello white,
                                           uint32_t mark, int repeats,
                                           uint32_t gap_us, uint32_t wait_ms,
                                           const volatile sig_atomic_t *stop,
                                           const d2k_base_seed *seed);

/* Период тика. Унаследован с Go-стороны (controller.go: time.NewTicker(3 *
   time.Second)) и там же обоснован: счётчики ядра опрашиваются по часам, а не
   по событиям. Выдумывать здесь другое число запрещено правилом «числа только
   из замера или наследования». */
#define TICK_MS 3000

/* Как часто сохранять каталог. Реже тика: запись на флеш роутера — дорогая
   операция, а знание между сохранениями не теряется (оно в памяти), теряется
   только при падении. Минута — тот же порядок, что у Go-стороны. */
#define SAVE_EVERY_MS 60000

/* Как часто говорить, что видно. Строка идёт в журнал на флеше: раз в 15 с
   это ~6000 строк в сутки (поле 06.10), а счётчики накопительные — пятнадцати
   минут хватает понять, видит ли служба трафик. Живой вид — в панели. */
#define REPORT_EVERY_MS (15 * 60 * 1000)

/* Как часто обновлять вид для панели. Две секунды: человек, открывший панель,
   ждёт, что идущий поиск на ней виден, а не появится через минуту. Файл
   маленький и лежит на tmpfs-подобном разделе состояния. */
#define LIVE_EVERY_MS 2000

static volatile sig_atomic_t stop_asked;
static void on_signal(int sig) { (void)sig; stop_asked = 1; }

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Атомарное сохранение: временный файл рядом, затем rename. Рядом, а не в
   /tmp — rename между файловыми системами не работает, а /opt и /tmp на
   роутере разные (tmpfs). */
static int save_atomic(const d2k_catalog *cat, const char *path,
                       char *err, size_t errcap) {
    return d2k_catalog_save_atomic(cat, path, err, errcap);
}

/* Печать планировщика. Со временем по стенным часам, а не монотонным: строку
   читает человек, и ему нужно сопоставить её с тем, что он делал. */
/* ПАМЯТЬ КОНТРОЛЛЕРА — В ТОЙ ЖЕ СВОДКЕ (задача 60). Поле 14.10.2026, Netis N6
   (mipsel, OpenWrt 25.12.5): d2kc 10,6 МБ сразу после перезапуска и 29,1 МБ
   через 1 д 9 ч, а датапат и туннель стояли на месте. Свою память d2kc не
   называл, и отличить заполнение ограниченных кэшей от утечки было не по
   чему. Теперь сводка несёт RSS, его пик, объём данных и число потоков, а
   рядом — размер каталога: рост памяти вместе с каталогом и без него —
   разные истории. Вне Linux /proc нет — память не печатается. */
static void self_mem(long *rss, long *hwm, long *data, long *thr) {
    *rss = *hwm = *data = *thr = -1;
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) { return; }
    char l[128];
    while (fgets(l, sizeof l, f)) {
        if (!strncmp(l, "VmRSS:", 6)) { *rss = strtol(l + 6, NULL, 10); }
        else if (!strncmp(l, "VmHWM:", 6)) { *hwm = strtol(l + 6, NULL, 10); }
        else if (!strncmp(l, "VmData:", 7)) { *data = strtol(l + 7, NULL, 10); }
        else if (!strncmp(l, "Threads:", 8)) { *thr = strtol(l + 8, NULL, 10); }
    }
    fclose(f);
}

static void sched_say(void *ctx, const char *line) {
    (void)ctx;
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    printf("%02d:%02d:%02d %s\n", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, line);
    fflush(stdout);
}

/* --- открытый HTTP: вставка провайдера → HTTPS имени (задача 51) -------- */

/* Поиск обхода самого HTTP (шаг 4): имена, у которых HTTPS нет. */
static d2k_httpsearch *g_hs;
static d2k_hs_runner *g_hr;
static int g_link_fd = -1;
static uint32_t g_probe_mark;
static const char *g_http_plans;

static void http_search_portal(const char *host, uint8_t family, const uint8_t *addr,
                               d2k_https_state st, int64_t now) {
    /* Только класс 3 — портал проходит как есть, HTTPS у имени нет. */
    if (!g_hs || !family || st == D2K_HTTPS_UNKNOWN || st == D2K_HTTPS_PROBING ||
        d2k_https_upgrade(st)) { return; }
    d2k_httpsearch_portal(g_hs, host, family, addr, now);
}

static int hs_open_port(void *ctx, uint8_t family, int *fd_out, uint16_t *sport_be) {
    (void)ctx;
    int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }
#ifdef SO_MARK
    /* Метка зондов: через очередь, к потоку достаётся только пробный план
       его порта, нового обнаружения он не рождает. */
    if (g_probe_mark &&
        setsockopt(fd, SOL_SOCKET, SO_MARK, &g_probe_mark, sizeof g_probe_mark) != 0) {
        close(fd);
        return -1;
    }
#endif
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t sl;
    if (family == 6) {
        ((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
        sl = sizeof(struct sockaddr_in6);
    } else {
        ((struct sockaddr_in *)&ss)->sin_family = AF_INET;
        sl = sizeof(struct sockaddr_in);
    }
    if (bind(fd, (struct sockaddr *)&ss, sl) != 0 ||
        getsockname(fd, (struct sockaddr *)&ss, &sl) != 0) {
        close(fd);
        return -1;
    }
    *sport_be = family == 6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                            : ((struct sockaddr_in *)&ss)->sin_port;
    *fd_out = fd;
    return 0;
}

static void hs_close_port(void *ctx, int fd) { (void)ctx; close(fd); }

static int hs_hex(const char *text, char *hex, size_t cap) {
    char err[200];
    if (d2k_plan_text_to_hex(text, hex, cap, err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: план HTTP не собрался: %s\n", err);
        return -1;
    }
    return 0;
}

static int hs_set_probe(void *ctx, const char *host, uint8_t family, uint16_t sport_be,
                        const char *text, const uint8_t trial[16]) {
    (void)ctx;
    static char hex[8192];
    char err[200];
    if (hs_hex(text, hex, sizeof hex) != 0) { return -1; }
    if (d2k_link_set_name_probe_trial(g_link_fd, host, 6, hex, D2K_LINK_SHAPE_HTTP, sport_be,
                                      family, trial, err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
        return -1;
    }
    return 0;
}

static int hs_del_probe(void *ctx, const char *host, uint8_t family, uint16_t sport_be) {
    (void)ctx;
    char err[200];
    if (d2k_link_del_name_probe_family(g_link_fd, host, 6, D2K_LINK_SHAPE_HTTP, sport_be,
                                       family, err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
        return -1;
    }
    return 0;
}

static int hs_set_plan(void *ctx, const char *host, uint8_t family, const char *text, const uint8_t token[16]) {
    (void)ctx;
    static char hex[8192];
    char err[200];
    if (hs_hex(text, hex, sizeof hex) != 0) { return -1; }
    if (d2k_link_set_name_bound(g_link_fd, host, 6, hex, D2K_LINK_SHAPE_HTTP, family, token,
                                 err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
        return -1;
    }
    return 0;
}

static int hs_del_plan(void *ctx, const char *host, uint8_t family, const d2k_binding_context *binding) {
    (void)ctx;
    if(!binding || binding->family!=family || !d2k_binding_known(binding))return -1;
    char err[200];
    if (d2k_link_del_name_bound(g_link_fd, host, 6, binding,
                                 err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
        return -1;
    }
    return 0;
}

static int hs_start(void *ctx, const d2k_hs_job *job) {
    (void)ctx;
    return d2k_hs_runner_start(g_hr, job);
}

static void hs_say(void *ctx, const char *line);
static void hs_changed(void *ctx) {
    (void)ctx;
    char err[300];
    if (g_hs && g_http_plans &&
        d2k_httpsearch_save(g_hs, g_http_plans, (int64_t)time(NULL), err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: планы HTTP не сохранены: %s\n", err);
    }
}

/* Датапат узнал вставку провайдера. Проверить HTTPS имени на том же адресе;
   подтверждённое, но забытое датапатом — повторить. */
static void http_portal(d2k_httpsprobe *hp, int fd, const d2k_ev *ev, int64_t now) {
    char line[512];
    uint32_t ttl = 0;
    int rc = d2k_httpsprobe_portal(hp, ev->name, ev->family, ev->high_ip, ev->code == 1,
                                   now, &ttl);
    if (rc == 0) {
        http_search_portal(ev->name, ev->family, ev->high_ip,
                           d2k_httpsprobe_state(hp, ev->name, now), now);
    }
    if (rc == 1) {
        snprintf(line, sizeof line, "HTTP %.255s: %s — проверяю HTTPS имени", ev->name,
                 ev->kind == D2K_EV_HTTP_RESPONSE ? "ответ перенаправляет на известный портал блокировки"
                                                : "провайдер подменяет ответ порталом блокировки");
        sched_say(NULL, line);
    } else if (rc == 2) {
        char err[200];
        if (d2k_link_set_https(fd, ev->name, ttl, err, sizeof err) != 0) {
            fprintf(stderr, "d2kc: %s\n", err);
        }
    }
}

static void http_push(int fd, const char *host, uint32_t ttl) {
    char err[200];
    if (d2k_link_set_https(fd, host, ttl, err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: %s\n", err);
    }
}

static void http_save(d2k_httpsprobe *hp, const char *path, int64_t now) {
    char err[300];
    if (path && d2k_httpsprobe_save(hp, path, now, (int64_t)time(NULL), err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: кэш HTTPS не сохранён: %s\n", err);
    }
}

static void http_probe_done(d2k_httpsprobe *hp, int fd, int64_t now, const char *cache_path) {
    d2k_httpsprobe_result r[8];
    size_t n, total = 0;
    while ((n = d2k_httpsprobe_done(hp, now, r, sizeof r / sizeof r[0])) > 0) {
        total += n;
        for (size_t i = 0; i < n; i++) {
            char line[1200];
            int up = d2k_https_upgrade(r[i].state);
            snprintf(line, sizeof line, "HTTP %.255s: %s (%.255s) — %s", r[i].host,
                     r[i].state == D2K_HTTPS_SERVED ? "TLS к 443 прошёл, имя в листе сертификата" :
                     r[i].state == D2K_HTTPS_TLS_BLOCKED ? "443 принимает, TLS срезан на линии" :
                     r[i].state == D2K_HTTPS_CLOSED ? "HTTPS у источника нет (443 закрыт)" :
                     r[i].state == D2K_HTTPS_OTHER_NAME ? "на 443 сертификат другого имени" :
                                                          "HTTPS не решён",
                     r[i].why,
                     up ? "вставку провайдера датапат заменит на 307 → https"
                        : "вставка провайдера идёт клиенту как есть: перевод на https "
                          "был бы тупиком");
            sched_say(NULL, line);
            if (up) { http_push(fd, r[i].host, r[i].ttl_s); }
            else { http_search_portal(r[i].host, r[i].family, r[i].addr, r[i].state, now); }
        }
    }
    if (total) { http_save(hp, cache_path, now); }
    static uint64_t lost_told;
    uint64_t lost = d2k_httpsprobe_lost(hp);
    if (lost != lost_told) {
        fprintf(stderr, "d2kc: ответов зонда HTTPS потеряно %llu (имена перепроверятся)\n",
                (unsigned long long)lost);
        lost_told = lost;
    }
}

static void hs_say(void *ctx, const char *line) { (void)ctx; sched_say(NULL, line); }

/* ПОРЧА ПРИМАНКИ, ИЗМЕРЕННАЯ НА ЭТОЙ ЛИНИИ: признаки порчи, на которой
   держатся подтверждённые TLS-планы коробок каталога (успехи > 0), —
   самые успешные первыми. Каждая — вопрос к HTTP-коробке той же линии
   вместо заготовки; tcpts/ipidzero HTTP-исполнитель не повторит, они
   отбрасываются (d2k_httpsearch_measured_poison). */
typedef struct { int succ; char spec[64]; } poison_seen;
static int poison_cmp(const void *a, const void *b) {
    return ((const poison_seen *)b)->succ - ((const poison_seen *)a)->succ;
}
static void hs_measured_poisons(d2k_httpsearch *hs, const d2k_catalog *cat) {
    poison_seen v[64];
    size_t n = 0;
    for (size_t b = 0; b < cat->n_boxes; b++) {
        const d2k_cat_box *box = &cat->boxes[b];
        for (size_t k = 0; k < box->n_plans && n < 64; k++) {
            const d2k_cat_plan *pl = &box->plans[k];
            if (!pl->text || pl->successes <= 0 || !pl->enabled ||
                !strstr(pl->text, "\nproto tcp tls\n")) { continue; }
            char specs[8][64];
            size_t m = d2k_hs_plan_poisons(pl->text, specs, 8);
            for (size_t i = 0; i < m && n < 64; i++) {
                snprintf(v[n].spec, sizeof v[n].spec, "%.63s", specs[i]);
                v[n].succ = pl->successes;
                n++;
            }
        }
    }
    qsort(v, n, sizeof v[0], poison_cmp);
    size_t taken = 0;
    for (size_t i = 0; i < n; i++) {
        if (d2k_httpsearch_measured_poison(hs, v[i].spec) == 0) { taken++; }
    }
    if (taken) { printf("d2kc: HTTP: измеренной порчи приманки с этой линии — %zu\n", taken); }
}

static void usage(void) {
    fprintf(stderr,
        "использование: d2kc --control <сокет> [--catalog <файл>] [--mark 0x2e] [--measure-mark 0x2f]\n"
        "  --control  управляющий сокет датапата (обязателен)\n"
        "  --catalog  где держать знание (умолчание /opt/d2k/catalog.json)\n"
        "  --live     куда писать вид для панели (умолчание — рядом с каталогом)\n"
        "  --log      куда писать журнал (умолчание — стандартный вывод)\n"
        "  --https-cache  кэш HTTPS имён для вставки провайдера (умолчание — рядом с каталогом)\n"
        "  --mark     метка verifier-зондов; они идут через NFQUEUE (умолчание 0x2d)\n"
        "  --measure-mark метка измерений; обычно обходит собственную NFQUEUE (по умолчанию --mark)\n");
}

static int offline_self_check(void) {
    static const uint8_t want[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    uint8_t got[32]; d2k_sha256((const uint8_t *)"abc", 3, got);
    return D2K_CTL_PROTO_VERSION == D2K_RUNTIME_WIRE && memcmp(got, want, 32) == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) { printf("d2kc release=%s wire=%u\n", D2K_RELEASE_ID, D2K_RUNTIME_WIRE); return 0; }
    int offline = d2k_runtime_offline(argc, argv, "d2kc", offline_self_check);
    if (offline >= 0) return offline;
    const char *health_path = "/tmp/d2k/d2kc.health";
    const char *sock = NULL;
    const char *catpath = "/opt/d2k/catalog.json";
    const char *livepath = NULL;
    const char *logpath = NULL;
    const char *https_path = NULL;
    uint32_t mark = 0x2d;
    uint32_t measure_mark = 0;
    int have_measure_mark = 0;

    for (int i = 1; i < argc; i++) {
        const char *f = argv[i];
        if (strcmp(f, "--health-file") == 0 && i + 1 < argc) { health_path = argv[++i]; }
        else if (strcmp(f, "--control") == 0 && i + 1 < argc) { sock = argv[++i]; }
        else if (strcmp(f, "--catalog") == 0 && i + 1 < argc) { catpath = argv[++i]; }
        else if (strcmp(f, "--live") == 0 && i + 1 < argc) { livepath = argv[++i]; }
        else if (strcmp(f, "--log") == 0 && i + 1 < argc) { logpath = argv[++i]; }
        else if (strcmp(f, "--https-cache") == 0 && i + 1 < argc) { https_path = argv[++i]; }
        else if (strcmp(f, "--mark") == 0 && i + 1 < argc) {
            mark = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(f, "--measure-mark") == 0 && i + 1 < argc) {
            measure_mark = (uint32_t)strtoul(argv[++i], NULL, 0);
            have_measure_mark = 1;
        } else {
            usage();
            return 2;
        }
    }
    if (!sock) { usage(); return 2; }

    /* Тот же приём, что в d2kd.c и ctlprobe.c: процесс не имеет права умирать
       оттого, что собеседник отвалился между записями. */
    /* Журнал открываем САМИ, а не перенаправлением снаружи: start-stop-daemon
       с -b потоки потомка не наследует — проверено на роутере, файл оставался
       нулевой длины при исправно работающем движке. Ровно то же было у
       Go-стороны, и там это тоже кончилось ключом. */
    if (logpath) {
        FILE *lf = freopen(logpath, "a", stdout);
        if (!lf) {
            fprintf(stderr, "d2kc: не открыть журнал %s: %s\n", logpath, strerror(errno));
            return 1;
        }
        (void)dup2(fileno(stdout), fileno(stderr));
        setvbuf(stdout, NULL, _IOLBF, 0);
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    d2k_catalog cat;
    memset(&cat, 0, sizeof cat);
    char err[512];
    if (d2k_catalog_load(catpath, &cat, err, sizeof err) != 0) {
        /* Каталога может не быть вовсе — это первый запуск, а не отказ.
           Отличить «нет файла» от «файл битый» обязательно: во втором случае
           молча начать с чистого листа значило бы потерять всё знание и не
           сказать об этом. */
        if (access(catpath, F_OK) == 0) {
            fprintf(stderr, "d2kc: каталог %s не разобрался: %s\n", catpath, err);
            return 1;
        }
        memset(&cat, 0, sizeof cat);
        printf("d2kc: каталога %s нет — начинаю с пустого\n", catpath);
    }

    int fd = d2k_link_open(sock, err, sizeof err);
    if (fd < 0) {
        fprintf(stderr, "d2kc: связь с датапатом %s: %s\n", sock, err);
        d2k_catalog_free(&cat);
        return 1;
    }

    /* Do not send catalog commands or start measurements before the peer
       proves it uses this key layout. Old greetings have shorter keys and
       cannot be safely interpreted as version-4 traffic. */
    d2k_ev greeting;
    if (d2k_link_next(fd, &greeting, 2000, err, sizeof err) != 0) {
        fprintf(stderr, "d2kc: нет корректного приветствия датапата: %s\n", err);
        d2k_link_close(fd);
        d2k_catalog_free(&cat);
        return 1;
    }
    if (greeting.kind != D2K_EV_PROTO || greeting.num != D2K_CTL_PROTO_VERSION || strcmp(greeting.release_id, D2K_RELEASE_ID)) {
        fprintf(stderr, "d2kc: несовместимое приветствие датапата, нужна версия %u\n",
                (unsigned)D2K_CTL_PROTO_VERSION);
        d2k_link_close(fd);
        d2k_catalog_free(&cat);
        return 1;
    }

    d2k_sched *s = d2k_sched_new(&cat, fd, mark);
    if (!s) {
        fprintf(stderr, "d2kc: планировщик не завёлся: %s\n",
                strerror(errno ? errno : EIO));
        d2k_link_close(fd);
        d2k_catalog_free(&cat);
        return 1;
    }
    d2k_sched_set_measure_mark(s, have_measure_mark ? measure_mark : mark);
    d2k_sched_set_send_cap(s, greeting.send_maxlen);

    d2k_sched_set_say(s, sched_say, NULL);

    /* Зонд HTTPS — с меткой зондов контроллера: через очередь, с уже
       подтверждённым планом имени, без нового обнаружения. */
    d2k_httpsprobe *hp = d2k_httpsprobe_new(mark, NULL);
    if (!hp) {
        fprintf(stderr, "d2kc: зонд HTTPS не завёлся — вставка провайдера в HTTP "
                        "будет идти клиенту как есть\n");
    }
    /* Кэш HTTPS переживает перезапуск (ревью I2): иначе первый заход после
       каждого перезапуска снова видел бы портал. Рядом с каталогом. */
    char https_buf[D2K_CATALOG_PATH_MAX + 32];
    if (!https_path) {
        const char *slash = strrchr(catpath, '/');
        size_t dirlen = slash ? (size_t)(slash - catpath + 1) : 0;
        if (dirlen < sizeof https_buf - 20) {
            memcpy(https_buf, catpath, dirlen);
            snprintf(https_buf + dirlen, sizeof https_buf - dirlen, "https-cache.txt");
            https_path = https_buf;
        }
    }
    /* Поиск обхода HTTP и его подтверждённые планы — рядом с каталогом. */
    g_link_fd = fd;
    g_probe_mark = mark;
    static char plans_buf[D2K_CATALOG_PATH_MAX + 32];
    {
        const char *slash = strrchr(catpath, '/');
        size_t dirlen = slash ? (size_t)(slash - catpath + 1) : 0;
        if (dirlen < sizeof plans_buf - 20) {
            memcpy(plans_buf, catpath, dirlen);
            snprintf(plans_buf + dirlen, sizeof plans_buf - dirlen, "http-plans.txt");
            g_http_plans = plans_buf;
        }
    }
    g_hr = d2k_hs_runner_new();
    if (g_hr) {
        d2k_hs_ops ops = {hs_open_port, hs_close_port, hs_set_probe, hs_del_probe, hs_set_plan,
                          hs_del_plan, hs_start, hs_say, hs_changed, NULL};
        g_hs = d2k_httpsearch_new(&ops);
        if (g_hs) { hs_measured_poisons(g_hs, &cat); }
    }
    if (!g_hs) {
        fprintf(stderr, "d2kc: поиск обхода HTTP не завёлся — вставка в HTTP без HTTPS "
                        "останется как есть\n");
    } else if (g_http_plans) {
        size_t nl = 0;
        char herr[300];
        if (d2k_httpsearch_load(g_hs, g_http_plans, &nl, herr, sizeof herr) != 0) {
            fprintf(stderr, "d2kc: планы HTTP не прочитаны: %s\n", herr);
        } else if (nl) {
            printf("d2kc: планы HTTP %s: имён %zu поставлено датапату\n", g_http_plans, nl);
        }
    }
    if (hp && https_path) {
        static d2k_httpsprobe_result push[D2K_HTTPSPROBE_NAMES];
        size_t np = 0, nl = 0;
        char herr[300];
        if (d2k_httpsprobe_load(hp, https_path, now_ms(), (int64_t)time(NULL), push,
                                D2K_HTTPSPROBE_NAMES, &np, &nl, herr, sizeof herr) != 0) {
            fprintf(stderr, "d2kc: кэш HTTPS не прочитан, начинаю с пустого: %s\n", herr);
        } else {
            for (size_t i = 0; i < np; i++) { http_push(fd, push[i].host, push[i].ttl_s); }
            if (nl) {
                printf("d2kc: кэш HTTPS %s: имён %zu, к датапату с 307 — %zu\n",
                       https_path, nl, np);
            }
        }
    }

    /* ИЗМЕРИТЕЛЬ TCP — ПЕРЕНЕСЁННЫЙ «ПОИСК ПО ДОМЕНУ», а не прежнее дерево.
     *
     * Прежнее (core/verdict.c) отвечало только на вопрос «какого класса
     * блокировка» и на этом кончалось: чем брать коробку, выяснял уже
     * планировщик отдельными вопросами через датапат. Перенесённый отвечает на
     * оба вопроса сразу и своими сокетами — фаза свойств и перебор отравлений
     * живут внутри того же вызова, — и возвращает НАЙДЕННОЕ ПЛЕЧО. Сверка с
     * оригиналом на живой линии: docs/field/2026-09-14-port-correspondence.md.
     *
     * Крючок, а не правка планировщика: тесты подменяют эту же точку, чтобы
     * утверждать развилку по транспорту, не выходя в сеть. */
    d2k_sched_tcp_hook = d2k_detect_sched_tcp;
    /* Свои подтверждённые планы — до полного замера (задача 32, ТЗ §3.4):
     * базовый вопрос донора отдельно, тем же измерителем. */
    d2k_sched_tcp_base_hook = d2k_detect_sched_tcp_base;
    /* Полный прогон берёт уже снятый ответ базы, а не спрашивает её снова;
     * QUIC — тот же шаг своим путём (core/quicprobe.c). */
    d2k_sched_tcp_seeded_hook = d2k_detect_sched_tcp_seeded;
    /* Белое имя сети приманкой для вопроса «приветствие под меткой» (поле
     * 10.10.2026): отдельный крючок, т.к. сигнатуру основного менять нельзя. */
    d2k_sched_tcp_white_hook = d2k_detect_sched_tcp_white;
    /* Тот же белый крючок, но на seeded-пути: у целей семейства C замер идёт
     * снятыми байтами клиента (seed), и без этого приманка не доходила — вопрос
     * не задавался в поле (прогон ac4edeb, 19 сайтов). */
    d2k_sched_tcp_seeded_white_hook = d2k_detect_sched_tcp_seeded_white;
    /* Перепроверка адреса с вердиктом address — сначала один нейтральный
     * байт, до любого триггера (задача 54). */
    d2k_sched_tcp_ack_hook = d2k_detect_sched_tcp_ack;
    d2k_sched_quic_base_hook = d2k_quic_base;
    d2k_sched_quic_seeded_hook = d2k_quic_run_seeded;

    /* Знание из каталога — датапату СРАЗУ: он состояния между запусками не
       хранит, и без этого прохода каждая уже изученная цель начинала бы поиск
       заново. Сам проход идёт порциями в цикле ниже — залпом он создавал бы
       окно, в котором датапату некуда сказать про живой трафик. */
    (void)d2k_sched_sync(s);

    printf("d2kc: запущен, сокет %s, каталог %s (%zu коробок), метка 0x%x\n",
           sock, catpath, cat.n_boxes, (unsigned)mark);
    fflush(stdout);

    /* Счётчики событий. Заведены измеренной нуждой: первый живой прогон
       молчал, и отличить «датапат не подозревает» от «связь есть, а событий не
       идёт» было нечем — а это разные беды, одна про линию, другая про нас. */
    unsigned long seen_events = 0, seen_hello = 0, seen_suspect = 0;
    unsigned long seen_exchange = 0, seen_applied = 0, seen_refused = 0;
    /* Версия провода: объявлена ли вообще и совпала ли. Оба «нет» означают
       «мы не знаем, с кем говорили», и оба обязаны быть слышны. */
    int proto_seen = 1, proto_bad = 0;
    int64_t last_report = now_ms();

    /* Путь вида для панели: рядом с каталогом, если не задан явно. Панель
       читает его и больше ничего о движке не знает (см. d2k_sched_write_live). */
    char livebuf[D2K_CATALOG_PATH_MAX + 16];
    if (!livepath) {
        const char *slash = strrchr(catpath, '/');
        size_t dirlen = slash ? (size_t)(slash - catpath + 1) : 0;
        if (dirlen < sizeof livebuf - 10) {
            memcpy(livebuf, catpath, dirlen);
            snprintf(livebuf + dirlen, sizeof livebuf - dirlen, "live.json");
            livepath = livebuf;
        }
    }
    int64_t last_live = 0;

    int64_t last_tick = now_ms(), last_save = last_tick;
    uint64_t dirty = cat.revision; /* catalog contents changed since last save */
    int link_lost = 0;

    while (!stop_asked) {
        (void)d2k_runtime_heartbeat(health_path, greeting.release_id, 1, 1, 1);
        struct pollfd pfd[4];
        pfd[0].fd = fd;                       pfd[0].events = POLLIN; pfd[0].revents = 0;
        pfd[1].fd = d2k_sched_wake_fd(s);     pfd[1].events = POLLIN; pfd[1].revents = 0;
        pfd[2].fd = d2k_httpsprobe_wake_fd(hp); pfd[2].events = POLLIN; pfd[2].revents = 0;
        pfd[3].fd = d2k_hs_runner_wake_fd(g_hr); pfd[3].events = POLLIN; pfd[3].revents = 0;

        int64_t t = now_ms();
        int wait = (int)(TICK_MS - (t - last_tick));
        if (wait < 0) { wait = 0; }
        if (d2k_sched_sync_pending(s)) {
            /* Пока проход по каталогу не закончен, круг цикла не ждёт: каждая
               порция обязана идти сразу за чтением событий. */
            wait = 0;
        }
        int pr = poll(pfd, 4, wait);
        if (pr < 0 && errno != EINTR) {
            fprintf(stderr, "d2kc: poll: %s\n", strerror(errno));
            break;
        }

        if (pr > 0 && (pfd[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            /* Читаем всё, что уже пришло, а не по одному событию за круг:
               датапат за секунду присылает сотни наблюдений, и круг poll на
               каждое был бы чистой тратой. Нулевой потолок — «только то, что
               уже в буфере». */
            for (;;) {
                int drained = 0;
                for (; drained < 256; drained++) {
                    d2k_ev ev;
                    if (d2k_link_next(fd, &ev, 0, err, sizeof err) != 0) { break; }
                    seen_events++;
                    switch (ev.kind) {
                    case D2K_EV_HELLO:    seen_hello++; break;
                    case D2K_EV_SUSPECT:  seen_suspect++; break;
                    case D2K_EV_EXCHANGE: seen_exchange++; break;
                    case D2K_EV_APPLIED:  seen_applied++; break;
                    case D2K_EV_REFUSED:  seen_refused++; break;
                    case D2K_EV_HTTP_RESPONSE: {
                        static const uint8_t no_trial[16] = {0};
                        (void)d2k_httpsearch_control(g_hs,&ev,now_ms());
                        /* Поздний портал сам по себе не доказывает подмену по
                           времени, но без привязки к пробе всё равно требует
                           прямой проверки. Результат пробы относится только
                           к её собственному заданию. */
                        if (hp && ev.code == 3 && ev.transport == 6 && ev.high_port == 80 &&
                            !memcmp(ev.trial_id, no_trial, sizeof no_trial))
                            http_portal(hp, fd, &ev, now_ms());
                        break;
                    }
                    case D2K_EV_HTTP_PORTAL:
                        (void)d2k_httpsearch_control(g_hs,&ev,now_ms());
                        if (hp) { http_portal(hp, fd, &ev, now_ms()); }
                        break;
                    default: break;
                    }
                    /* Поиск HTTP: подтверждение своей пробы и исполнение
                       своего плана (сверка по trial ID и Plan ID). */
                    if(ev.kind==D2K_EV_ACK)(void)d2k_httpsearch_control(g_hs,&ev,now_ms());
                    if (g_hs && ev.kind == D2K_EV_ACK && ev.code == D2K_CMD_SET_NAME_PROBE) {
                        d2k_httpsearch_ack(g_hs, ev.trial_id, ((ev.num >> 8) & 0xffu) == 1u, now_ms());
                    } else if (g_hs && ev.kind == D2K_EV_APPLIED) {
                        (void)d2k_httpsearch_control(g_hs,&ev,now_ms());
                    }
                    switch (ev.kind) {
                    case D2K_EV_PROTO:
                        /* ВЕРСИЯ ПРОВОДА. Чужая — работать нельзя: смешанная пара
                           не падает и не ругается, она молча не даёт
                           подтверждений, и всё измерение уходит в никуда. Лучше
                           громкий отказ сейчас, чем полдня пустых замеров. */
                        proto_seen = 1;
                        /* Предел отправки едет тем же событием и нужен сборке
                           планов: тело фальшивки обязано помещаться в канал. */
                        d2k_sched_set_send_cap(s, ev.send_maxlen);
                        if (ev.num != (uint32_t)D2K_CTL_PROTO_VERSION) {
                            fprintf(stderr,
                                "d2kc: датапат говорит на версии протокола %u, наша %u — "
                                "работать с такой парой нельзя: подтверждений она не даст, "
                                "а измерения будут пустыми. Обновите d2kd, d2kc и d2kask "
                                "вместе, из одного дерева.\n",
                                (unsigned)ev.num, (unsigned)D2K_CTL_PROTO_VERSION);
                            proto_bad = 1;
                        }
                        break;
                    default: break;
                    }
                    d2k_sched_event(s, &ev);
                }
                /* В обычном потоке ограничиваем круг 256 событиями, чтобы
                   таймеры и планировщик не голодали. После закрытия peer
                   очередь конечна: дочитываем её до EOF, иначе последняя
                   пачка наблюдений теряется перед сохранением каталога. */
                if (drained < 256 || d2k_link_peer_closed(fd) != 1) { break; }
            }
        }
        if (hp && pr > 0 && (pfd[2].revents & POLLIN)) {
            http_probe_done(hp, fd, now_ms(), https_path);
        }
        if (g_hs && pr > 0 && (pfd[3].revents & POLLIN)) {
            d2k_hs_result hr;
            if (d2k_hs_runner_done(g_hr, &hr)) { d2k_httpsearch_result(g_hs, &hr, now_ms()); }
        }
        if (g_hs) { d2k_httpsearch_tick(g_hs, now_ms()); }
        /* Таблица датапата вытесняет давно не нужные записи (LRU): свои
           HTTP-планы ставятся заново раз в 30 мин (ревью M-5). */
        static int64_t last_http_push;
        if (g_hs && now_ms() - last_http_push >= 30ll * 60 * 1000) {
            if (last_http_push) { d2k_httpsearch_push_all(g_hs); }
            last_http_push = now_ms();
        }
        /* PID живого контроллера ещё не означает, что он связан с датапатом:
           закрытый AF_UNIX peer даёт POLLHUP один раз. Не выходя здесь,
           контроллер продолжал бы публиковать live.json с linked=true. */
        int peer_closed = d2k_link_peer_closed(fd);
        if (peer_closed != 0) {
            if (peer_closed < 0) {
                fprintf(stderr, "d2kc: проверка связи с датапатом: %s\n",
                        strerror(errno));
            } else {
                fprintf(stderr, "d2kc: связь с датапатом оборвалась\n");
            }
            link_lost = 1;
            break;
        }
        if (proto_bad) { break; }

        /* Порция прохода по каталогу — ПОСЛЕ чтения событий и до следующего
           круга poll: так между командами всегда есть чтение, и датапату
           всегда есть куда сказать. */
        int more = d2k_sched_sync_step(s);

        t = now_ms();
        if (more || t - last_tick >= TICK_MS || (pr > 0 && (pfd[1].revents & POLLIN))) {
            d2k_sched_tick(s, t);
            last_tick = t;
        }

        if (t - last_report >= REPORT_EVERY_MS) {
            size_t n_binds = 0, n_plans = 0;
            for (size_t b = 0; b < cat.n_boxes; b++) {
                n_binds += cat.boxes[b].n_binds;
                n_plans += cat.boxes[b].n_plans;
            }
            long rss, hwm, data, thr;
            self_mem(&rss, &hwm, &data, &thr);
            char mem[160] = "";
            if (rss >= 0) {
                snprintf(mem, sizeof mem, "; память: RSS %ld КиБ (пик %ld), данные %ld КиБ, потоков %ld",
                         rss, hwm, data, thr);
            }
            char line[600];
            snprintf(line, sizeof line,
                     "событий %lu (приветствий %lu, подозрений %lu, обменов %lu, "
                     "применений %lu, отказов %lu), поисков идёт %zu; каталог: коробок %zu, "
                     "привязок %zu, планов %zu%s",
                     seen_events, seen_hello, seen_suspect, seen_exchange,
                     seen_applied, seen_refused, d2k_sched_active(s),
                     cat.n_boxes, n_binds, n_plans, mem);
            sched_say(NULL, line);
            last_report = t;
        }

        if (livepath && t - last_live >= LIVE_EVERY_MS) {
            (void)d2k_sched_write_live(s, livepath, catpath);
            last_live = t;
        }

        if (t - last_save >= SAVE_EVERY_MS) {
            if (cat.revision != dirty) {
                if (save_atomic(&cat, catpath, err, sizeof err) != 0) {
                    fprintf(stderr, "d2kc: каталог не сохранён: %s\n", err);
                } else {
                    dirty = cat.revision;
                    printf("d2kc: каталог сохранён (изменение %llu)\n",
                           (unsigned long long)dirty);
                    fflush(stdout);
                }
            }
            last_save = t;
        }
    }

    if (proto_bad) {
        printf("d2kc: остановлен из-за несовпадения версии протокола\n");
    }
    if (!proto_seen) {
        /* Версии не было вовсе — либо датапат старый (до появления
           объявления), либо событие потерялось. Оба случая одинаково значат
           «мы не знаем, с кем говорили», и молчать об этом нельзя. */
        fprintf(stderr, "d2kc: датапат версию протокола не объявил — "
                        "работоспособность пары НЕ подтверждена\n");
    }
    printf("d2kc: останавливаюсь\n");
    /* Сперва сказать измерителю бросить, потом уже дожидаться потоков: иначе
       d2k_sched_free досиживает замер до конца, и служба не выходит по
       сигналу (стенд транзита 17.09 повис на этом). Журнал при этом уезжает
       в файл через буфер, поэтому строка выше явно выталкивается — иначе
       «останавливаюсь» не видно ровно тогда, когда его и ищут. */
    fflush(stdout);
    d2k_detect_stop_all();
    d2k_httpsprobe_free(hp);
    /* Сперва дождаться зонда (он держит сокет), потом снять свою пробу. */
    d2k_hs_runner_free(g_hr);
    d2k_httpsearch_free(g_hs);
    d2k_sched_free(s);
    if (cat.revision != dirty) {
        if (save_atomic(&cat, catpath, err, sizeof err) != 0) {
            fprintf(stderr, "d2kc: каталог не сохранён на выходе: %s\n", err);
        }
    }
    d2k_link_close(fd);
    d2k_catalog_free(&cat);
    return link_lost ? 1 : 0;
}
