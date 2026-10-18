/* d2kfetch — обращение к цели КАК У БРАУЗЕРА, с роутера.
 *
 * ЗАЧЕМ. Полевую проверку до сих пор подпирали curl, и он врал. План D2K
 * привязан к ИМЕНИ И ФОРМЕ приветствия, а исполнитель считает смещения разреза
 * от разметки конкретного приветствия. Приветствие curl короче браузерного
 * (поле 15.10.2026: Edge — 1951 байт, curl — около 517) и устроено иначе:
 * план, выведенный по браузерным байтам, к потоку curl либо не подходит
 * формой, либо не исполняется — якоря разреза выходят за его длину. Оттого
 * flibusta.is у человека открывалась в браузере и не открывалась через curl,
 * и «ноль байт» в выводе curl ничего не говорил о том, работает ли обход.
 *
 * ЧТО ДЕЛАЕТ. Один запрос к цели СВОИМ клиентом, но приветствием той же формы
 * и той же длины, что у браузера, НЕПОМЕЧЕННЫЙ — то есть ровно так, как идёт
 * поток человека: датапат применит к нему тот же план. Печатает, что реально
 * пришло: версию TLS, код HTTP, сколько тела получено из скольких ожидаемых,
 * доведён ли ответ до конца или оборван.
 *
 * ДЛИНА ПРИВЕТСТВИЯ. --wire N задаёт её прямо. --snapshot берёт её у
 * ЖИВОГО браузера: взводит ловушку снимка в датапате и ждёт, пока человек
 * (или вкладка на этом же роутере) сам сходит на это имя. Это честнее
 * любого числа из головы: меряем тем, чем ходит клиент.
 *
 * ЧЕГО НЕ ДЕЛАЕТ. Не повторяет байты браузера один в один: без его ключей
 * сессию не продолжить, и за тем, что происходит ПОСЛЕ рукопожатия, пришлось
 * бы всё равно идти своим клиентом. Поэтому совпадают форма и длина — то, по
 * чему план выбирается и исполняется, — а не содержимое расширений.
 * Не ходит по редиректам и не меняет цель. */
#define _POSIX_C_SOURCE 200809L
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "d2k_hello.h"
#include "d2k_link.h"
#include "d2k_verify.h"
#include "d2k_volume.h"

static void usage(void) {
    fprintf(stderr,
        "d2kfetch — обращение к цели как у браузера (через планы D2K)\n"
        "\n"
        "  d2kfetch --name ИМЯ [--ip АДРЕС] [--port N] [--path /путь]\n"
        "           [--wire N | --snapshot[=МС]] [--tls12] [--deadline МС]\n"
        "\n"
        "  --name      имя в SNI и в заголовке Host (обязательно)\n"
        "  --ip        адрес цели; без него имя разрешается системой\n"
        "  --port      порт, по умолчанию 443\n"
        "  --path      путь запроса, по умолчанию /\n"
        "  --wire N    длина приветствия на проводе, как у браузера\n"
        "  --snapshot  взять длину у живого приветствия браузера: взвести\n"
        "              ловушку датапата и ждать (по умолчанию 60000 мс)\n"
        "  --ladder    вместо запроса страницы прогнать ТУ ЖЕ исходящую\n"
        "              лестницу, которой меряет планировщик, и показать её\n"
        "              вердикт: так видно, совпадает ли её обрыв с тем, что\n"
        "              видит браузерное обращение\n"
        "  --mark 0xN  метка SO_MARK для лестницы: с ней она идёт МИМО планов\n"
        "              (так её гоняет планировщик), без неё — через планы\n"
        "  --quic      идти по QUIC/HTTP3 вместо TCP (как браузер по h3)\n"
        "  --tls12     старое приветствие TLS 1.2 вместо 1.3\n"
        "  --deadline  потолок на рукопожатие и на ответ, по умолчанию 15000 мс\n"
        "\n"
        "Обращение идёт НЕПОМЕЧЕННЫМ: датапат применяет к нему тот же план,\n"
        "что и к потоку браузера. Это и есть смысл инструмента.\n");
}

static int resolve_first(const char *name, char *out, size_t cap) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(name, NULL, &hints, &res) != 0 || !res) { return -1; }
    int rc = getnameinfo(res->ai_addr, res->ai_addrlen, out, (socklen_t)cap,
                         NULL, 0, NI_NUMERICHOST);
    freeaddrinfo(res);
    return rc == 0 ? 0 : -1;
}

/* Длина живого приветствия браузера: ловушка датапата и ожидание. */
static int snapshot_wire(const char *name, long wait_ms, size_t *out_wire) {
    char err[200];
    int fd = d2k_link_open(NULL, err, sizeof err);
    if (fd < 0) {
        fprintf(stderr, "нет связи с датапатом: %s\n", err);
        return -1;
    }
    if (d2k_link_arm_shape(fd, name, 6, err, sizeof err) != 0) {
        fprintf(stderr, "ловушка снимка не взвелась: %s\n", err);
        d2k_link_close(fd);
        return -1;
    }
    fprintf(stderr, "жду приветствие браузера к %s (до %ld мс): откройте сайт\n",
            name, wait_ms);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = -1;
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long spent = (now.tv_sec - t0.tv_sec) * 1000L +
                     (now.tv_nsec - t0.tv_nsec) / 1000000L;
        if (spent >= wait_ms) {
            fprintf(stderr, "приветствия не дождались за %ld мс\n", wait_ms);
            break;
        }
        d2k_ev ev;
        int r = d2k_link_next(fd, &ev, (int)(wait_ms - spent), err, sizeof err);
        if (r < 0) { fprintf(stderr, "связь с датапатом: %s\n", err); break; }
        if (r == 1) { continue; }
        if (ev.kind != D2K_EV_SHAPE || ev.transport != 6) { continue; }
        *out_wire = ev.shape_len;
        fprintf(stderr, "снято приветствие браузера: %zu байт\n", ev.shape_len);
        rc = 0;
        break;
    }
    d2k_link_close(fd);
    return rc;
}

int main(int argc, char **argv) {
    const char *name = NULL, *ip = NULL, *path = "/";
    uint16_t port = 443;
    size_t wire = 0;
    int tls12 = 0, deadline = 15000, ladder = 0, quic = 0;
    uint32_t mark = 0;
    long snap_ms = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int last = i + 1 >= argc;
        if (!strcmp(a, "--name") && !last) { name = argv[++i]; }
        else if (!strcmp(a, "--ip") && !last) { ip = argv[++i]; }
        else if (!strcmp(a, "--path") && !last) { path = argv[++i]; }
        else if (!strcmp(a, "--port") && !last) { port = (uint16_t)atoi(argv[++i]); }
        else if (!strcmp(a, "--wire") && !last) { wire = (size_t)atol(argv[++i]); }
        else if (!strcmp(a, "--deadline") && !last) { deadline = atoi(argv[++i]); }
        else if (!strcmp(a, "--tls12")) { tls12 = 1; }
        else if (!strcmp(a, "--ladder")) { ladder = 1; }
        else if (!strcmp(a, "--quic")) { quic = 1; }
        else if (!strcmp(a, "--mark") && !last) { mark = (uint32_t)strtoul(argv[++i], NULL, 0); }
        else if (!strcmp(a, "--snapshot")) { snap_ms = 60000; }
        else if (!strncmp(a, "--snapshot=", 11)) { snap_ms = atol(a + 11); }
        else { usage(); return 2; }
    }
    if (!name || !name[0]) { usage(); return 2; }

    if (snap_ms > 0 && snapshot_wire(name, snap_ms, &wire) != 0) {
        return 1;  /* без живой длины мерить браузерным приветствием нечем */
    }
    if (quic && wire == 0) {
        /* У QUIC приветствие живёт внутри Initial-датаграммы (около 1200
           байт вместе с заголовками), и длина от TCP-профиля в неё не
           влезает. Ноль — не добивать: пусть клиент возьмёт свою
           естественную длину. */
    } else if (wire == 0) {
        /* Длина не названа и снимка нет: берём длину приветствия того же
           профиля, которым D2K меряет холодный старт, — это всё ещё
           браузерная форма, но её длина, а не длина чужого браузера. */
        static uint8_t probe[4096];
        size_t n = 0;
        if (d2k_hello_from_profile(tls12 ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN,
                                   name, probe, sizeof probe, &n) == 0) {
            wire = n;
        }
        fprintf(stderr, "длина приветствия не задана — беру профильную: %zu байт\n", wire);
    }

    char addr[128];
    if (!ip || !ip[0]) {
        if (resolve_first(name, addr, sizeof addr) != 0) {
            fprintf(stderr, "имя %s не разрешилось\n", name);
            return 1;
        }
        ip = addr;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (ladder) {
        /* Та же проба, которой меряет планировщик. С меткой она идёт мимо
           планов (меряет линию), без метки — через них, как браузер. */
        d2k_vol_result v = d2k_volume_probe_path(ip, port, name, port == 80,
                                                  tls12, wire, mark,
                                                  (path && path[0] && strcmp(path, "/"))
                                                      ? path : NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long lms = (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
        printf("цель:        %s (%s:%u), путь %s\n", name, ip, (unsigned)port, path);
        printf("приветствие: %zu байт, %s, метка 0x%x\n", wire,
               tls12 ? "TLS 1.2" : "TLS 1.3", (unsigned)mark);
        printf("лестница:    %s%s\n", d2k_vol_verdict_name(v.verdict),
               v.verdict == D2K_VOL_CUT ? "" : " (обрыва нет)");
        if (v.at_kb) { printf("оборвалась:  около %d КБ\n", v.at_kb); }
        if (v.rx_cut) { printf("вход:        обрыв ответа около %d КБ\n", v.rx_at_kb); }
        printf("время:       %ld мс\n", lms);
        if (v.reason[0]) { printf("причина:     %s\n", v.reason); }
        return v.verdict == D2K_VOL_CUT || v.rx_cut ? 1 : 0;
    }
    /* Без --mark обращение идёт НЕПОМЕЧЕННЫМ, и датапат применяет к нему тот
       же план, что к потоку браузера, — ради этого инструмент и сделан.
       С --mark пакеты уходят мимо очереди: так видно ГОЛУЮ линию, без
       обхода. Два прогона рядом отвечают на вопрос «обход работает или
       блокировки уже нет».
       «/» задаётся как NULL: у probe_path непустой путь — это свидетель-
       таблица стилей со своей проверкой допустимости, и «/» она отвергает. */
    const char *req = (path && path[0] && strcmp(path, "/")) ? path : NULL;
    /* QUIC-зонд метки не принимает по устройству: по QUIC инструмент всегда
       идёт через планы. */
    d2k_ver_result r = quic
        ? d2k_verify_probe_quic_path_on(-1, ip, port, name, deadline, wire, req)
        : d2k_verify_probe_path_on(-1, ip, port, name, deadline,
                                   wire, tls12, 0, mark, req);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;

    printf("цель:        %s (%s:%u), путь %s\n", name, ip, (unsigned)port, path);
    printf("приветствие: %zu байт, %s, %s\n", wire, tls12 ? "TLS 1.2" : "TLS 1.3",
           mark ? "МИМО планов (голая линия)" : "через планы (как браузер)");
    printf("TLS:         %s\n",
           r.negotiated_tls == 0x0304 ? "1.3" :
           r.negotiated_tls == 0x0303 ? "1.2" : "рукопожатия нет");
    printf("HTTP:        %d\n", r.status);
    if (r.body_has_length || r.body_chunked || r.body_bytes) {
        printf("тело:        %llu из %llu байт%s%s\n",
               (unsigned long long)r.body_bytes,
               (unsigned long long)r.body_expected,
               r.body_chunked ? " (chunked)" : "",
               r.body_encoding == 1 ? ", gzip" : "");
    }
    printf("итог:        %s\n",
           r.body_complete ? "ОТВЕТ ПОЛУЧЕН ЦЕЛИКОМ"
           : r.status      ? "ОБРЫВ: ответ начался и не доехал"
                           : "ОБРЫВ: ответа нет");
    printf("время:       %ld мс, местный порт %u\n", ms, (unsigned)r.local_port);
    if (r.reason[0]) { printf("причина:     %s\n", r.reason); }
    d2k_verify_close(&r);
    /* 0 — ответ целиком; 1 — оборвано; так вызывающий скрипт отличит их без
       разбора текста. */
    return r.body_complete ? 0 : 1;
}
