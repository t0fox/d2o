/* main.c — CLI d2k-dnsprobe: один запрос выбранным протоколом. */
#define _POSIX_C_SOURCE 200809L
#include "d2k_dnsprobe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(void)
{
    fprintf(stderr,
        "d2k-dnsprobe <doh|dot|doq|plain> <host> [флаги]\n"
        "d2k-dnsprobe search <manifest> [--json]\n"
        "  --ip ADDR        адрес резолвера (иначе системный getaddrinfo)\n"
        "  --port N         443 для doh, 853 для dot/doq, 53 для plain\n"
        "  --path PATH      DoH-путь (по умолчанию /dns-query)\n"
        "  --sni MODE       canon | dot | none (по умолчанию canon)\n"
        "  --name NAME      что спрашивать (по умолчанию wikipedia.org;\n"
        "                     example.com эти Smart DNS переписывают на 8.47.69.x)\n"
        "  --timeout MS     потолок (6000)\n"
        "  --repeats N      search: сколько подряд успехов нужно (1)\n"
        "  --mark HEX       SO_MARK\n"
        "  --expect IP      ответ обязан содержать этот адрес (анти-подмена)\n"
        "  --json           JSON-строка\n"
        "manifest: service|host|ip|proto|path[|expect[|port]], по строке; # — комментарий.\n");
}

static int parse_sni(const char *v, d2k_dns_sni *out)
{
    if (!strcmp(v, "dot")) { *out = D2K_DNS_SNI_DOT; return 0; }
    if (!strcmp(v, "none")) { *out = D2K_DNS_SNI_NONE; return 0; }
    if (!strcmp(v, "canon")) { *out = D2K_DNS_SNI_CANON; return 0; }
    return -1;
}

static int parse_proto(const char *v, d2k_dns_proto *out)
{
    if (!strcmp(v, "doh")) { *out = D2K_DNS_PROTO_DOH; return 0; }
    if (!strcmp(v, "dot")) { *out = D2K_DNS_PROTO_DOT; return 0; }
    if (!strcmp(v, "doq")) { *out = D2K_DNS_PROTO_DOQ; return 0; }
    if (!strcmp(v, "plain")) { *out = D2K_DNS_PROTO_PLAIN; return 0; }
    return -1;
}

/* Подбор как для голоса: сначала дешёвый и наиболее вероятный способ,
 * затем тот же endpoint другими способами предъявления имени. Первый
 * проверенный DNS-ответ останавливает поиск по услуге. */
static int search_file(const char *path, int json, int repeats, int timeout_ms)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 2; }
    char line[768];
    char service[64] = "";
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') { p++; }
        if (*p == '#' || *p == '\n' || *p == '\0') { continue; }
        char *nl = strchr(p, '\n');
        if (nl) { *nl = '\0'; }
        char *fields[7] = {0};
        int nf = 0;
        for (char *s = p; nf < 7; ) {
            fields[nf++] = s;
            char *bar = strchr(s, '|');
            if (!bar) { break; }
            *bar = '\0';
            s = bar + 1;
        }
        if (nf < 4) { continue; }
        if (strcmp(service, fields[0]) != 0) {
            if (service[0] && !found && !json) { printf("service=%s winner=none\n", service); }
            snprintf(service, sizeof service, "%s", fields[0]);
            found = 0;
        }
        if (found) { continue; }
        d2k_dns_proto proto;
        if (parse_proto(fields[3], &proto) != 0) { continue; }
        d2k_dns_sni modes[3];
        int nm = 0;
        if (proto == D2K_DNS_PROTO_DOH) {
            modes[nm++] = D2K_DNS_SNI_CANON;
            modes[nm++] = D2K_DNS_SNI_DOT;
            modes[nm++] = D2K_DNS_SNI_NONE;
        } else if (proto == D2K_DNS_PROTO_DOT) {
            modes[nm++] = D2K_DNS_SNI_CANON;
            modes[nm++] = D2K_DNS_SNI_NONE;
            modes[nm++] = D2K_DNS_SNI_DOT;
        } else {
            modes[nm++] = D2K_DNS_SNI_CANON;
        }
        for (int m = 0; m < nm && !found; m++) {
            d2k_dns_opts o;
            memset(&o, 0, sizeof o);
            o.proto = proto;
            o.host = fields[1];
            o.ip = fields[2];
            o.path = nf >= 5 ? fields[4] : NULL;
            o.sni = modes[m];
            o.query = "wikipedia.org";
            o.timeout_ms = timeout_ms;
            o.case_check = 1;
            o.expect = (nf >= 6 && fields[5][0]) ? fields[5] : NULL;
            o.port = nf >= 7 ? (uint16_t)strtoul(fields[6], NULL, 0) : 0;
            d2k_dns_result r;
            int ok = 1;
            d2k_dns_status st = D2K_DNS_IO;
            for (int rep = 0; rep < repeats && ok; rep++) {
                st = d2k_dns_fetch(&o, &r);
                if (st != D2K_DNS_OK) { ok = 0; }
                if (!json) {
                    printf("  try service=%s proto=%s ip=%s sni=%s rep=%d/%d -> %s rtt=%lldms%s%s\n",
                           fields[0], d2k_dns_proto_name(proto), fields[2],
                           d2k_dns_sni_name(modes[m]), rep + 1, repeats,
                           d2k_dns_status_name(st), (long long)r.rtt_ms,
                           r.err[0] ? " " : "", r.err);
                }
            }
            if (ok) {
                found = 1;
                if (json) {
                    printf("{\"service\":\"%s\",\"proto\":\"%s\",\"host\":\"%s\","
                           "\"ip\":\"%s\",\"sni\":\"%s\",\"path\":\"%s\",\"answers\":%d,"
                           "\"rtt_ms\":%lld}\n",
                           fields[0], d2k_dns_proto_name(proto), fields[1],
                           fields[2], d2k_dns_sni_name(modes[m]),
                           nf >= 5 ? fields[4] : "", r.answers, (long long)r.rtt_ms);
                } else {
                    printf("service=%s winner=%s host=%s ip=%s sni=%s answers=%d rtt=%lldms",
                           fields[0], d2k_dns_proto_name(proto), fields[1],
                           fields[2], d2k_dns_sni_name(modes[m]), r.answers,
                           (long long)r.rtt_ms);
                    for (int a = 0; a < r.answers && a < D2K_DNS_ADDR_MAX; a++) {
                        printf(" %s", r.addr[a]);
                    }
                    printf("\n");
                }
            }
        }
    }
    if (service[0] && !found && !json) { printf("service=%s winner=none\n", service); }
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) { usage(); return 2; }
    if (!strcmp(argv[1], "search")) {
        int json = 0;
        int repeats = 1;
        int timeout_ms = 6000;
        for (int i = 3; i < argc; i++) {
            if (!strcmp(argv[i], "--json")) { json = 1; }
            else if (!strcmp(argv[i], "--repeats") && i + 1 < argc) {
                repeats = atoi(argv[++i]);
                if (repeats < 1) { repeats = 1; }
            } else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) {
                timeout_ms = atoi(argv[++i]);
                if (timeout_ms < 1000) { timeout_ms = 1000; }
            } else {
                fprintf(stderr, "неизвестный флаг поиска %s\n", argv[i]);
                return 2;
            }
        }
        return search_file(argv[2], json, repeats, timeout_ms);
    }
    d2k_dns_opts o;
    memset(&o, 0, sizeof o);
    o.timeout_ms = 6000;
    o.query = "wikipedia.org";
    o.sni = D2K_DNS_SNI_CANON;
    if (parse_proto(argv[1], &o.proto) != 0) { usage(); return 2; }
    o.host = argv[2];
    int json = 0;
    for (int i = 3; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--ip") && v) { o.ip = v; i++; }
        else if (!strcmp(a, "--port") && v) { o.port = (uint16_t)strtoul(v, NULL, 0); i++; }
        else if (!strcmp(a, "--path") && v) { o.path = v; i++; }
        else if (!strcmp(a, "--name") && v) { o.query = v; i++; }
        else if (!strcmp(a, "--timeout") && v) { o.timeout_ms = atoi(v); i++; }
        else if (!strcmp(a, "--mark") && v) { o.mark = (uint32_t)strtoul(v, NULL, 0); i++; }
        else if (!strcmp(a, "--sni") && v) { if (parse_sni(v, &o.sni) != 0) { usage(); return 2; } i++; }
        else if (!strcmp(a, "--expect") && v) { o.expect = v; i++; }
        else if (!strcmp(a, "--json")) { json = 1; }
        else { fprintf(stderr, "неизвестный флаг %s\n", a); return 2; }
    }
    d2k_dns_result r;
    d2k_dns_status st = d2k_dns_fetch(&o, &r);
    if (json) {
        printf("{\"proto\":\"%s\",\"sni\":\"%s\",\"host\":\"%s\",\"ip\":\"%s\","
               "\"status\":\"%s\",\"answers\":%d,\"rtt_ms\":%lld,\"peer_name\":%d,\"err\":\"%s\",\"addr\":[",
               d2k_dns_proto_name(o.proto), d2k_dns_sni_name(o.sni), o.host,
               r.ip, d2k_dns_status_name(st), r.answers, (long long)r.rtt_ms,
               r.tls_peer_name, r.err);
        for (int i = 0; i < r.answers && i < D2K_DNS_ADDR_MAX; i++) {
            printf("%s\"%s\"", i ? "," : "", r.addr[i]);
        }
        printf("]}\n");
    } else {
        printf("proto=%s sni=%s host=%s ip=%s port=%u status=%s answers=%d rtt=%lldms peer_name=%d\n",
               d2k_dns_proto_name(o.proto), d2k_dns_sni_name(o.sni), o.host,
               r.ip, (unsigned)r.port, d2k_dns_status_name(st), r.answers,
               (long long)r.rtt_ms, r.tls_peer_name);
        for (int i = 0; i < r.answers && i < D2K_DNS_ADDR_MAX; i++) {
            printf("  %s\n", r.addr[i]);
        }
        if (r.err[0]) { printf("  err: %s\n", r.err); }
    }
    return st == D2K_DNS_OK ? 0 : 1;
}
