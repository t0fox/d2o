/* d2k_dnsprobe.h — проверка и обход блокировки DoH/DoT/DoQ.
 *
 * Задача: получить настоящий DNS-ответ от выбранного шифрованного резолвера,
 * доказав, что ответ принадлежит нашему запросу, и перебрать способы
 * предъявления имени (обычный SNI, SNI с точкой, без SNI), если сеть рвёт
 *连接 по имени. Это измерительный инструмент, а не транспорт для чужих данных:
 * сертификат проверяется только по имени (как в core/tls13.c), цепочка
 * доверия не строится.
 */
#ifndef D2K_DNSPROBE_H
#define D2K_DNSPROBE_H

#include <stddef.h>
#include <stdint.h>

#define D2K_DNS_NAME_MAX 254
#define D2K_DNS_ADDR_MAX 16
#define D2K_DNS_TEXT_MAX 64

typedef enum {
    D2K_DNS_PROTO_DOH = 0,
    D2K_DNS_PROTO_DOT = 1,
    D2K_DNS_PROTO_DOQ = 2,
    D2K_DNS_PROTO_PLAIN = 3
} d2k_dns_proto;

typedef enum {
    D2K_DNS_SNI_CANON = 0, /* host */
    D2K_DNS_SNI_DOT = 1,   /* host. — обход пословной блокировки имени */
    D2K_DNS_SNI_NONE = 2   /* без расширения server_name */
} d2k_dns_sni;

typedef enum {
    D2K_DNS_OK = 1,
    D2K_DNS_NXDOMAIN = 0,
    D2K_DNS_SPOOF = -1,
    D2K_DNS_MALFORMED = -2,
    D2K_DNS_IO = -3,
    D2K_DNS_SUBSTITUTED = -4
} d2k_dns_status;

typedef struct {
    char host[D2K_DNS_NAME_MAX]; /* имя, которое спрашивали */
    char ip[D2K_DNS_TEXT_MAX];   /* куда шли */
    uint16_t port;
    uint16_t id;
    d2k_dns_status status;
    int rcode;
    int answers;
    int64_t rtt_ms;
    char addr[D2K_DNS_ADDR_MAX][D2K_DNS_TEXT_MAX];
    int tls_peer_name; /* 1 совпало, 0 чужое, -1 не прочитано/не проверялось */
    char err[240];
} d2k_dns_result;

typedef struct {
    d2k_dns_proto proto;
    const char *host;   /* DNS-имя резолвера (SNI, Host, сертификат) */
    const char *ip;     /* IPv4/IPv6 текстом; NULL — взять системный getaddrinfo */
    uint16_t port;      /* 0 — 443 для DoH, 853 для DoT/DoQ */
    const char *path;   /* DoH: по умолчанию /dns-query */
    d2k_dns_sni sni;
    const char *query;  /* имя, чей A-адрес спрашиваем */
    int timeout_ms;     /* 0 — 6000 */
    uint32_t mark;      /* SO_MARK; 0 — не метить */
    int case_check;     /* 1 — требовать точный регистр имени (0x20) */
    const char *expect; /* если задан — ответ обязан содержать этот адрес */
} d2k_dns_opts;

/* Собирает запрос A/AAAA. Возвращает длину или 0. */
size_t d2k_dns_query_build(uint8_t *out, size_t cap, uint16_t id,
                           const char *name, uint16_t type);

/* Разбирает и проверяет ответ: тот же id, тот же вопрос, QR=1, RCODE,
 * нет TC, есть хотя бы один A/AAAA. Результат — в res (без сети). */
d2k_dns_status d2k_dns_answer_check(const uint8_t *msg, size_t len,
                                    uint16_t id, const char *name, uint16_t type,
                                    int exact_case, d2k_dns_result *res);

/* Один запрос выбранным протоколом и способом предъявления имени. */
d2k_dns_status d2k_dns_fetch(const d2k_dns_opts *o, d2k_dns_result *res);

/* Текст статуса для журнала. */
const char *d2k_dns_status_name(d2k_dns_status s);
const char *d2k_dns_sni_name(d2k_dns_sni s);
const char *d2k_dns_proto_name(d2k_dns_proto p);
/* Есть ли в результате ровно этот адрес (текстом). */
int d2k_dns_result_has(const d2k_dns_result *r, const char *addr);

#endif
