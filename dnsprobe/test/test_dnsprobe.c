/* test_dnsprobe.c — проверки без сети: форма запроса, анти-подмена, имя. */
#include "d2k_dnsprobe.h"
#include "d2k_tls13core.h"

#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(x, m) do { if (!(x)) { printf("FAIL %s (строка %d)\n", m, __LINE__); fails++; } \
                         else { printf("ok   %s\n", m); } } while (0)

static size_t add_answer(uint8_t *msg, size_t n, const uint8_t ip[4])
{
    /* указатель на вопрос в начале сообщения */
    msg[n++] = 0xC0; msg[n++] = 0x0C;
    msg[n++] = 0x00; msg[n++] = 0x01;       /* A */
    msg[n++] = 0x00; msg[n++] = 0x01;       /* IN */
    msg[n++] = 0x00; msg[n++] = 0x00;
    msg[n++] = 0x00; msg[n++] = 0x3C;       /* TTL 60 */
    msg[n++] = 0x00; msg[n++] = 0x04;       /* RDLENGTH */
    memcpy(msg + n, ip, 4); n += 4;
    msg[6] = 0; msg[7] = 1;                 /* ANCOUNT=1 */
    return n;
}

static void test_query(void)
{
    uint8_t q[128];
    size_t n = d2k_dns_query_build(q, sizeof q, 0xABCD, "example.com", 1);
    CHECK(n == 29, "длина запроса example.com/A");
    CHECK(q[0] == 0xAB && q[1] == 0xCD, "id запроса");
    CHECK(q[2] == 0x01, "RD выставлен");
    CHECK(q[4] == 0 && q[5] == 1, "QDCOUNT=1");
    CHECK(q[12] == 7 && memcmp(q + 13, "example", 7) == 0, "первая метка");
    CHECK(q[20] == 3 && memcmp(q + 21, "com", 3) == 0, "вторая метка");
    CHECK(q[n - 5] == 0 && q[n - 4] == 0 && q[n - 3] == 1 &&
          q[n - 2] == 0 && q[n - 1] == 1, "QTYPE=A QCLASS=IN");
    CHECK(d2k_dns_query_build(q, sizeof q, 1, "", 1) == 0, "пустое имя отвергнуто");
    CHECK(d2k_dns_query_build(q, sizeof q, 1, "a..b", 1) == 0, "пустая метка отвергнута");
    CHECK(d2k_dns_query_build(q, sizeof q, 1, "-bad.example", 1) == 0, "метка с '-' отвергнута");
}

static void test_answer(void)
{
    uint8_t q[128], r[256], ip[4] = {1, 2, 3, 4};
    size_t qn = d2k_dns_query_build(q, sizeof q, 0x1234, "example.com", 1);
    memcpy(r, q, qn);
    r[2] = 0x81; r[3] = 0x80;              /* QR=1, RD=1, RA=1, RCODE=0 */
    size_t rn = add_answer(r, qn, ip);

    d2k_dns_result res;
    CHECK(d2k_dns_answer_check(r, rn, 0x1234, "example.com", 1, 1, &res) == D2K_DNS_OK,
          "верный ответ принят");
    CHECK(res.answers == 1 && strcmp(res.addr[0], "1.2.3.4") == 0, "A-адрес извлечён");
    CHECK(d2k_dns_result_has(&res, "1.2.3.4") == 1, "ожидаемый адрес найден");
    CHECK(d2k_dns_result_has(&res, "5.6.7.8") == 0, "чужой адрес не найден");

    uint8_t bad[256];
    memcpy(bad, r, rn);
    bad[0] ^= 0xFF;
    CHECK(d2k_dns_answer_check(bad, rn, 0x1234, "example.com", 1, 1, &res) == D2K_DNS_SPOOF,
          "чужой id отвергнут");

    memcpy(bad, r, rn);
    bad[2] |= 0x02;                         /* TC */
    CHECK(d2k_dns_answer_check(bad, rn, 0x1234, "example.com", 1, 1, &res) == D2K_DNS_MALFORMED,
          "усечённый ответ отвергнут");

    memcpy(bad, r, rn);
    bad[3] = 0x83;                          /* NXDOMAIN */
    CHECK(d2k_dns_answer_check(bad, rn, 0x1234, "example.com", 1, 1, &res) == D2K_DNS_NXDOMAIN,
          "NXDOMAIN распознан");

    /* Другой вопрос при том же id — подмена. */
    d2k_dns_result r2;
    CHECK(d2k_dns_answer_check(r, rn, 0x1234, "example.org", 1, 1, &r2) == D2K_DNS_SPOOF,
          "чужой вопрос отвергнут");

    /* 0x20: регистр имени вопроса обязан совпасть. */
    uint8_t q2[128], r2b[256];
    size_t q2n = d2k_dns_query_build(q2, sizeof q2, 0x2222, "ExAmPle.CoM", 1);
    memcpy(r2b, q2, q2n);
    r2b[2] = 0x81; r2b[3] = 0x80;
    size_t r2n = add_answer(r2b, q2n, ip);
    CHECK(d2k_dns_answer_check(r2b, r2n, 0x2222, "ExAmPle.CoM", 1, 1, &r2) == D2K_DNS_OK,
          "0x20: точный регистр принят");
    CHECK(d2k_dns_answer_check(r2b, r2n, 0x2222, "example.com", 1, 1, &r2) == D2K_DNS_SPOOF,
          "0x20: другой регистр отвергнут");
}

/* Минимальный TLS 1.2 Certificate с SAN: парсеру важна только форма
   OID subjectAltName + OCTET STRING + SEQUENCE + dNSName. */
static size_t fake_cert12(uint8_t *out, size_t cap, const char *dns)
{
    uint8_t der[128];
    size_t d = 0;
    der[d++] = 0x30; der[d++] = 0x00;      /* SEQUENCE, длина ниже */
    der[d++] = 0x06; der[d++] = 0x03; der[d++] = 0x55; der[d++] = 0x1D; der[d++] = 0x11;
    size_t nl = strlen(dns);
    der[d++] = 0x04; der[d++] = (uint8_t)(nl + 4);
    der[d++] = 0x30; der[d++] = (uint8_t)(nl + 2);
    der[d++] = 0x82; der[d++] = (uint8_t)nl;
    memcpy(der + d, dns, nl); d += nl;
    der[1] = (uint8_t)(d - 2);

    uint8_t body[160];
    size_t b = 0;
    size_t list = 3 + d;
    body[b++] = (uint8_t)(list >> 16);
    body[b++] = (uint8_t)(list >> 8);
    body[b++] = (uint8_t)list;
    body[b++] = (uint8_t)(d >> 16);
    body[b++] = (uint8_t)(d >> 8);
    body[b++] = (uint8_t)d;
    memcpy(body + b, der, d); b += d;
    (void)cap;
    memcpy(out, body, b);
    return b;
}

static void test_cert_name(void)
{
    uint8_t body[256];
    size_t n = fake_cert12(body, sizeof body, "example.com");
    CHECK(d2k_t13_cert_name_ok12(body, n, "example.com") == 1, "сертификат: имя совпало");
    CHECK(d2k_t13_cert_name_ok12(body, n, "example.com.") == 1,
          "сертификат: FQDN с точкой — то же имя");
    CHECK(d2k_t13_cert_name_ok12(body, n, "example.org") == 0, "сертификат: чужое имя");

    n = fake_cert12(body, sizeof body, "*.example.com");
    CHECK(d2k_t13_cert_name_ok12(body, n, "a.example.com.") == 1,
          "сертификат: wildcard с точкой");
}

int main(void)
{
    test_query();
    test_answer();
    test_cert_name();
    if (fails) { printf("%d FAIL\n", fails); return 1; }
    printf("all ok\n");
    return 0;
}
