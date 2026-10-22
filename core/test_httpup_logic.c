#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_httpup.h"

static int failures;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL: %s\n", m); failures++; } } while (0)

int main(void) {
    char out[4096];

    static const char get[] = "GET /forum/index.php?q=1 HTTP/1.1\r\nHost: RuTracker.org:80\r\nConnection: close\r\n\r\n";
    CHECK(d2k_httpup_request_safe(get, sizeof get - 1),
          "safe origin-form GET was not recognized");

    static const char post[] = "POST /login HTTP/1.1\r\nHost: rutracker.org\r\n\r\n";
    static const char no_host[] = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    static const char absolute[] =
        "GET http://rutracker.org/ HTTP/1.1\r\nHost: rutracker.org\r\n\r\n";
    static const char portal[] =
        "HTTP/1.1 302 Found\r\nLocation: http://lawfilter.ertelecom.ru/deny?id=7\r\n"
        "Content-Length: 0\r\n\r\n";
    static const char ordinary_cross_host[] =
        "HTTP/1.1 302 Found\r\nLocation: https://login.example.net/continue\r\n"
        "Content-Length: 0\r\n\r\n";
    static const char same_host[] =
        "HTTP/1.1 302 Found\r\nLocation: https://rutracker.org/forum/\r\n"
        "Content-Length: 0\r\n\r\n";
    static const char deceptive_marker[] =
        "HTTP/1.1 302 Found\r\nLocation: https://unblocked.example/continue\r\n"
        "Content-Length: 0\r\n\r\n";
    static const char megafon_portal[] =
        "HTTP/1.1 302 Found\r\nLocation: https://m.megafonpro.ru/rkn-auth?channel=2m\r\n"
        "Content-Length: 0\r\n\r\n";
    static const char rt_portal[] =
        "HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/\r\n"
        "Content-Length: 0\r\n\r\n";
    static const char beeline_portal[] =
        "HTTP/1.1 302 Found\r\nLocation: http://warn.beeline.ru/\r\n"
        "Content-Length: 0\r\n\r\n";
    static const char megafon_deny[] =
        "HTTP/1.1 302 Found\r\nLocation: http://deny.megafon.ru/blocked\r\n"
        "Content-Length: 0\r\n\r\n";
    static const char unrelated_rkn_path[] =
        "HTTP/1.1 302 Found\r\nLocation: http://isp.example.org/rkn-landing/rkn?id=1\r\n"
        "Content-Length: 0\r\n\r\n";
    char bounded_rt[sizeof rt_portal - 1];
    memcpy(bounded_rt, rt_portal, sizeof bounded_rt);
    static const char not_redirect[] =
        "HTTP/1.1 200 OK\r\nLocation: https://lawfilter.example/\r\n"
        "Content-Length: 0\r\n\r\n";
    CHECK(!d2k_httpup_request_safe(post, sizeof post - 1),
          "POST body was treated as a safe navigation request");
    CHECK(!d2k_httpup_request_safe(no_host, sizeof no_host - 1),
          "malformed request without Host was treated as safe");
    CHECK(!d2k_httpup_request_safe(absolute, sizeof absolute - 1),
          "absolute-form proxy request was misinterpreted");
    CHECK(d2k_httpup_portal_response(get, sizeof get - 1, portal,
                                     sizeof portal - 1, out, sizeof out) &&
          strstr(out, "Location: https://RuTracker.org/forum/index.php?q=1\r\n") &&
          strstr(out, "provider-portal"),
          "explicit provider portal redirect did not restart navigation over HTTPS");
    CHECK(d2k_httpup_portal_response(get, sizeof get - 1, megafon_portal,
                                     sizeof megafon_portal - 1, out, sizeof out),
          "портал Megafon не распознан");
    CHECK(d2k_httpup_portal_response(get, sizeof get - 1, rt_portal,
                                     sizeof rt_portal - 1, out, sizeof out),
          "портал Ростелекома не распознан");
    CHECK(d2k_httpup_portal_response(get, sizeof get - 1, bounded_rt,
                                     sizeof bounded_rt, out, sizeof out),
          "ограниченный ответ без NUL не обработан");
    CHECK(d2k_httpup_portal_response(get, sizeof get - 1, beeline_portal,
                                     sizeof beeline_portal - 1, out, sizeof out),
          "портал Beeline не распознан");
    CHECK(d2k_httpup_portal_response(get, sizeof get - 1, megafon_deny,
                                     sizeof megafon_deny - 1, out, sizeof out),
          "портал отказа Megafon не распознан");
    CHECK(!d2k_httpup_portal_response(get, sizeof get - 1, unrelated_rkn_path,
                                      sizeof unrelated_rkn_path - 1, out, sizeof out),
          "чужой редирект с путём /rkn ошибочно признан порталом");
    CHECK(!d2k_httpup_portal_response(get, sizeof get - 1, ordinary_cross_host,
                                      sizeof ordinary_cross_host - 1, out, sizeof out),
          "ordinary cross-host login redirect was mistaken for a filter portal");
    CHECK(!d2k_httpup_portal_response(get, sizeof get - 1, same_host,
                                      sizeof same_host - 1, out, sizeof out),
          "same-host canonical HTTPS redirect was mistaken for a filter portal");
    CHECK(!d2k_httpup_portal_response(get, sizeof get - 1, deceptive_marker,
                                      sizeof deceptive_marker - 1, out, sizeof out),
          "a hostname containing 'blocked' as a substring was misclassified");
    CHECK(!d2k_httpup_portal_response(get, sizeof get - 1, not_redirect,
                                      sizeof not_redirect - 1, out, sizeof out),
          "a 200 response with a Location header was treated as a redirect");

    static const char has_body[] =
        "GET / HTTP/1.1\r\nHost: rutracker.org\r\nContent-Length: 1\r\n\r\nx";
    CHECK(!d2k_httpup_request_safe(has_body, sizeof has_body - 1),
          "request with a body was treated as safe to redirect/inspect");
    static const char unframed_tail[] =
        "GET / HTTP/1.1\r\nHost: rutracker.org\r\n\r\nx";
    CHECK(!d2k_httpup_request_safe(unframed_tail, sizeof unframed_tail - 1),
          "unframed bytes after GET headers were accepted for redirect");

    if (failures) { printf("test_httpup_logic: %d failures\n", failures); return 1; }
    puts("test_httpup_logic: OK");
    return 0;
}
