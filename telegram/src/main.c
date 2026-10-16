#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "../../runtime/d2k_runtime.h"
#include "tg_config.h"
#include "tg_net.h"
#include "tg_tls.h"
#include "tg_dc_map.h"
#include "tg_epoll_proxy.h"
#include "tg_transparent.h"
#include "tg_mtproto.h"
#include "tg_mtproto_discovery.h"
#include "tg_stats_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TG_BUILD "d2k-tg-0.3"
#define TG_DC_REFRESH_SECS (6u * 60u * 60u)
#define TG_DC_REFRESH_RETRY_SECS (60u * 60u)

static const char *health_path = "/tmp/d2k/d2ktg.health";
static volatile sig_atomic_t stop_requested;

static void on_signal(int signo) { (void)signo;stop_requested=1; }

static void log_msg(const char *message) {
    time_t now=time(NULL);struct tm tmv;char stamp[32]="unknown-time";
    if(localtime_r(&now,&tmv))strftime(stamp,sizeof(stamp),"%Y-%m-%d %H:%M:%S",&tmv);
    fprintf(stderr,"%s d2ktg: %s\n",stamp,message);fflush(stderr);
}

static int write_status(const char *path,const char *value) {
    char tmp[600];if(!path||!*path||snprintf(tmp,sizeof(tmp),"%s.tmp.%ld",path,(long)getpid())>=(int)sizeof(tmp))return -1;
    int fd=open(tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0644);if(fd<0)return -1;
    size_t len=strlen(value);ssize_t n=write(fd,value,len);int ok=n==(ssize_t)len&&fsync(fd)==0;
    if(close(fd)!=0)ok=0;
    if(!ok||rename(tmp,path)!=0){unlink(tmp);return -1;}
    return 0;
}

static int create_local_listener(uint16_t port) {
    int one = 1;
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd >= 0) {
        int flags = fcntl(fd, F_GETFL, 0);
        int v6only = 0;
        struct sockaddr_in6 address = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(port),
            .sin6_addr = IN6ADDR_ANY_INIT
        };
        if (flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 &&
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0 &&
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
                       sizeof(v6only)) == 0 &&
            bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0 &&
            listen(fd, 256) == 0)
            return fd;
        close(fd);
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {.s_addr = htonl(INADDR_ANY)}
    };
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
        bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(fd, 256) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int refresh_local_dc_map(tg_dc_map_store *store, int64_t now) {
    static const struct {
        const char *address;
        uint32_t dc_id;
    } bootstrap[] = {
        {"149.154.175.50", 1},
        {"2001:b28:f23d:f001::a", 1}
    };
    for (size_t i = 0; i < sizeof(bootstrap) / sizeof(bootstrap[0]); ++i) {
        tg_dc_snapshot snapshot = {0};
        if (tg_mtproto_discover_config(bootstrap[i].address, 443,
                                       bootstrap[i].dc_id, 4000, 0x31, now,
                                       &snapshot) == 0) {
            int installed = tg_dc_map_store_install(store, &snapshot, now);
            tg_dc_snapshot_destroy(&snapshot);
            if (installed == 0) return 0;
        }
    }
    return -1;
}

static int run_local_daemon(const char *config_path) {
    static const uint16_t allowed_ports[] = {443};
    static const char *const allowed_cidrs[] = {
        "149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22",
        "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
        "91.108.56.0/22", "91.105.192.0/23", "95.161.64.0/20",
        "185.76.151.0/24", "2001:67c:4e8::/48", "2001:b28:f23c::/47",
        "2001:b28:f23f::/48", "2a0a:f280:203::/48"
    };
    const uint16_t listen_ports[] = {TG_LISTEN_PORT};
    tg_config cfg;
    tg_dc_map_store map_store = {0};
    tg_cf_domain_pool cf_domain_pool = {0};
    tg_epoll_proxy *proxy = NULL;
    SSL_CTX *tls_context = NULL;
    tg_stats_socket stats_socket = {.fd = -1};
    int listener = -1, rc = 1;
    int64_t next_dc_refresh_at = 0;
    if (tg_config_read(config_path, &cfg) != 0) {
        log_msg("не удалось прочитать конфигурацию локального прокси");
        return 1;
    }
    if (!cfg.enabled) {
        (void)write_status(cfg.status_path, "stopped\n");
        tg_config_clean(&cfg);
        return 0;
    }
    int64_t now = (int64_t)time(NULL);
    if (!cfg.local_mode || tg_dc_map_store_init(&map_store, cfg.dc_map_path) != 0 ||
        tg_dc_map_store_load(&map_store, now) != 0) {
        log_msg("не удалось инициализировать проверенную карту Telegram DC");
        goto done;
    }
    if (tg_cf_domain_pool_init(&cf_domain_pool, cfg.cf_domain_cache_path,
            &cfg.cf_proxy_domains[0][0], cfg.cf_proxy_domain_count,
            cfg.default_domains) != 0) {
        log_msg("не удалось загрузить проверенный пул CF-доменов");
        goto done;
    }
    int initial_refresh_due = tg_dc_map_store_refresh_due(
        &map_store, now, TG_DC_REFRESH_SECS);
    if (initial_refresh_due) {
        if (refresh_local_dc_map(&map_store, now) == 0) {
            next_dc_refresh_at = now + TG_DC_REFRESH_SECS;
        } else {
            log_msg("не удалось обновить карту через Telegram; используется last-known-good или встроенная карта");
            next_dc_refresh_at = now + TG_DC_REFRESH_RETRY_SECS;
        }
    } else {
        next_dc_refresh_at = now + TG_DC_REFRESH_SECS;
    }
    tls_context = tg_tls_client_context(cfg.ca_bundle);
    if (!tls_context) {
        log_msg("не удалось загрузить доверенные сертификаты для direct WSS");
        goto done;
    }
    listener = create_local_listener(cfg.listen_port);
    if (listener < 0) {
        log_msg("не удалось открыть IPv4/IPv6 listener локального прокси");
        goto done;
    }
    tg_transparent_policy policy = {
        .map_store = &map_store,
        .allowed_ports = allowed_ports,
        .allowed_port_count = sizeof(allowed_ports) / sizeof(allowed_ports[0]),
        .allowed_cidrs = allowed_cidrs,
        .allowed_cidr_count = sizeof(allowed_cidrs) / sizeof(allowed_cidrs[0])
    };
    tg_epoll_proxy_config proxy_config = {
        .listener_fd = listener,
        .queue_bytes = 64u * 1024u,
        .memory_budget_bytes = 32u * 1024u * 1024u,
        .configured_max_connections = 64,
        .handshake_timeout_ms = 5000,
        .idle_timeout_ms = 300000,
        .socket_mark = 0x31,
        .require_socket_mark = 1,
        .enforce_self_dial = 1,
        .enable_direct_wss = 1,
        .tls_context = tls_context,
        .routing_config = &cfg,
        .cf_domain_pool = &cf_domain_pool,
        .listen_ports = listen_ports,
        .listen_port_count = sizeof(listen_ports) / sizeof(listen_ports[0]),
        .select_target = tg_transparent_select_target,
        .context = &policy
    };
    proxy = tg_epoll_proxy_create(&proxy_config);
    if (!proxy) {
        log_msg("не удалось запустить epoll-прокси с безопасным лимитом ресурсов");
        goto done;
    }
    if (tg_stats_socket_open(&stats_socket, cfg.stats_socket_path) != 0)
        log_msg("не удалось открыть локальный read-only socket статистики Telegram");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)signal(SIGPIPE, SIG_IGN);
    stop_requested = 0;
    (void)write_status(cfg.status_path, "local\n");
    log_msg("локальный Telegram TCP-прокси запущен через epoll");
    rc = 0;
    while (!stop_requested) {
        if (stats_socket.fd >= 0 &&
            tg_stats_socket_serve(&stats_socket, proxy) != 0)
            log_msg("ошибка обслуживания локального socket статистики Telegram");
        if (tg_epoll_proxy_step(proxy, 1000) < 0) {
            log_msg("ошибка epoll runtime локального Telegram-прокси");
            rc = 1;
            break;
        }
        if (stats_socket.fd >= 0 &&
            tg_stats_socket_serve(&stats_socket, proxy) != 0)
            log_msg("ошибка обслуживания локального socket статистики Telegram");
        int64_t refresh_now = (int64_t)time(NULL);
        if (refresh_now >= next_dc_refresh_at &&
            tg_dc_map_store_refresh_due(&map_store, refresh_now,
                                       TG_DC_REFRESH_SECS)) {
            if (refresh_local_dc_map(&map_store, refresh_now) == 0) {
                next_dc_refresh_at = refresh_now + TG_DC_REFRESH_SECS;
            } else {
                log_msg("не удалось периодически обновить карту Telegram; используется last-known-good или встроенная карта");
                next_dc_refresh_at = refresh_now + TG_DC_REFRESH_RETRY_SECS;
            }
        }
        int ready = d2k_runtime_listener_ready(listener);
        (void)d2k_runtime_heartbeat(health_path, NULL, 0, ready, ready);
    }
    (void)write_status(cfg.status_path, rc == 0 ? "stopped\n" : "error\n");
done:
    tg_stats_socket_close(&stats_socket);
    tg_epoll_proxy_destroy(proxy);
    SSL_CTX_free(tls_context);
    if (listener >= 0) close(listener);
    tg_cf_domain_pool_destroy(&cf_domain_pool);
    tg_dc_map_store_destroy(&map_store);
    tg_config_clean(&cfg);
    return rc;
}

static int check_config(const char *path) {
    tg_config cfg = {0};
    int ok = tg_config_read(path, &cfg) == 0 && cfg.local_mode &&
        cfg.listen_port == TG_LISTEN_PORT && cfg.dc_map_path[0] == '/' &&
        access(cfg.ca_bundle, R_OK) == 0;
    tg_config_clean(&cfg);
    return ok ? 0 : 1;
}

static int redirect_log(const char *path) {
    if(!path||!*path)return 0;
    int fd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW,0644);if(fd<0)return -1;
    if(dup2(fd,STDERR_FILENO)<0){close(fd);return -1;}close(fd);return 0;
}

/* DNS edge health, not an application/bypass verdict. Keep the certificate
   bound to the requested Meta name while avoiding its blocked wire SNI.
   No HTTP requests, account data, or relay traffic are involved.
   The list is the router script's HOSTS and the VPS /resolve allowlist
   (scripts/test-instagram-dns.sh compares all three). Measured 03.10.2026
   with SNI example.com: Instagram edges present *.instagram.com and
   *.cdninstagram.com; fbcdn edges *.facebook.com with *.xx.fbcdn.net in SAN;
   WhatsApp edges *.whatsapp.net with *.whatsapp.com in SAN (static/mmg/pps
   .whatsapp.net match *.whatsapp.net). So every name is
   verified as itself, except the c10r alias below. */
static const char *const meta_hosts[]={
    /* META_HOSTS_BEGIN */
    "instagram.com","www.instagram.com","graph.instagram.com","api.instagram.com",
    "i.instagram.com","instagram.c10r.instagram.com","static.cdninstagram.com",
    "scontent.cdninstagram.com","static.xx.fbcdn.net","scontent.xx.fbcdn.net",
    "web.whatsapp.com","www.whatsapp.com","scontent.whatsapp.net","graph.whatsapp.com",
    "v.whatsapp.com","static.whatsapp.net","mmg.whatsapp.net","pps.whatsapp.net"
    /* META_HOSTS_END */
};

/* The certificate name that authenticates host, or NULL outside the list. */
static const char *meta_verify_name(const char *host) {
    for(size_t i=0;i<sizeof(meta_hosts)/sizeof(meta_hosts[0]);i++){
        if(strcmp(host,meta_hosts[i])!=0)continue;
        /* This DNS alias is not covered by *.instagram.com; authenticate its
           canonical service rather than disabling certificate validation. */
        return strcmp(host,"instagram.c10r.instagram.com")==0?"instagram.com":meta_hosts[i];
    }
    return NULL;
}

static int check_instagram_ip(const char *host,const char *ip,const char *ca) {
    struct in_addr address;const char *verify=meta_verify_name(host);
    if(!verify||inet_pton(AF_INET,ip,&address)!=1)return 2;
    (void)signal(SIGPIPE,SIG_IGN);
    alarm(5); /* Bound the entire operation, including slow TLS peers. */
    SSL_CTX *ctx=tg_tls_client_context(ca);if(!ctx)return 1;
    int fd=tg_tcp_connect_ipv4(ip,443,3000);
    SSL *ssl=fd<0?NULL:tg_tls_connect_fd_sni(ctx,fd,verify,"example.com");
    int rc=ssl?0:1;
    if(ssl) { puts("Meta edge reachable; certificate verified (not a bypass verdict)"); }
    SSL_free(ssl);SSL_CTX_free(ctx);if(fd>=0)close(fd);alarm(0);return rc;
}

static int offline_self_check(void) {
    return OPENSSL_init_ssl(0,NULL)==1?0:-1;
}

static int parse_unsigned_arg(const char *text, unsigned long max,
                              unsigned long *value) {
    if (!text || !*text || !value) return -1;
    for (const char *p = text; *p; ++p)
        if (*p < '0' || *p > '9') return -1;
    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno || !end || *end || parsed == 0 || parsed > max) return -1;
    *value = parsed;
    return 0;
}

static int check_telegram_dc(const char *address, const char *dc_text,
                            const char *port_text) {
    struct in_addr v4;
    struct in6_addr v6;
    unsigned long dc, port = 443;
    if ((!inet_pton(AF_INET, address, &v4) &&
         !inet_pton(AF_INET6, address, &v6)) ||
        parse_unsigned_arg(dc_text, 999, &dc) != 0 ||
        (port_text && parse_unsigned_arg(port_text, 65535, &port) != 0)) {
        puts("{\"ok\":false,\"stage\":\"input\",\"error\":\"invalid_arguments\"}");
        return 2;
    }
    tg_mtproto_probe_result result = {0};
    tg_mtproto_probe_status status = tg_mtproto_probe_res_pq(
        address, (uint16_t)port, (uint32_t)dc, 0, 8000, &result);
    const char *stage = "input", *error = "invalid";
    switch (result.stage) {
    case TG_MTPROTO_PROBE_STAGE_TCP: stage = "tcp"; break;
    case TG_MTPROTO_PROBE_STAGE_MTPROTO: stage = "mtproto"; break;
    case TG_MTPROTO_PROBE_STAGE_RES_PQ: stage = "resPQ"; break;
    default: break;
    }
    switch (status) {
    case TG_MTPROTO_PROBE_OK: error = ""; break;
    case TG_MTPROTO_PROBE_TIMEOUT: error = "timeout"; break;
    case TG_MTPROTO_PROBE_CONNECT: error = "connect_failed"; break;
    case TG_MTPROTO_PROBE_IO: error = "io_error"; break;
    default: error = "invalid_resPQ"; break;
    }
    printf("{\"ok\":%s,\"stage\":\"%s\",\"dc\":%lu,\"address\":\"%s\",\"port\":%lu,\"latency_ms\":%llu,\"error\":\"%s\"}\n",
           status == TG_MTPROTO_PROBE_OK ? "true" : "false", stage, dc,
           address, port, (unsigned long long)result.latency_ms, error);
    return status == TG_MTPROTO_PROBE_OK ? 0 : 1;
}

static const char *telegram_probe_stage_name(tg_mtproto_probe_stage stage) {
    switch (stage) {
    case TG_MTPROTO_PROBE_STAGE_DNS: return "dns";
    case TG_MTPROTO_PROBE_STAGE_TCP: return "tcp";
    case TG_MTPROTO_PROBE_STAGE_TLS: return "tls";
    case TG_MTPROTO_PROBE_STAGE_WS: return "websocket";
    case TG_MTPROTO_PROBE_STAGE_MTPROTO: return "mtproto";
    case TG_MTPROTO_PROBE_STAGE_RES_PQ: return "resPQ";
    default: return "input";
    }
}

static const char *telegram_probe_error_name(tg_mtproto_probe_error error) {
    switch (error) {
    case TG_MTPROTO_PROBE_ERROR_NONE: return "";
    case TG_MTPROTO_PROBE_ERROR_INVALID_INPUT: return "invalid_arguments";
    case TG_MTPROTO_PROBE_ERROR_DNS: return "dns_failed";
    case TG_MTPROTO_PROBE_ERROR_CONNECT: return "connect_failed";
    case TG_MTPROTO_PROBE_ERROR_TLS_HANDSHAKE: return "tls_handshake_failed";
    case TG_MTPROTO_PROBE_ERROR_TLS_VERIFY: return "tls_verify_failed";
    case TG_MTPROTO_PROBE_ERROR_WS_UPGRADE: return "websocket_upgrade_failed";
    case TG_MTPROTO_PROBE_ERROR_MTPROTO_RESPONSE:
        return "invalid_mtproto_response";
    case TG_MTPROTO_PROBE_ERROR_TIMEOUT: return "timeout";
    case TG_MTPROTO_PROBE_ERROR_IO: return "io_error";
    default: return "unknown_error";
    }
}

static int check_telegram_wss_matrix(const char *ca_bundle) {
    if (!ca_bundle || !*ca_bundle) ca_bundle = "/opt/d2k/files/tg-roots.pem";
    SSL_CTX *tls_context = tg_tls_client_context(ca_bundle);
    if (!tls_context) {
        puts("{\"ok\":false,\"stage\":\"input\",\"error\":\"ca_bundle_unavailable\"}");
        return 2;
    }
    int failed = 0;
    for (uint32_t dc = 1; dc <= 5; ++dc) {
        char hostname[64];
        int n = snprintf(hostname, sizeof(hostname),
                         "kws%u.web.telegram.org", dc);
        if (n <= 0 || (size_t)n >= sizeof(hostname)) {
            failed = 1;
            continue;
        }
        tg_mtproto_probe_result result = {0};
        tg_mtproto_probe_status status = tg_mtproto_probe_res_pq_wss(
            tls_context, hostname, dc, 8000, &result);
        printf("{\"ok\":%s,\"route\":\"direct_wss\",\"stage\":\"%s\",\"dc\":%u,\"host\":\"%s\",\"latency_ms\":%llu,\"error\":\"%s\"}\n",
               status == TG_MTPROTO_PROBE_OK ? "true" : "false",
               telegram_probe_stage_name(result.stage), dc, hostname,
               (unsigned long long)result.latency_ms,
               telegram_probe_error_name(result.error));
        if (status != TG_MTPROTO_PROBE_OK) failed = 1;
    }
    SSL_CTX_free(tls_context);
    return failed;
}
static int discover_telegram_dc(const char *address, const char *dc_text,
                               const char *port_text) {
    struct in_addr v4;
    struct in6_addr v6;
    unsigned long dc, port = 443;
    if ((!inet_pton(AF_INET, address, &v4) &&
         !inet_pton(AF_INET6, address, &v6)) ||
        parse_unsigned_arg(dc_text, 999, &dc) != 0 ||
        (port_text && parse_unsigned_arg(port_text, 65535, &port) != 0)) {
        puts("{\"ok\":false,\"stage\":\"input\",\"error\":\"invalid_arguments\"}");
        return 2;
    }
    tg_dc_snapshot snapshot = {0};
    int rc = tg_mtproto_discover_config(address, (uint16_t)port,
                                        (uint32_t)dc, 8000, 0,
                                        (int64_t)time(NULL), &snapshot);
    if (rc == 0) {
        printf("{\"ok\":true,\"stage\":\"help.getConfig\",\"dc\":%lu,\"address\":\"%s\",\"port\":%lu,\"this_dc\":%u,\"endpoint_count\":%zu,\"config_date\":%lld,\"config_expires\":%lld}\n",
               dc, address, port, snapshot.this_dc, snapshot.endpoint_count,
               (long long)snapshot.config_date,
               (long long)snapshot.config_expires);
        tg_dc_snapshot_destroy(&snapshot);
        return 0;
    }
    printf("{\"ok\":false,\"stage\":\"help.getConfig\",\"dc\":%lu,\"address\":\"%s\",\"port\":%lu,\"error\":\"discovery_failed\"}\n",
           dc, address, port);
    tg_dc_snapshot_destroy(&snapshot);
    return 1;
}

static const struct {
    const char *address;
    const char *dc;
} telegram_dc_matrix[] = {
    {"149.154.175.50", "1"},
    {"149.154.167.51", "2"},
    {"149.154.175.100", "3"},
    {"149.154.167.91", "4"},
    {"149.154.171.5", "5"}
};

static int check_telegram_dc_matrix(void) {
    int failed = 0;
    for (size_t i = 0; i < sizeof(telegram_dc_matrix) / sizeof(telegram_dc_matrix[0]); ++i)
        if (check_telegram_dc(telegram_dc_matrix[i].address,
                              telegram_dc_matrix[i].dc, NULL) != 0)
            failed = 1;
    return failed;
}

static int discover_telegram_dc_matrix(void) {
    int failed = 0;
    for (size_t i = 0; i < sizeof(telegram_dc_matrix) / sizeof(telegram_dc_matrix[0]); ++i)
        if (discover_telegram_dc(telegram_dc_matrix[i].address,
                                 telegram_dc_matrix[i].dc, NULL) != 0)
            failed = 1;
    return failed;
}

int main(int argc,char **argv) {
    int offline = d2k_runtime_offline(argc, argv, "d2ktg", offline_self_check);
    if (offline >= 0) return offline;
    const char *config="/opt/d2k/config",*log_path=NULL;
    if(argc==2&&strcmp(argv[1],"--version")==0){puts(TG_BUILD " features=instagram-ip-probe,meta-hosts-v3,telegram-local-tcp-epoll,mtproto-respq,mtproto-auth,mtproto-v2,mtproto-help-config,mtproto-gzip-config,mtproto-wss-probe release=" D2K_RELEASE_ID);return 0;}
    if(argc==5&&strcmp(argv[1],"--check-instagram-ip")==0)return check_instagram_ip(argv[2],argv[3],argv[4]);
    if((argc==4||argc==5)&&strcmp(argv[1],"--check-telegram-dc")==0)return check_telegram_dc(argv[2],argv[3],argc==5?argv[4]:NULL);
    if((argc==4||argc==5)&&strcmp(argv[1],"--discover-telegram-dc")==0)return discover_telegram_dc(argv[2],argv[3],argc==5?argv[4]:NULL);
    if(argc==2&&strcmp(argv[1],"--check-telegram-dc-matrix")==0)return check_telegram_dc_matrix();
    if(argc==2&&strcmp(argv[1],"--discover-telegram-dc-matrix")==0)return discover_telegram_dc_matrix();
    if((argc==2||argc==3)&&strcmp(argv[1],"--check-telegram-wss-matrix")==0)return check_telegram_wss_matrix(argc==3?argv[2]:NULL);
    if(argc==2&&strcmp(argv[1],"--help")==0){puts("d2ktg [--config FILE] | --check-telegram-dc-matrix | --discover-telegram-dc-matrix | --check-telegram-wss-matrix [CA_BUNDLE] | --check-telegram-dc IP DC [PORT] | --discover-telegram-dc IP DC [PORT]");return 0;}
    if(argc==3&&strcmp(argv[1],"--check-config")==0)return check_config(argv[2]);
    for(int i=1;i<argc;i++) {
        if(strcmp(argv[i],"--health-file")==0&&i+1<argc)health_path=argv[++i];
        else if(strcmp(argv[i],"--config")==0&&i+1<argc)config=argv[++i];
        else if(strcmp(argv[i],"--log")==0&&i+1<argc)log_path=argv[++i];
        else {fprintf(stderr,"usage: d2ktg [--config FILE] [--log FILE]\n");return 2;}
    }
    if(redirect_log(log_path)!=0){fprintf(stderr,"d2ktg: cannot open configured log file\n");return 1;}
    return run_local_daemon(config);
}
