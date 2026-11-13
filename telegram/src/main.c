#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
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
#include "tg_cf_domains.h"
#include "tg_route_dns.h"
#include "tg_route_plan.h"
#include "tg_listener.h"
#include "tg_limits.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TG_BUILD "d2k-tg-0.3"
#define TG_LOW_MEMORY_ROUTER_BYTES (128u * 1024u * 1024u)
#define TG_RESOURCE_REFRESH_MS 5000u
#define TG_DC_REFRESH_SECS (6u * 60u * 60u)
#define TG_DC_REFRESH_RETRY_SECS (60u * 60u)
#define TG_DC_DISCOVERY_TIMEOUT_MS 12000u
#define TG_DC_DISCOVERY_TOTAL_MS 90000u
#define TG_DC_DISCOVERY_DNS_WAIT_MS 20000u
#define TG_DC_DISCOVERY_WORKER_LIMIT 3u

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

typedef struct {
    uint32_t dc_id;
    const char *address;
} dc_bootstrap;

static const dc_bootstrap dc_bootstraps[] = {
    {1, "149.154.175.50"},
    {2, "149.154.167.51"},
    {3, "149.154.175.100"},
    {4, "149.154.167.91"},
    {5, "149.154.171.5"},
    {203, "91.105.192.100"}
};

typedef struct {
    pthread_t thread;
    atomic_int done;
    atomic_int cancelled;
    int started;
    int result;
    int64_t now;
    const tg_config *config;
    tg_cf_domain_pool *cf_domains;
    tg_route_dns *route_dns;
    SSL_CTX *tls_context;
    tg_dc_snapshot snapshot;
} dc_refresh_job;

static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static int discovery_cancelled(const atomic_int *cancelled,
                               uint64_t deadline) {
    uint64_t now = monotonic_ms();
    return atomic_load_explicit(cancelled, memory_order_relaxed) || !now ||
           now >= deadline;
}

static int discover_wss_host(SSL_CTX *tls_context, tg_route_dns *route_dns,
                             const char *hostname, const char *path, int worker,
                             uint32_t dc_id, int64_t now,
                             const atomic_int *cancelled, uint64_t deadline,
                             tg_dc_snapshot *snapshot) {
    if (!route_dns || discovery_cancelled(cancelled, deadline) ||
        tg_route_dns_prefetch(route_dns, hostname) != 0)
        return -1;
    uint64_t now_ms = monotonic_ms();
    if (!now_ms) return -1;
    uint64_t dns_deadline = now_ms + TG_DC_DISCOVERY_DNS_WAIT_MS;
    if (dns_deadline > deadline) dns_deadline = deadline;
    tg_listener_destination seen[TG_ROUTE_DNS_ADDRESS_MAX] = {{0}};
    size_t seen_count = 0;
    while (!discovery_cancelled(cancelled, dns_deadline)) {
        tg_listener_destination target = {0};
        if (tg_route_dns_resolve(route_dns, hostname, &target) != 0) {
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 50000000L};
            (void)nanosleep(&pause, NULL);
            continue;
        }
        int duplicate = 0;
        for (size_t i = 0; i < seen_count; ++i) {
            size_t bytes = target.family == AF_INET ? 4u : 16u;
            if (seen[i].family == target.family &&
                memcmp(seen[i].address, target.address, bytes) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate || seen_count == TG_ROUTE_DNS_ADDRESS_MAX) break;
        seen[seen_count++] = target;
        char numeric_address[INET6_ADDRSTRLEN];
        const void *address = target.address;
        int family = target.family;
        if ((family != AF_INET && family != AF_INET6) ||
            !inet_ntop(family, address, numeric_address,
                       sizeof(numeric_address)))
            continue;
        if (discovery_cancelled(cancelled, deadline)) return -1;
        now_ms = monotonic_ms();
        if (!now_ms || now_ms >= deadline) return -1;
        uint64_t remaining = deadline - now_ms;
        uint32_t timeout = remaining < TG_DC_DISCOVERY_TIMEOUT_MS
            ? (uint32_t)remaining : TG_DC_DISCOVERY_TIMEOUT_MS;
        if (tg_mtproto_discover_config_wss(
                tls_context, numeric_address, hostname, path, worker, 443, dc_id,
                timeout, TG_OUTBOUND_SOCKET_MARK, now,
                snapshot) == 0)
            return 0;
    }
    return -1;
}

static int refresh_local_dc_map(const tg_config *config,
                                tg_cf_domain_pool *cf_domains,
                                tg_route_dns *route_dns,
                                SSL_CTX *tls_context, int64_t now,
                                const atomic_int *cancelled,
                                tg_dc_snapshot *snapshot) {
    if (!config || !cf_domains || !route_dns || !tls_context || !snapshot)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    uint64_t started = monotonic_ms();
    if (!started) return -1;
    uint64_t deadline = started + TG_DC_DISCOVERY_TOTAL_MS;
    size_t domain_count = config->route_only == TG_ROUTE_ONLY_WORKER
        ? 0 : tg_cf_domain_pool_count(cf_domains);
    size_t worker_count = config->route_only == TG_ROUTE_ONLY_CF_PROXY
        ? 0 : config->cf_worker_domain_count;
    if (worker_count > TG_DC_DISCOVERY_WORKER_LIMIT)
        worker_count = TG_DC_DISCOVERY_WORKER_LIMIT;
    size_t first_proxy = domain_count ? 1u : 0u;
    for (size_t i = 0; i < sizeof(dc_bootstraps) / sizeof(dc_bootstraps[0]); ++i) {
        uint32_t dc_id = dc_bootstraps[i].dc_id;
        /* Try the primary proxy, then Workers before the remaining proxies. */
        for (size_t route = 0; route < domain_count + worker_count; ++route) {
            if (discovery_cancelled(cancelled, deadline)) return -1;
            int worker = route >= first_proxy && route < first_proxy + worker_count;
            char hostname[TG_CF_DOMAIN_LEN + 16u];
            char path[128] = "/apiws";
            if (worker) {
                snprintf(hostname, sizeof(hostname), "%s",
                         config->cf_worker_domains[route - first_proxy]);
                int n = snprintf(path, sizeof(path), "/apiws?dst=%s&dc=%u&media=0",
                                 dc_bootstraps[i].address, dc_id);
                if (n <= 0 || (size_t)n >= sizeof(path)) continue;
            } else {
                size_t index = route == 0 ? 0 : route - worker_count;
                char domain[TG_CF_DOMAIN_LEN];
                if (tg_cf_domain_pool_copy_at(cf_domains, index, domain) != 0 ||
                    tg_route_cf_proxy_hostname(dc_id, 0, domain, hostname,
                                               sizeof(hostname)) != 0)
                    continue;
            }
            if (discover_wss_host(tls_context, route_dns, hostname, path, worker,
                    dc_id, now, cancelled, deadline, snapshot) == 0)
                return 0;
        }
    }
    return -1;
}

static void *dc_refresh_worker(void *opaque) {
    dc_refresh_job *job = opaque;
    job->result = refresh_local_dc_map(job->config, job->cf_domains,
        job->route_dns, job->tls_context, job->now, &job->cancelled,
        &job->snapshot);
    atomic_store_explicit(&job->done, 1, memory_order_release);
    return NULL;
}

static int start_dc_refresh(dc_refresh_job *job, const tg_config *config,
                            tg_cf_domain_pool *cf_domains,
                            tg_route_dns *route_dns, SSL_CTX *tls_context,
                            int64_t now) {
    if (!job || job->started) return -1;
    job->config = config;
    job->cf_domains = cf_domains;
    job->route_dns = route_dns;
    job->tls_context = tls_context;
    job->now = now;
    job->result = -1;
    memset(&job->snapshot, 0, sizeof(job->snapshot));
    atomic_store_explicit(&job->done, 0, memory_order_relaxed);
    atomic_store_explicit(&job->cancelled, 0, memory_order_relaxed);
    if (pthread_create(&job->thread, NULL, dc_refresh_worker, job) != 0)
        return -1;
    job->started = 1;
    return 0;
}

static int finish_dc_refresh(dc_refresh_job *job, tg_dc_map_store *store,
                             int64_t now) {
    if (!job || !job->started ||
        !atomic_load_explicit(&job->done, memory_order_acquire))
        return 0;
    (void)pthread_join(job->thread, NULL);
    int ok = job->result == 0 &&
             tg_dc_map_store_install(store, &job->snapshot, now) == 0;
    tg_dc_snapshot_destroy(&job->snapshot);
    job->started = 0;
    return ok ? 1 : -1;
}

static void stop_dc_refresh(dc_refresh_job *job) {
    if (!job || !job->started) return;
    atomic_store_explicit(&job->cancelled, 1, memory_order_relaxed);
    (void)pthread_join(job->thread, NULL);
    tg_dc_snapshot_destroy(&job->snapshot);
    job->started = 0;
}

static int read_memory_resources(size_t *total, size_t *available) {
    FILE *file = fopen("/proc/meminfo", "r");
    tg_limits_read_meminfo(file, total, available);
    if (file) fclose(file);
    return *total && *available <= *total;
}

static int run_local_daemon(const char *config_path) {
    static const uint16_t allowed_ports[] = {443, 5222};
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
    tg_stats_socket_context stats_context = {
        .dc_map = &map_store,
        .last_refresh_result = "never"
    };
    tg_cf_domain_pool cf_domain_pool = {0};
    tg_route_dns *discovery_dns = NULL;
    tg_epoll_proxy *proxy = NULL;
    SSL_CTX *tls_context = NULL;
    dc_refresh_job refresh_job = {0};
    tg_stats_socket stats_socket = {.fd = -1};
    int listener = -1, rc = 1;
    int64_t next_dc_refresh_at = 0;
    atomic_init(&refresh_job.done, 0);
    atomic_init(&refresh_job.cancelled, 0);
    if (tg_config_read(config_path, &cfg) != 0) {
        log_msg("не удалось прочитать конфигурацию локального прокси");
        return 1;
    }
    if (!cfg.enabled) {
        (void)write_status(cfg.status_path, "stopped\n");
        tg_config_clean(&cfg);
        return 0;
    }
    size_t total_memory, available_memory;
    (void)read_memory_resources(&total_memory, &available_memory);
    size_t fd_limit = tg_limits_soft_nofile();
    char resource_note[192];
    size_t configured_limit = cfg.manual_connection_limit ? cfg.connection_limit : 32u;
    size_t max_connections = tg_limits_policy_connections(
        fd_limit, total_memory, available_memory, configured_limit);
    if (!max_connections) {
        snprintf(resource_note, sizeof(resource_note),
                 "нет бюджета запуска: RAM %zu/%zu КиБ доступно, FD %zu",
                 available_memory / 1024u, total_memory / 1024u, fd_limit);
        log_msg(resource_note);
        goto done;
    }
    int64_t now = (int64_t)time(NULL);
    if (!cfg.local_mode || tg_dc_map_store_init(&map_store, cfg.dc_map_path) != 0 ||
        tg_dc_map_store_load(&map_store, now) != 0) {
        log_msg("не удалось инициализировать проверенную карту Telegram DC");
        goto done;
    }
    if (map_store.has_snapshot) {
        stats_context.last_success_at = map_store.snapshot.fetched_at;
        stats_context.last_refresh_result = map_store.loaded_last_good
            ? "loaded_last_good" : "loaded";
    } else {
        stats_context.last_refresh_result = "no_snapshot";
    }
    if (tg_cf_domain_pool_init(&cf_domain_pool, cfg.cf_domain_cache_path,
            &cfg.cf_proxy_domains[0][0], cfg.cf_proxy_domain_count,
            cfg.default_domains) != 0) {
        log_msg("не удалось загрузить проверенный пул CF-доменов");
        goto done;
    }
    const tg_dc_snapshot *snapshot = tg_dc_map_store_current(&map_store);
    if (snapshot && tg_dc_write_endpoint_manifest(cfg.dc_map_endpoints_path,
            snapshot, allowed_ports, sizeof(allowed_ports) / sizeof(allowed_ports[0]),
            now) != 0)
        log_msg("не удалось записать пары IP:порт Telegram для firewall");
    if (!snapshot) (void)unlink(cfg.dc_map_endpoints_path);
    int initial_refresh_due = tg_dc_map_store_refresh_due(
        &map_store, now, TG_DC_REFRESH_SECS);
    next_dc_refresh_at = initial_refresh_due ? now : now + TG_DC_REFRESH_SECS;
    tls_context = tg_tls_client_context(cfg.ca_bundle);
    if (!tls_context) {
        log_msg("не удалось загрузить доверенные сертификаты для маршрутов Cloudflare");
        goto done;
    }
    discovery_dns = tg_route_dns_create(tls_context,
        TG_OUTBOUND_SOCKET_MARK, NULL, NULL, NULL);
    if (!discovery_dns)
        log_msg("не удалось создать DoH-резолвер обновления карты DC");
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
        .memory_budget_bytes = tg_limits_runtime_memory_budget(total_memory, available_memory),
        .configured_max_connections = configured_limit,
        .initial_connection_limit = max_connections,
        .handshake_timeout_ms = cfg.handshake_timeout_secs * 1000u,
        .idle_timeout_ms = 300000,
        .socket_mark = TG_OUTBOUND_SOCKET_MARK,
        .require_socket_mark = 1,
        .enforce_self_dial = 1,
        .enable_direct_wss = 1,
        .cloudflare_only = 1,
        .tls_context = tls_context,
        .routing_config = &cfg,
        .cf_domain_pool = &cf_domain_pool,
        .listen_ports = listen_ports,
        .listen_port_count = sizeof(listen_ports) / sizeof(listen_ports[0]),
        .select_target = tg_transparent_select_target,
        .select_route = tg_transparent_select_route,
        .context = &policy
    };
    proxy = tg_epoll_proxy_create(&proxy_config);
    if (!proxy) {
        snprintf(resource_note, sizeof(resource_note),
                 "не удалось запустить epoll-прокси: %s; лимит %zu, RAM %zu/%zu КиБ доступно, FD %zu",
                 strerror(errno), max_connections, available_memory / 1024u,
                 total_memory / 1024u, fd_limit);
        log_msg(resource_note);
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
    snprintf(resource_note, sizeof(resource_note),
             "локальный Telegram TCP-прокси запущен, лимит %zu, RAM %zu/%zu КиБ доступно, FD %zu",
             tg_epoll_proxy_max_connections(proxy), available_memory / 1024u,
             total_memory / 1024u, fd_limit);
    log_msg(resource_note);
    rc = 0;
    uint64_t rebind_at_ms = 0;
    unsigned rebind_attempt = 0;
    uint64_t next_resource_refresh = monotonic_ms() + TG_RESOURCE_REFRESH_MS;
    while (!stop_requested) {
        if (total_memory <= TG_LOW_MEMORY_ROUTER_BYTES &&
            monotonic_ms() >= next_resource_refresh) {
            next_resource_refresh = monotonic_ms() + TG_RESOURCE_REFRESH_MS;
            size_t total, available;
            if (read_memory_resources(&total, &available)) {
                size_t old_limit = tg_epoll_proxy_max_connections(proxy);
                tg_epoll_proxy_update_limits(proxy,
                    tg_limits_policy_admission(tg_limits_soft_nofile(), total,
                                                available, configured_limit,
                                                tg_epoll_proxy_active_connections(proxy)),
                    tg_limits_runtime_memory_budget(total, available),
                    tg_limits_runtime_memory_budget(total, total));
                size_t new_limit = tg_epoll_proxy_max_connections(proxy);
                if (old_limit != new_limit) {
                    snprintf(resource_note, sizeof(resource_note),
                             "лимит соединений Telegram %zu → %zu, RAM %zu/%zu КиБ доступно",
                             old_limit, new_limit, available / 1024u, total / 1024u);
                    log_msg(resource_note);
                }
            }
        }
        if (listener < 0 && monotonic_ms() >= rebind_at_ms) {
            listener = create_local_listener(cfg.listen_port);
            if (listener >= 0 && tg_epoll_proxy_set_listener(proxy, listener) == 0) {
                log_msg("listener Telegram восстановлен");
            } else {
                if (listener >= 0) close(listener);
                listener = -1;
                if (++rebind_attempt == 5) {
                    log_msg("исчерпаны попытки восстановления listener Telegram");
                    rc = 1;
                    break;
                }
                rebind_at_ms = monotonic_ms() + (100u << rebind_attempt);
            }
        }
        if (stats_socket.fd >= 0 &&
            tg_stats_socket_serve(&stats_socket, proxy, &stats_context) != 0)
            log_msg("ошибка обслуживания локального socket статистики Telegram");
        int step_result = tg_epoll_proxy_step(proxy, listener < 0 ? 100 : 1000);
        if (step_result == TG_EPOLL_REBIND_LISTENER) {
            log_msg("ошибки accept: восстанавливается listener Telegram");
            (void)tg_epoll_proxy_set_listener(proxy, -1);
            close(listener);
            listener = -1;
            rebind_attempt = 0;
            rebind_at_ms = monotonic_ms() + 100u;
        } else if (step_result < 0) {
            log_msg("ошибка epoll runtime локального Telegram-прокси");
            rc = 1;
            break;
        }
        if (stats_socket.fd >= 0 &&
            tg_stats_socket_serve(&stats_socket, proxy, &stats_context) != 0)
            log_msg("ошибка обслуживания локального socket статистики Telegram");
        int64_t refresh_now = (int64_t)time(NULL);
        int refresh_result = finish_dc_refresh(&refresh_job, &map_store,
                                                refresh_now);
        if (refresh_result > 0) {
            stats_context.refreshing = 0;
            ++stats_context.refresh_successes;
            stats_context.last_success_at = refresh_now;
            stats_context.last_refresh_errno = 0;
            stats_context.last_refresh_result = "success";
            if (tg_dc_write_endpoint_manifest(cfg.dc_map_endpoints_path,
                    tg_dc_map_store_current(&map_store), allowed_ports,
                    sizeof(allowed_ports) / sizeof(allowed_ports[0]), refresh_now) != 0) {
                stats_context.last_manifest_errno = errno;
                log_msg("не удалось обновить пары IP:порт Telegram для firewall");
            } else {
                stats_context.last_manifest_errno = 0;
            }
            next_dc_refresh_at = refresh_now + TG_DC_REFRESH_SECS;
            stats_context.next_refresh_at = next_dc_refresh_at;
            log_msg("карта Telegram обновлена по подтверждённому help.getConfig");
        } else if (refresh_result < 0) {
            stats_context.refreshing = 0;
            ++stats_context.refresh_failures;
            stats_context.last_failure_at = refresh_now;
            stats_context.last_refresh_errno = refresh_job.result == 0 ? errno : 0;
            stats_context.last_refresh_result = refresh_job.result == 0
                ? "install_failed" : "discovery_failed";
            next_dc_refresh_at = refresh_now + TG_DC_REFRESH_RETRY_SECS;
            stats_context.next_refresh_at = next_dc_refresh_at;
            log_msg("обновление карты Telegram не подтвердилось; сохранена last-known-good карта");
        }
        if (discovery_dns && !refresh_job.started && refresh_now >= next_dc_refresh_at &&
            tg_dc_map_store_refresh_due(&map_store, refresh_now,
                                       TG_DC_REFRESH_SECS)) {
            stats_context.last_attempt_at = refresh_now;
            ++stats_context.refresh_attempts;
            if (start_dc_refresh(&refresh_job, &cfg, &cf_domain_pool,
                    discovery_dns, tls_context, refresh_now) == 0) {
                stats_context.refreshing = 1;
                stats_context.last_refresh_result = "running";
                stats_context.last_refresh_errno = 0;
                log_msg("запущено фоновое обновление DC через Cloudflare Proxy и Worker");
            } else {
                stats_context.refreshing = 0;
                ++stats_context.refresh_failures;
                stats_context.last_failure_at = refresh_now;
                stats_context.last_refresh_errno = errno;
                stats_context.last_refresh_result = "thread_start_failed";
                log_msg("не удалось запустить фоновое обновление карты Telegram");
                next_dc_refresh_at = refresh_now + TG_DC_REFRESH_RETRY_SECS;
                stats_context.next_refresh_at = next_dc_refresh_at;
            }
        }
        int ready = d2k_runtime_listener_ready(listener);
        (void)d2k_runtime_heartbeat(health_path, NULL, 0, ready, ready);
    }
done:
    (void)write_status(cfg.status_path, rc == 0 ? "stopped\n" : "error\n");
    stop_dc_refresh(&refresh_job);
    tg_stats_socket_close(&stats_socket);
    tg_epoll_proxy_destroy(proxy);
    tg_route_dns_destroy(discovery_dns);
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

static int check_telegram_dc_map(const char *config_path) {
    tg_config config;
    if (tg_config_read(config_path, &config) != 0) {
        puts("{\"ok\":false,\"error\":\"invalid_config\"}");
        return 2;
    }
    (void)signal(SIGPIPE, SIG_IGN);
    tg_cf_domain_pool domains = {0};
    tg_dc_snapshot snapshot = {0};
    atomic_int cancelled = ATOMIC_VAR_INIT(0);
    SSL_CTX *tls = tg_tls_client_context(config.ca_bundle);
    tg_route_dns *dns = tls ? tg_route_dns_create(tls, TG_OUTBOUND_SOCKET_MARK,
                                                   NULL, NULL, NULL) : NULL;
    int rc = -1;
    if (dns && tg_cf_domain_pool_init(&domains, config.cf_domain_cache_path,
            &config.cf_proxy_domains[0][0], config.cf_proxy_domain_count,
            config.default_domains) == 0)
        rc = refresh_local_dc_map(&config, &domains, dns, tls,
                                  (int64_t)time(NULL), &cancelled, &snapshot);
    if (rc == 0)
        printf("{\"ok\":true,\"stage\":\"help.getConfig\",\"this_dc\":%u,\"endpoint_count\":%zu}\n",
               snapshot.this_dc, snapshot.endpoint_count);
    else
        puts("{\"ok\":false,\"stage\":\"help.getConfig\",\"error\":\"discovery_failed\"}");
    tg_dc_snapshot_destroy(&snapshot);
    tg_route_dns_destroy(dns);
    tg_cf_domain_pool_destroy(&domains);
    SSL_CTX_free(tls);
    tg_config_clean(&config);
    return rc == 0 ? 0 : 1;
}

int main(int argc,char **argv) {
    int offline = d2k_runtime_offline(argc, argv, "d2ktg", offline_self_check);
    if (offline >= 0) return offline;
    const char *config="/opt/d2k/config",*log_path=NULL;
    if(argc==2&&strcmp(argv[1],"--version")==0){puts(TG_BUILD " features=instagram-ip-probe,meta-hosts-v3,telegram-local-tcp-epoll,mtproto-respq,mtproto-auth,mtproto-v2,mtproto-help-config,mtproto-gzip-config,telegram-cf-dc-discovery release=" D2K_RELEASE_ID);return 0;}
    if(argc==5&&strcmp(argv[1],"--check-instagram-ip")==0)return check_instagram_ip(argv[2],argv[3],argv[4]);
    if ((argc == 2 || argc == 3) && strcmp(argv[1], "--check-telegram-dc-map") == 0)
        return check_telegram_dc_map(argc == 3 ? argv[2] : config);
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        puts("d2ktg [--config FILE] | --check-telegram-dc-map [CONFIG]");
        return 0;
    }
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
