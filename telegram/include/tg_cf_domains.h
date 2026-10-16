#ifndef D2K_TG_CF_DOMAINS_H
#define D2K_TG_CF_DOMAINS_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define TG_CF_DOMAIN_LEN 254u
#define TG_CF_REMOTE_MAX 32u
#define TG_CF_MANUAL_MAX 32u
#define TG_CF_POOL_MAX (TG_CF_REMOTE_MAX + TG_CF_MANUAL_MAX)
#define TG_CF_CACHE_PATH_MAX 1024u

typedef struct tg_cf_domain_pool {
    char cache_path[TG_CF_CACHE_PATH_MAX];
    char manual[TG_CF_MANUAL_MAX][TG_CF_DOMAIN_LEN];
    char remote[TG_CF_REMOTE_MAX][TG_CF_DOMAIN_LEN];
    char domains[TG_CF_POOL_MAX][TG_CF_DOMAIN_LEN];
    size_t manual_count;
    size_t remote_count;
    size_t domain_count;
    uint64_t fetched_at;
    uint64_t generation;
    uint64_t refresh_retry_after;
    int auto_update;
    pthread_mutex_t mutex;
    int mutex_initialized;
} tg_cf_domain_pool;

struct tg_route_dns;

int tg_cf_domain_pool_init(
    tg_cf_domain_pool *pool, const char *cache_path,
    const char *manual_domains,
    size_t manual_count, int auto_update);
int tg_cf_domain_pool_parse_remote(const char *text, size_t length,
                                   char domains[TG_CF_REMOTE_MAX][TG_CF_DOMAIN_LEN],
                                   size_t *count);
int tg_cf_domain_pool_install_remote(tg_cf_domain_pool *pool,
                                     const char *domains,
                                     size_t count, uint64_t fetched_at);
int tg_cf_domain_pool_refresh(tg_cf_domain_pool *pool,
                              struct tg_route_dns *route_dns);
int tg_cf_domain_pool_refresh_due(const tg_cf_domain_pool *pool,
                                  uint64_t now);
uint64_t tg_cf_domain_pool_fetched_at(const tg_cf_domain_pool *pool);
size_t tg_cf_domain_pool_count(const tg_cf_domain_pool *pool);
int tg_cf_domain_pool_copy_at(const tg_cf_domain_pool *pool, size_t index,
                              char domain[TG_CF_DOMAIN_LEN]);
void tg_cf_domain_pool_destroy(tg_cf_domain_pool *pool);

#endif
