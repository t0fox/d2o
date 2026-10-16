#define _POSIX_C_SOURCE 200809L
#include "tg_cf_domains.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_remote_list_is_decoded_normalized_and_bounded(void) {
    const char input[] = "# domains\nvirkgj.com\nvmmzovy.com\n"
                         "virkgj.com\nnot-encoded.example\n..com\n";
    char domains[TG_CF_REMOTE_MAX][TG_CF_DOMAIN_LEN] = {{0}};
    size_t count = 0;
    assert(tg_cf_domain_pool_parse_remote(input, sizeof(input) - 1u,
                                          domains, &count) == 0);
    assert(count == 2);
    assert(strstr(domains[0], ".co.uk") != NULL);
    assert(strcmp(domains[0], domains[1]) != 0);
    assert(tg_cf_domain_pool_parse_remote(input, sizeof(input) - 1u,
                                          domains, NULL) != 0);
}

static void test_pool_keeps_last_known_good_and_merges_manual_domains(void) {
    char directory[] = "/tmp/d2k-tg-cf-pool-XXXXXX";
    char cache[512];
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(cache, sizeof(cache), "%s/domains.cache", directory) > 0);
    const char manual[TG_CF_MANUAL_MAX][TG_CF_DOMAIN_LEN] = {
        "manual.example"
    };
    tg_cf_domain_pool pool;
    assert(tg_cf_domain_pool_init(&pool, cache, &manual[0][0], 1, 1) == 0);
    assert(pool.remote_count >= 3 && pool.domain_count > pool.remote_count);
    char domain[TG_CF_DOMAIN_LEN];
    assert(tg_cf_domain_pool_copy_at(&pool, 0, domain) == 0);
    assert(strcmp(domain, "manual.example") == 0);

    char remote[TG_CF_REMOTE_MAX][TG_CF_DOMAIN_LEN] = {
        "one.example", "two.example", "three.example"
    };
    assert(tg_cf_domain_pool_install_remote(&pool, &remote[0][0], 3, 123456) == 0);
    assert(pool.remote_count == 3 && pool.domain_count == 4);
    assert(pool.fetched_at == 123456 && pool.generation == 1);
    assert(tg_cf_domain_pool_install_remote(&pool, &remote[0][0], 2, 123457) != 0);
    assert(pool.remote_count == 3 && pool.fetched_at == 123456);
    assert(!tg_cf_domain_pool_refresh_due(&pool, 123457));
    assert(tg_cf_domain_pool_refresh_due(&pool, 123456 + 3600));

    tg_cf_domain_pool restored;
    assert(tg_cf_domain_pool_init(&restored, cache, &manual[0][0], 1, 1) == 0);
    assert(restored.remote_count == 3 && restored.fetched_at == 123456);
    assert(restored.domain_count == 4);
    assert(tg_cf_domain_pool_copy_at(&restored, 3, domain) == 0);
    assert(strcmp(domain, "three.example") == 0);

    tg_cf_domain_pool_destroy(&restored);
    tg_cf_domain_pool_destroy(&pool);
    assert(unlink(cache) == 0);
    assert(rmdir(directory) == 0);
}

int main(void) {
    test_remote_list_is_decoded_normalized_and_bounded();
    test_pool_keeps_last_known_good_and_merges_manual_domains();
    puts("Тесты пула CF-доменов: ок");
    return 0;
}
