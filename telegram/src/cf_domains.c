#define _POSIX_C_SOURCE 200809L
#include "tg_cf_domains.h"

#include "tg_route_dns.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define TG_CF_REMOTE_TEXT_MAX (64u * 1024u)
#define TG_CF_CACHE_FILE_MAX (TG_CF_POOL_MAX * TG_CF_DOMAIN_LEN + 128u)

static const char *const fallback_encoded[] = {
    "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com",
    "twdmbzcm.com", "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com",
    "bxaxtxmrw.com", "dmohrsgmohcrwb.com", "vwbmtmoi.com", "khgrre.com",
    "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com", "orgcnunpj.com",
    "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com"
};

static int normalize_domain(const char *input,
                            char output[TG_CF_DOMAIN_LEN]) {
    size_t length = strlen(input);
    if (!length || length >= TG_CF_DOMAIN_LEN) return -1;
    for (size_t i = 0; i <= length; ++i)
        output[i] = (char)tolower((unsigned char)input[i]);
    while (length && output[length - 1] == '.') output[--length] = '\0';
    if (!length) return -1;
    size_t label_start = 0, labels = 0;
    int tld_has_alpha = 0;
    for (size_t i = 0; i <= length; ++i) {
        if (i < length && output[i] != '.') {
            unsigned char c = (unsigned char)output[i];
            if (!(isalnum(c) || c == '-')) return -1;
            continue;
        }
        size_t label_length = i - label_start;
        if (!label_length || label_length > 63 || output[label_start] == '-' ||
            output[i - 1] == '-') return -1;
        ++labels;
        if (i == length) {
            if (label_length < 2) return -1;
            for (size_t j = label_start; j < i; ++j)
                if (isalpha((unsigned char)output[j])) tld_has_alpha = 1;
        }
        label_start = i + 1;
    }
    return labels >= 2 && tld_has_alpha ? 0 : -1;
}

static int add_unique(char domains[][TG_CF_DOMAIN_LEN], size_t *count,
                      size_t capacity, const char *candidate) {
    char normalized[TG_CF_DOMAIN_LEN];
    if (normalize_domain(candidate, normalized) != 0) return -1;
    for (size_t i = 0; i < *count; ++i)
        if (strcmp(domains[i], normalized) == 0) return 0;
    if (*count >= capacity) return -1;
    memcpy(domains[(*count)++], normalized, strlen(normalized) + 1u);
    return 0;
}

static int decode_domain(const char *encoded, char output[TG_CF_DOMAIN_LEN]) {
    size_t length = strlen(encoded);
    static const char suffix[] = ".com";
    if (length <= sizeof(suffix) - 1u ||
        strcmp(encoded + length - (sizeof(suffix) - 1u), suffix) != 0)
        return -1;
    size_t prefix_len = length - (sizeof(suffix) - 1u);
    if (prefix_len + sizeof(".co.uk") > TG_CF_DOMAIN_LEN) return -1;
    size_t shift = 0;
    for (size_t i = 0; i < prefix_len; ++i)
        if (isalpha((unsigned char)encoded[i])) ++shift;
    for (size_t i = 0; i < prefix_len; ++i) {
        unsigned char c = (unsigned char)encoded[i];
        if (c >= 'a' && c <= 'z')
            output[i] = (char)('a' + ((c - 'a' + 26u - shift % 26u) % 26u));
        else if (c >= 'A' && c <= 'Z')
            output[i] = (char)('A' + ((c - 'A' + 26u - shift % 26u) % 26u));
        else
            output[i] = (char)c;
    }
    memcpy(output + prefix_len, ".co.uk", sizeof(".co.uk"));
    char normalized[TG_CF_DOMAIN_LEN];
    if (normalize_domain(output, normalized) != 0) return -1;
    memcpy(output, normalized, strlen(normalized) + 1u);
    return 0;
}

int tg_cf_domain_pool_parse_remote(
    const char *text, size_t length,
    char domains[TG_CF_REMOTE_MAX][TG_CF_DOMAIN_LEN], size_t *count) {
    if (!text || !domains || !count || length > TG_CF_REMOTE_TEXT_MAX ||
        memchr(text, '\0', length)) return -1;
    memset(domains, 0, TG_CF_REMOTE_MAX * TG_CF_DOMAIN_LEN);
    *count = 0;
    size_t offset = 0;
    while (offset < length) {
        size_t line_end = offset;
        while (line_end < length && text[line_end] != '\n') ++line_end;
        size_t start = offset;
        while (start < line_end && isspace((unsigned char)text[start])) ++start;
        size_t content_end = line_end;
        while (content_end > start &&
               isspace((unsigned char)text[content_end - 1])) --content_end;
        if (content_end > start && text[start] != '#') {
            size_t line_length = content_end - start;
            if (line_length < TG_CF_DOMAIN_LEN) {
                char encoded[TG_CF_DOMAIN_LEN], decoded[TG_CF_DOMAIN_LEN];
                memcpy(encoded, text + start, line_length);
                encoded[line_length] = '\0';
                if (decode_domain(encoded, decoded) == 0) {
                    int rc = add_unique(domains, count, TG_CF_REMOTE_MAX, decoded);
                    if (rc != 0 && *count < TG_CF_REMOTE_MAX) return -1;
                }
            }
        }
        offset = line_end < length ? line_end + 1u : line_end;
    }
    return 0;
}

static int merge_domains(tg_cf_domain_pool *pool) {
    pool->domain_count = 0;
    for (size_t i = 0; i < pool->manual_count; ++i)
        if (add_unique(pool->domains, &pool->domain_count, TG_CF_POOL_MAX,
                       pool->manual[i]) != 0) return -1;
    for (size_t i = 0; i < pool->remote_count; ++i)
        if (add_unique(pool->domains, &pool->domain_count, TG_CF_POOL_MAX,
                       pool->remote[i]) != 0) return -1;
    return 0;
}

static int parse_timestamp(const char *text, uint64_t *timestamp) {
    static const char prefix[] = "fetched_at=";
    if (strncmp(text, prefix, sizeof(prefix) - 1u) != 0 ||
        !text[sizeof(prefix) - 1u]) return -1;
    const char *value = text + sizeof(prefix) - 1u;
    for (const char *p = value; *p; ++p)
        if (!isdigit((unsigned char)*p)) return -1;
    errno = 0;
    unsigned long long parsed = strtoull(value, NULL, 10);
    if (errno || !parsed) return -1;
    *timestamp = (uint64_t)parsed;
    return 0;
}

static int load_cache(const char *path,
                      char domains[TG_CF_REMOTE_MAX][TG_CF_DOMAIN_LEN],
                      size_t *count, uint64_t *fetched_at) {
    static const char header[] = "D2K-CF-DOMAINS 1\n";
    char data[TG_CF_CACHE_FILE_MAX + 1u];
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat status;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size <= 0 || (uint64_t)status.st_size > TG_CF_CACHE_FILE_MAX) {
        close(fd);
        return -1;
    }
    size_t used = 0;
    while (used < (size_t)status.st_size) {
        ssize_t n = read(fd, data + used, (size_t)status.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return -1; }
        used += (size_t)n;
    }
    close(fd);
    data[used] = '\0';
    if (used < sizeof(header) - 1u ||
        memcmp(data, header, sizeof(header) - 1u) != 0 ||
        memchr(data, '\0', used)) return -1;
    size_t offset = sizeof(header) - 1u, end = offset;
    while (end < used && data[end] != '\n') ++end;
    if (end == used || end - offset >= 32u) return -1;
    data[end] = '\0';
    if (parse_timestamp(data + offset, fetched_at) != 0) return -1;
    offset = end + 1u;
    memset(domains, 0, TG_CF_REMOTE_MAX * TG_CF_DOMAIN_LEN);
    *count = 0;
    while (offset < used) {
        end = offset;
        while (end < used && data[end] != '\n') ++end;
        if (end == offset || end == used || end - offset >= TG_CF_DOMAIN_LEN)
            return -1;
        data[end] = '\0';
        if (add_unique(domains, count, TG_CF_REMOTE_MAX, data + offset) != 0)
            return -1;
        offset = end + 1u;
    }
    return *count >= 3 ? 0 : -1;
}

static int write_all(int fd, const char *data, size_t length) {
    size_t used = 0;
    while (used < length) {
        ssize_t n = write(fd, data + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        used += (size_t)n;
    }
    return 0;
}

static int create_parent_directories(const char *path) {
    char parent[TG_CF_CACHE_PATH_MAX];
    if (strlen(path) >= sizeof(parent)) return -1;
    memcpy(parent, path, strlen(path) + 1u);
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) return 0;
    *slash = '\0';
    for (char *p = parent + 1; ; ++p) {
        if (*p != '/' && *p != '\0') continue;
        char saved = *p;
        *p = '\0';
        if (mkdir(parent, 0700) != 0 && errno != EEXIST) return -1;
        struct stat status;
        if (stat(parent, &status) != 0 || !S_ISDIR(status.st_mode)) return -1;
        *p = saved;
        if (!saved) break;
    }
    return 0;
}

static int write_cache(const tg_cf_domain_pool *pool,
                       char domains[TG_CF_REMOTE_MAX][TG_CF_DOMAIN_LEN],
                       size_t count, uint64_t fetched_at) {
    if (create_parent_directories(pool->cache_path) != 0) return -1;
    char temporary[TG_CF_CACHE_PATH_MAX + 80u];
    static unsigned long sequence;
    int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld.%lu",
                     pool->cache_path, (long)getpid(), ++sequence);
    if (n <= 0 || (size_t)n >= sizeof(temporary)) return -1;
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    char header[64];
    n = snprintf(header, sizeof(header), "D2K-CF-DOMAINS 1\nfetched_at=%llu\n",
                 (unsigned long long)fetched_at);
    int result = n > 0 && (size_t)n < sizeof(header)
        ? write_all(fd, header, (size_t)n) : -1;
    for (size_t i = 0; result == 0 && i < count; ++i) {
        size_t length = strlen(domains[i]);
        result = write_all(fd, domains[i], length);
        if (result == 0) result = write_all(fd, "\n", 1);
    }
    if (result == 0 && fsync(fd) != 0) result = -1;
    if (close(fd) != 0) result = -1;
    if (result == 0 && rename(temporary, pool->cache_path) != 0) result = -1;
    if (result == 0) {
        char parent[TG_CF_CACHE_PATH_MAX];
        memcpy(parent, pool->cache_path, strlen(pool->cache_path) + 1u);
        char *slash = strrchr(parent, '/');
        if (slash && slash != parent) *slash = '\0';
        else if (slash) slash[1] = '\0';
        int dir_fd = open(parent, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
        if (dir_fd >= 0) { (void)fsync(dir_fd); close(dir_fd); }
    } else {
        (void)unlink(temporary);
    }
    return result;
}

static void load_fallback(tg_cf_domain_pool *pool) {
    pool->remote_count = 0;
    for (size_t i = 0;
         i < sizeof(fallback_encoded) / sizeof(fallback_encoded[0]); ++i) {
        char decoded[TG_CF_DOMAIN_LEN];
        if (decode_domain(fallback_encoded[i], decoded) == 0)
            (void)add_unique(pool->remote, &pool->remote_count,
                             TG_CF_REMOTE_MAX, decoded);
    }
    pool->fetched_at = 0;
}

int tg_cf_domain_pool_init(
    tg_cf_domain_pool *pool, const char *cache_path,
    const char *manual_domains,
    size_t manual_count, int auto_update) {
    if (!pool || !cache_path || cache_path[0] != '/' ||
        strlen(cache_path) >= TG_CF_CACHE_PATH_MAX ||
        manual_count > TG_CF_MANUAL_MAX ||
        (manual_count && !manual_domains) ||
        (auto_update != 0 && auto_update != 1)) return -1;
    memset(pool, 0, sizeof(*pool));
    if (pthread_mutex_init(&pool->mutex, NULL) != 0) return -1;
    pool->mutex_initialized = 1;
    memcpy(pool->cache_path, cache_path, strlen(cache_path) + 1u);
    pool->auto_update = auto_update;
    for (size_t i = 0; i < manual_count; ++i)
        if (add_unique(pool->manual, &pool->manual_count,
                       TG_CF_MANUAL_MAX,
                       manual_domains + i * TG_CF_DOMAIN_LEN) != 0) {
            tg_cf_domain_pool_destroy(pool);
            return -1;
        }
    if (auto_update) {
        if (load_cache(pool->cache_path, pool->remote, &pool->remote_count,
                       &pool->fetched_at) != 0)
            load_fallback(pool);
    }
    return merge_domains(pool);
}

int tg_cf_domain_pool_install_remote(
    tg_cf_domain_pool *pool,
    const char *domains, size_t count,
    uint64_t fetched_at) {
    if (!pool || !pool->auto_update || !domains || count < 3 ||
        count > TG_CF_REMOTE_MAX || !fetched_at) return -1;
    char normalized[TG_CF_REMOTE_MAX][TG_CF_DOMAIN_LEN] = {{0}};
    size_t normalized_count = 0;
    for (size_t i = 0; i < count; ++i)
        if (add_unique(normalized, &normalized_count, TG_CF_REMOTE_MAX,
                       domains + i * TG_CF_DOMAIN_LEN) != 0) return -1;
    if (normalized_count < 3 || write_cache(pool, normalized,
                                            normalized_count, fetched_at) != 0)
        return -1;
    pthread_mutex_lock(&pool->mutex);
    memcpy(pool->remote, normalized, sizeof(pool->remote));
    pool->remote_count = normalized_count;
    pool->fetched_at = fetched_at;
    pool->refresh_retry_after = 0;
    if (merge_domains(pool) != 0) {
        pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    if (pool->generation != UINT64_MAX) ++pool->generation;
    pthread_mutex_unlock(&pool->mutex);
    return 0;
}

size_t tg_cf_domain_pool_count(const tg_cf_domain_pool *pool) {
    if (!pool || !pool->mutex_initialized) return 0;
    tg_cf_domain_pool *mutable_pool = (tg_cf_domain_pool *)pool;
    pthread_mutex_lock(&mutable_pool->mutex);
    size_t count = pool->domain_count;
    pthread_mutex_unlock(&mutable_pool->mutex);
    return count;
}

int tg_cf_domain_pool_copy_at(const tg_cf_domain_pool *pool, size_t index,
                              char domain[TG_CF_DOMAIN_LEN]) {
    if (!pool || !domain || !pool->mutex_initialized) return -1;
    tg_cf_domain_pool *mutable_pool = (tg_cf_domain_pool *)pool;
    pthread_mutex_lock(&mutable_pool->mutex);
    if (index >= pool->domain_count) {
        pthread_mutex_unlock(&mutable_pool->mutex);
        return -1;
    }
    memcpy(domain, pool->domains[index], TG_CF_DOMAIN_LEN);
    pthread_mutex_unlock(&mutable_pool->mutex);
    return 0;
}

uint64_t tg_cf_domain_pool_fetched_at(const tg_cf_domain_pool *pool) {
    if (!pool || !pool->mutex_initialized) return 0;
    tg_cf_domain_pool *mutable_pool = (tg_cf_domain_pool *)pool;
    pthread_mutex_lock(&mutable_pool->mutex);
    uint64_t fetched_at = pool->fetched_at;
    pthread_mutex_unlock(&mutable_pool->mutex);
    return fetched_at;
}

int tg_cf_domain_pool_refresh_due(const tg_cf_domain_pool *pool,
                                  uint64_t now) {
    if (!pool || !pool->auto_update || !pool->mutex_initialized) return 0;
    tg_cf_domain_pool *mutable_pool = (tg_cf_domain_pool *)pool;
    pthread_mutex_lock(&mutable_pool->mutex);
    int due = now >= pool->refresh_retry_after &&
        (!pool->fetched_at ||
         (now >= pool->fetched_at && now - pool->fetched_at >= 3600u));
    pthread_mutex_unlock(&mutable_pool->mutex);
    return due;
}

int tg_cf_domain_pool_refresh(tg_cf_domain_pool *pool,
                              struct tg_route_dns *route_dns) {
    static const char host[] = "raw.githubusercontent.com";
    static const char path[] =
        "/Flowseal/tg-ws-proxy/refs/heads/main/.github/cfproxy-domains.txt";
    if (!pool || !route_dns || !pool->auto_update) return -1;
    uint64_t now = (uint64_t)time(NULL);
    if (!tg_cf_domain_pool_refresh_due(pool, now)) return 1;
    tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX] = {{0}};
    size_t address_count = 0;
    uint8_t response[TG_ROUTE_HTTPS_BODY_MAX];
    size_t response_len = 0;
    int fetched = -1;
    if (tg_route_dns_lookup_now(route_dns, host, addresses,
                                &address_count) == 0) {
        for (size_t i = 0; i < address_count; ++i) {
            if (tg_route_dns_https_request(
                    route_dns, host, &addresses[i], "GET", path,
                    "text/plain", NULL, NULL, 0, response,
                    sizeof(response), &response_len) == 0) {
                fetched = 0;
                break;
            }
        }
    }
    char domains[TG_CF_REMOTE_MAX][TG_CF_DOMAIN_LEN] = {{0}};
    size_t domain_count = 0;
    if (fetched == 0 &&
        tg_cf_domain_pool_parse_remote((const char *)response, response_len,
                                       domains, &domain_count) == 0 &&
        domain_count >= 3 &&
        tg_cf_domain_pool_install_remote(pool, &domains[0][0], domain_count,
                                         now) == 0)
        return 0;
    pthread_mutex_lock(&pool->mutex);
    pool->refresh_retry_after = now + 300u;
    pthread_mutex_unlock(&pool->mutex);
    return -1;
}

void tg_cf_domain_pool_destroy(tg_cf_domain_pool *pool) {
    if (!pool || !pool->mutex_initialized) return;
    pthread_mutex_destroy(&pool->mutex);
    memset(pool, 0, sizeof(*pool));
}
