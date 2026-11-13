#ifndef D2K_DIAGNOSTICS_H
#define D2K_DIAGNOSTICS_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define D2K_DIAG_TASK_STATE_COUNT 16
#define D2K_DIAG_LIMIT_CPU 1u
#define D2K_DIAG_LIMIT_MEMORY 2u
#define D2K_DIAG_LIMIT_CONNTRACK 4u
#define D2K_DIAG_LIMIT_SLOTS 8u
#define D2K_DIAG_MEMORY_SITE_COUNT 6u
#define D2K_DIAG_MADVISE_ERRNO_SLOTS 4u
#define D2K_DIAG_TG_HISTORY 1440u
#define D2K_DIAG_TG_JSON_MAX (256u*1024u)
#define D2K_DIAG_TG_FIELD_COUNT 67u
enum {
    D2K_DIAG_MEM_SCHED_TCP_WORKER_ARG,
    D2K_DIAG_MEM_TLS12_SESSION,
    D2K_DIAG_MEM_TLS13_SESSION,
    D2K_DIAG_MEM_TCP_TLS_RX,
    D2K_DIAG_MEM_QUIC_CONNECTION,
    D2K_DIAG_MEM_QUIC_HEADER
};
typedef struct {
    uint32_t live_bytes, peak_bytes, live_objects, created, destroyed, alloc_failures;
} d2k_diag_mem_site;
typedef struct {
    int error;
    uint64_t count;
} d2k_diag_errno_count;
typedef struct {
    uint64_t successes, failures, requested_bytes, failed_requested_bytes, other_errno_count;
    int last_errno;
    d2k_diag_errno_count errno_hist[D2K_DIAG_MADVISE_ERRNO_SLOTS];
} d2k_diag_madvise;
/* Callback выполняется в потоке контроллера и не влияет на результаты поиска. */
typedef struct {
    uint64_t id;
    int64_t elapsed_ms, queue_ms, probe_units;
    unsigned family, trigger, shape;
    const char *target, *protocol, *outcome, *reason, *ip, *path, *kind;
} d2k_diag_event;
typedef void (*d2k_diag_observer)(void *, const d2k_diag_event *);
typedef struct {
    uint64_t boxes, bindings, plans, observations, active, queued, tasks, snapshots, http_records, http_queued;
    uint64_t task_states[D2K_DIAG_TASK_STATE_COUNT];
    uint64_t snapshot_bytes, catalog_bytes;
    uint64_t tracked_tcp_bytes, tracked_quic_bytes, tracked_tls_bytes;
    uint64_t workers_running, workers_live, workers_result_pending, workers_join_pending;
    int64_t worker_oldest_age_ms, last_measurement_age_ms;
    uint64_t workers_started, workers_joined, worker_start_failures, worker_join_failures;
    uint64_t http_failures, http_bytes, http_records_bytes, http_queue_bytes, http_failure_bytes;
    uint64_t http_records_limit_bytes, http_queue_limit_bytes;
    uint64_t http_failure_limit_bytes, http_failure_record_limit_bytes;
    uint64_t http_failure_limit_hits, http_failure_record_limit_hits, http_failure_alloc_failures;
    uint64_t http_record_limit_hits, http_record_alloc_failures;
    uint64_t http_queue_limit_hits, http_queue_alloc_failures;
    char worker_oldest_type[12];
    uint64_t measurement_limit, measurement_slots;
    uint64_t resource_sequence, limit_sequence, limit_age_ms;
    uint64_t mem_avail_kb, mem_total_kb, mem_reserve_kb;
    uint64_t conntrack_count, conntrack_max;
    int64_t cpu_free_pct;
    unsigned limiter_mask;
    int resources_valid, cpu_valid, mem_valid, conntrack_valid, grow_pending;
} d2k_diag_counts;
typedef void (*d2k_diag_limit_observer)(void *, int64_t, const d2k_diag_counts *);
typedef struct d2k_diag d2k_diag;
typedef struct d2k_diag_telegram d2k_diag_telegram;
d2k_diag *d2k_diag_new(void);
void d2k_diag_free(d2k_diag *d);
size_t d2k_diag_bytes(const d2k_diag *d);
size_t d2k_diag_event_count(const d2k_diag *d);
size_t d2k_diag_sample_count(const d2k_diag *d);
size_t d2k_diag_memory_history_count(const d2k_diag *d);
void d2k_diag_record(d2k_diag *d,const d2k_diag_event *e);
void d2k_diag_record_limit(d2k_diag *d,int64_t mono_ms,const d2k_diag_counts *c);
void d2k_diag_sample(d2k_diag *d,int64_t mono_ms,const d2k_diag_counts *c,const char *proc,const char *run);
void d2k_diag_memory_enable(int enabled);
int d2k_diag_memory_active(void);
int d2k_diag_memory_acquire(unsigned site,size_t bytes);
void d2k_diag_memory_release(unsigned site,size_t bytes,int tracked);
void d2k_diag_memory_alloc_failure(unsigned site);
void d2k_diag_memory_snapshot(d2k_diag_mem_site out[D2K_DIAG_MEMORY_SITE_COUNT]);
void d2k_diag_memory_counts(d2k_diag_counts *counts);
void d2k_diag_set_controller(d2k_diag *d, long pid, const d2k_diag_mem_site *memory);
void d2k_diag_set_madvise(d2k_diag *d,const d2k_diag_madvise *stats);
void d2k_diag_record_write_error(d2k_diag *d,const char *stage,int error);
int d2k_diag_write(const d2k_diag *d,FILE *f);
void d2k_diag_set_enabled(d2k_diag *d,int enabled);
d2k_diag_telegram *d2k_diag_telegram_new(void);
void d2k_diag_telegram_free(d2k_diag_telegram *d);
int d2k_diag_telegram_record(d2k_diag_telegram *d,int64_t mono_ms,const char *json,size_t len);
void d2k_diag_telegram_error(d2k_diag_telegram *d,int error);
int d2k_diag_write_combined(const d2k_diag *d,const d2k_diag_telegram *tg,FILE *f);
#endif
