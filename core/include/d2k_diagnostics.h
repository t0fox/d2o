#ifndef D2K_DIAGNOSTICS_H
#define D2K_DIAGNOSTICS_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define D2K_DIAG_TASK_STATE_COUNT 15
#define D2K_DIAG_LIMIT_CPU 1u
#define D2K_DIAG_LIMIT_MEMORY 2u
#define D2K_DIAG_LIMIT_CONNTRACK 4u
#define D2K_DIAG_LIMIT_SLOTS 8u
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
    uint64_t workers_running, workers_live, workers_result_pending, workers_join_pending;
    int64_t worker_oldest_age_ms, last_measurement_age_ms;
    uint64_t workers_started, workers_joined, worker_start_failures, worker_join_failures;
    uint64_t http_failures, http_bytes, http_failure_bytes, http_failure_limit_hits;
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
d2k_diag *d2k_diag_new(void);
void d2k_diag_free(d2k_diag *d);
size_t d2k_diag_bytes(const d2k_diag *d);
size_t d2k_diag_event_count(const d2k_diag *d);
size_t d2k_diag_sample_count(const d2k_diag *d);
void d2k_diag_record(d2k_diag *d,const d2k_diag_event *e);
void d2k_diag_record_limit(d2k_diag *d,int64_t mono_ms,const d2k_diag_counts *c);
void d2k_diag_sample(d2k_diag *d,int64_t mono_ms,const d2k_diag_counts *c,const char *proc,const char *run);
int d2k_diag_write(const d2k_diag *d,FILE *f);
#endif
