#define _POSIX_C_SOURCE 200809L
#include "include/d2k_diagnostics.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#ifndef D2K_RELEASE_ID
#define D2K_RELEASE_ID "dev"
#endif
#define EVENTS 64
#define LIMIT_EVENTS 32
#define SAMPLES 120
#define MEMORY_HISTORY 1440
#define ANOMALIES 8
#define GROWTH_POINTS 10
#define PROCESS_COUNT 3
static const char *const names[PROCESS_COUNT]={"d2kc","d2kd","d2kpanel"};
static const char *const pidfiles[PROCESS_COUNT]={"d2k.pid","d2kd.pid","d2k-panel.pid"};
static const char *const memory_site_names[D2K_DIAG_MEMORY_SITE_COUNT]={
    "TCP worker argument", "TLS 1.2 session", "TLS 1.3 session",
    "TCP/TLS receive buffer", "QUIC connection", "QUIC response header"
};
static const char *const memory_site_ids[D2K_DIAG_MEMORY_SITE_COUNT]={
    "tcp.worker_arg", "tls12.session", "tls13.session", "tcp.tls_rx_buffer",
    "quic.connection", "quic.response_header"
};
static const char *const memory_site_locations[D2K_DIAG_MEMORY_SITE_COUNT]={
    "core/sched.c:start_worker", "core/tls12.c:d2k_tls12_connect/resume",
    "core/tls13.c:tls_connect_internal", "core/verify.c:TCP/TLS response buffer",
    "core/quicconn.c:d2k_qc_first_initial/connect", "core/verify.c and quicprobe.c:HTTP/3 response buffers"
};
typedef struct {
    volatile uint32_t live_bytes,peak_bytes,live_objects,created,destroyed,alloc_failures;
} mem_counter;
static mem_counter memory_counters[D2K_DIAG_MEMORY_SITE_COUNT];
static volatile int memory_collection;
typedef struct {long pid;int64_t rss,hwm,anon,threads,vm_data,vm_swap;} proc_mem;
typedef struct {
    uint64_t id; int64_t at,elapsed,queued,units;unsigned family,trigger,shape;
    char target[256],protocol[16],outcome[32],reason[256],ip[48],path[16],kind[8];
} event;
typedef struct {
    int64_t at,mono,cpu_free_pct;
    uint64_t limit,slots,resource_seq,limit_seq,mem_avail,mem_total,mem_reserve,ct_count,ct_max;
    unsigned mask,flags;
} limit_event;
typedef struct {
    int64_t at,mono,total,available,conntrack;d2k_diag_counts counts;proc_mem procs[PROCESS_COUNT];
} sample;
/* 24-hour d2kc memory trend: compact KiB counters, with rollup read by the
   existing once-per-minute procfs pass. Negative values mean unavailable. */
typedef struct {
    uint32_t at_s;
    uint32_t mono_s;
    int32_t rss,vm_data,vm_swap,rollup[5];
    int32_t rollup_errno;
    uint8_t rollup_status;
    uint16_t d2kc_epoch;
    int32_t rss_anon_kib,catalog_bytes,http_bytes,snapshot_bytes,tracked_tcp_bytes,tracked_quic_bytes,tracked_tls_bytes;
    uint8_t tasks,workers_live,workers_result_pending,workers_join_pending;
} memory_sample;
typedef struct {
    int64_t mono;
    int32_t rss,accounted;
} growth_point;
typedef struct {
    uint64_t at;
    int32_t code,rss_delta,accounted_delta;
    uint8_t kind;
    char stage[24];
} anomaly;
static const char *const task_state_names[D2K_DIAG_TASK_STATE_COUNT]={
    "free","queued","asking","shape_wait","props_contact","props_wait",
    "planning","trial_settle","verify","verify_wait","watching","resting",
    "voice_measure","voice_trial","voice_watch"
};
/* Два снимка на процесс; сырые карты памяти и имена файлов не сохраняются. */
typedef struct {
    long pid; int64_t at,mono,rss,start_ticks,vm[4],fds;
    int rollup_status,rollup_errno,rollup_source;
    int64_t rollup[5];
} memory_detail;
struct d2k_diag {
    memory_detail first[PROCESS_COUNT],latest[PROCESS_COUNT];
    event events[EVENTS];limit_event limits[LIMIT_EVENTS];sample samples[SAMPLES];
    memory_sample memory_history[MEMORY_HISTORY];
    anomaly anomalies[ANOMALIES];growth_point growth[GROWTH_POINTS];d2k_diag_madvise madvise;
    size_t ne,nl,ns,nm,na,ng,growth_next;uint64_t event_total,limit_total,sample_total,memory_total,anomaly_total,write_failures;
    int32_t growth_pid;long memory_pid;int64_t memory_start_ticks,last_unattributed_ms,last_ms;
    /* One generation change per retained row fits in this 16-bit value. */
    uint16_t d2kc_epoch;int memory_pid_seen,sampled;
};
typedef char bounded_ring[(sizeof(struct d2k_diag)<=256*1024)?1:-1];
static void copy(char *to,size_t cap,const char *s) {
    if(!s)s="";
    size_t n=strlen(s);if(n>=cap)n=cap-1;
    /* Не обрезать многобайтовый символ UTF-8 по границе буфера. */
    while(n && ((unsigned char)s[n]&0xc0)==0x80)n--;
    memcpy(to,s,n);to[n]=0;
}
static void js(FILE *f,const char *s) {
    fputc('"',f);
    const unsigned char *p=(const unsigned char *)s;
    while(*p) {
        if(*p=='"'||*p=='\\'){fputc('\\',f);fputc(*p,f);}
        else if(*p=='\n') fputs("\\n",f);
        else if(*p<32)fputc('?',f);
        else if(*p<0x80)fputc(*p,f);
        else {
            unsigned need=0;uint32_t cp=0,min=0;
            if(*p>=0xc2&&*p<=0xdf){need=1;cp=*p&0x1f;min=0x80;}
            else if(*p>=0xe0&&*p<=0xef){need=2;cp=*p&0x0f;min=0x800;}
            else if(*p>=0xf0&&*p<=0xf4){need=3;cp=*p&0x07;min=0x10000;}
            int valid=need!=0;
            for(unsigned i=1;valid&&i<=need;i++) {
                if(!p[i]||(p[i]&0xc0)!=0x80)valid=0;
                else cp=(cp<<6)|(p[i]&0x3f);
            }
            if(valid&&(cp<min||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff)))valid=0;
            if(valid){for(unsigned i=0;i<=need;i++)fputc(p[i],f);p+=need;}
            else fputs("\\ufffd",f);
        }
        p++;
    }
    fputc('"',f);
}
static void number(FILE *f,int64_t v) {if(v<0)fputs("null",f);else fprintf(f,"%lld",(long long)v);}
d2k_diag *d2k_diag_new(void){return calloc(1,sizeof(d2k_diag));}
void d2k_diag_free(d2k_diag *d){free(d);}
size_t d2k_diag_bytes(const d2k_diag *d){return d?sizeof *d:0;}
size_t d2k_diag_event_count(const d2k_diag *d){return d?d->ne:0;}
size_t d2k_diag_sample_count(const d2k_diag *d){return d?d->ns:0;}
size_t d2k_diag_memory_history_count(const d2k_diag *d){return d?d->nm:0;}
void d2k_diag_memory_enable(int enabled){__atomic_store_n(&memory_collection,enabled!=0,__ATOMIC_RELEASE);}
int d2k_diag_memory_active(void){return __atomic_load_n(&memory_collection,__ATOMIC_RELAXED)!=0;}
static uint32_t atomic_read(const volatile uint32_t *value){return __sync_fetch_and_add((volatile uint32_t *)value,0);}
static void atomic_peak(volatile uint32_t *peak,uint32_t value){
    uint32_t old=atomic_read(peak);
    while(value>old){uint32_t seen=__sync_val_compare_and_swap(peak,old,value);if(seen==old)break;old=seen;}
}
int d2k_diag_memory_acquire(unsigned site,size_t bytes){
    if(site>=D2K_DIAG_MEMORY_SITE_COUNT||!d2k_diag_memory_active()||bytes>UINT32_MAX)return 0;
    mem_counter *c=&memory_counters[site];uint32_t size=(uint32_t)bytes;
    uint32_t live=__sync_add_and_fetch(&c->live_bytes,size);
    __sync_add_and_fetch(&c->live_objects,1);__sync_add_and_fetch(&c->created,1);atomic_peak(&c->peak_bytes,live);
    return 1;
}
void d2k_diag_memory_release(unsigned site,size_t bytes,int tracked){
    if(!tracked||site>=D2K_DIAG_MEMORY_SITE_COUNT||bytes>UINT32_MAX)return;
    mem_counter *c=&memory_counters[site];__sync_sub_and_fetch(&c->live_bytes,(uint32_t)bytes);
    __sync_sub_and_fetch(&c->live_objects,1);__sync_add_and_fetch(&c->destroyed,1);
}
void d2k_diag_memory_alloc_failure(unsigned site){
    if(site<D2K_DIAG_MEMORY_SITE_COUNT&&d2k_diag_memory_active())
        __sync_add_and_fetch(&memory_counters[site].alloc_failures,1);
}
void d2k_diag_memory_snapshot(d2k_diag_mem_site out[D2K_DIAG_MEMORY_SITE_COUNT]){
    if(!out)return;
    for(unsigned i=0;i<D2K_DIAG_MEMORY_SITE_COUNT;i++){
        mem_counter *c=&memory_counters[i];
        out[i]=(d2k_diag_mem_site){atomic_read(&c->live_bytes),atomic_read(&c->peak_bytes),
            atomic_read(&c->live_objects),atomic_read(&c->created),atomic_read(&c->destroyed),
            atomic_read(&c->alloc_failures)};
    }
}
void d2k_diag_memory_counts(d2k_diag_counts *c){
    if(!c)return;
    d2k_diag_mem_site sites[D2K_DIAG_MEMORY_SITE_COUNT];d2k_diag_memory_snapshot(sites);
    c->tracked_tcp_bytes=(uint64_t)sites[D2K_DIAG_MEM_SCHED_TCP_WORKER_ARG].live_bytes+
                         sites[D2K_DIAG_MEM_TCP_TLS_RX].live_bytes;
    c->tracked_tls_bytes=(uint64_t)sites[D2K_DIAG_MEM_TLS12_SESSION].live_bytes+
                         sites[D2K_DIAG_MEM_TLS13_SESSION].live_bytes;
    c->tracked_quic_bytes=(uint64_t)sites[D2K_DIAG_MEM_QUIC_CONNECTION].live_bytes+
                           sites[D2K_DIAG_MEM_QUIC_HEADER].live_bytes;
}
void d2k_diag_set_madvise(d2k_diag *d,const d2k_diag_madvise *stats){if(d&&stats)d->madvise=*stats;}
static void record_anomaly(d2k_diag *d,unsigned kind,const char *stage,int code,int32_t rss,int32_t accounted){
    if(!d)return;
    anomaly *a=&d->anomalies[d->anomaly_total++%ANOMALIES];memset(a,0,sizeof *a);
    a->at=(uint64_t)time(NULL);a->kind=(uint8_t)kind;a->code=code;a->rss_delta=rss;a->accounted_delta=accounted;
    copy(a->stage,sizeof a->stage,stage);
    if(d->na<ANOMALIES)d->na++;
}
void d2k_diag_record_write_error(d2k_diag *d,const char *stage,int error){
    if(!d)return;
    d->write_failures++;record_anomaly(d,2,stage,error,0,0);
}
void d2k_diag_record(d2k_diag *d,const d2k_diag_event *v) {
    if(!d||!v)return;
    event *e=&d->events[d->event_total++%EVENTS];memset(e,0,sizeof *e);
    e->at=(int64_t)time(NULL);e->id=v->id;e->elapsed=v->elapsed_ms;e->queued=v->queue_ms;
    e->units=v->probe_units;e->family=v->family;e->trigger=v->trigger;e->shape=v->shape;
    copy(e->ip,sizeof e->ip,v->ip);copy(e->path,sizeof e->path,v->path);copy(e->kind,sizeof e->kind,v->kind);
    copy(e->target,sizeof e->target,v->target);copy(e->protocol,sizeof e->protocol,v->protocol);
    copy(e->outcome,sizeof e->outcome,v->outcome);copy(e->reason,sizeof e->reason,v->reason);
    if(d->ne<EVENTS)d->ne++;
}
void d2k_diag_record_limit(d2k_diag *d,int64_t ms,const d2k_diag_counts *c) {
    if(!d||!c)return;
    limit_event *e=&d->limits[d->limit_total++%LIMIT_EVENTS];
    e->at=(int64_t)time(NULL);e->mono=ms;e->limit=c->measurement_limit;e->slots=c->measurement_slots;
    e->resource_seq=c->resource_sequence;e->limit_seq=c->limit_sequence;e->mem_avail=c->mem_avail_kb;
    e->mem_total=c->mem_total_kb;e->mem_reserve=c->mem_reserve_kb;e->ct_count=c->conntrack_count;
    e->ct_max=c->conntrack_max;e->cpu_free_pct=c->cpu_free_pct;e->mask=c->limiter_mask;
    e->flags=(c->resources_valid?1u:0u)|(c->cpu_valid?2u:0u)|(c->mem_valid?4u:0u)|
             (c->conntrack_valid?8u:0u)|(c->grow_pending?16u:0u);
    if(d->nl<LIMIT_EVENTS)d->nl++;
}
static int64_t value(const char *line,const char *key) {
    size_t n=strlen(key);long long x;
    if(strncmp(line,key,n)||sscanf(line+n,"%lld",&x)!=1||x<0)return -1;
    return (int64_t)x;
}
static int32_t compact_kib(int64_t v) {
    return v<0||v>INT32_MAX?-1:(int32_t)v;
}
static int32_t compact_bytes_kib(uint64_t bytes){uint64_t kib=bytes/1024u+(bytes%1024u!=0);return kib>INT32_MAX?-1:(int32_t)kib;}
static int32_t compact_bytes(uint64_t bytes){return bytes>INT32_MAX?-1:(int32_t)bytes;}
static uint8_t compact_count(uint64_t n){return n>UINT8_MAX?UINT8_MAX:(uint8_t)n;}
/* A missing optional proc file is unsupported only while its PID still exists. */
static int proc_pid_dir_present(const char *proc,long pid) {
    char path[512];struct stat st;
    int n=snprintf(path,sizeof path,"%s/%ld",proc,pid);
    return n>=0&&(size_t)n<sizeof path&&stat(path,&st)==0&&S_ISDIR(st.st_mode);
}
static int optional_proc_status(const char *proc,long pid,int error,int *reported_error) {
    if(error==ENOENT&&proc_pid_dir_present(proc,pid)) {
        *reported_error=0;
        return 4;
    }
    *reported_error=error;
    return 1;
}
static void read_proc(proc_mem *m,const char *proc,const char *run,size_t i) {
    char path[512],line[256];FILE *f;long pid=0;
    *m=(proc_mem){.pid=0,.rss=-1,.hwm=-1,.anon=-1,.threads=-1,.vm_data=-1,.vm_swap=-1};
    if(snprintf(path,sizeof path,"%s/%s",run,pidfiles[i])>=(int)sizeof path)return;
    f=fopen(path,"r");if(!f)return;int ok=fscanf(f,"%ld",&pid)==1&&pid>0&&pid<=INT_MAX;fclose(f);if(!ok)return;
    if(snprintf(path,sizeof path,"%s/%ld/comm",proc,pid)>=(int)sizeof path)return;
    f=fopen(path,"r");if(!f)return;ok=fgets(line,sizeof line,f)!=NULL;fclose(f);
    if(!ok)return;
    line[strcspn(line,"\r\n")]=0;if(strcmp(line,names[i]))return;
    m->pid=pid;
    if(snprintf(path,sizeof path,"%s/%ld/status",proc,pid)>=(int)sizeof path)return;
    f=fopen(path,"r");if(!f)return;
    while(fgets(line,sizeof line,f)) {
        int64_t v;
        if((v=value(line,"VmRSS:"))>=0)m->rss=v;
        if((v=value(line,"VmHWM:"))>=0)m->hwm=v;
        if((v=value(line,"RssAnon:"))>=0)m->anon=v;
        if((v=value(line,"Threads:"))>=0)m->threads=v;
        if((v=value(line,"VmData:"))>=0)m->vm_data=v;
        if((v=value(line,"VmSwap:"))>=0)m->vm_swap=v;
    }fclose(f);
}
static void read_detail(memory_detail *m,const proc_mem *p,int64_t at,int64_t ms,const char *proc) {
    memset(m,0,sizeof *m);m->pid=p->pid;m->rss=p->rss;m->at=at;m->mono=ms;
    m->start_ticks=m->fds=-1;for(size_t k=0;k<4;k++)m->vm[k]=-1;
    for(size_t k=0;k<5;k++)m->rollup[k]=-1;
    if(!p->pid)return;
    char path[512],line[512];FILE *f;
    if(snprintf(path,sizeof path,"%s/%ld/stat",proc,p->pid)>=(int)sizeof path)return;
    f=fopen(path,"r");if(f){
        if(fgets(line,sizeof line,f)) {
            char *end=strrchr(line,')'),*save=NULL;
            if(end){char *t=strtok_r(end+1," ", &save);
                for(int field=3;t && field<22;field++)t=strtok_r(NULL," ",&save);
                if(t){char *tail;errno=0;long long n=strtoll(t,&tail,10);
                    if(!errno && tail!=t && (*tail==0 || *tail=='\n') && n>=0)m->start_ticks=n;}
            }
        }fclose(f);
    }
    const char *keys[]={"VmSize:","VmData:","VmStk:","VmSwap:"};
    snprintf(path,sizeof path,"%s/%ld/status",proc,p->pid);
    f=fopen(path,"r");if(f){while(fgets(line,sizeof line,f)){for(size_t k=0;k<4;k++){
        int64_t n=value(line,keys[k]);if(n>=0)m->vm[k]=n;
    }}fclose(f);}
    snprintf(path,sizeof path,"%s/%ld/fd",proc,p->pid);
    DIR *dir=opendir(path);if(dir){
        struct dirent *entry;m->fds=0;errno=0;
        while((entry=readdir(dir)))if(entry->d_name[0]!='.')m->fds++;
        if(errno)m->fds=-1;
        closedir(dir);
    }
    snprintf(path,sizeof path,"%s/%ld/smaps_rollup",proc,p->pid);
    errno=0;f=fopen(path,"r");
    if(!f){int error=errno;m->rollup_status=optional_proc_status(proc,p->pid,error,&m->rollup_errno);}
    else {
        const char *keys[]={"Rss:","Pss:","Anonymous:","Private_Dirty:","Swap:"};
        unsigned seen=0;
        errno=0;
        while(fgets(line,sizeof line,f))for(size_t k=0;k<5;k++){
            int64_t n=value(line,keys[k]);if(n>=0){m->rollup[k]=n;seen|=1u<<k;}
        }
        int read_error=ferror(f),read_errno=errno;fclose(f);
        if(read_error)m->rollup_errno=read_errno;
        if(!read_error&&seen==31){m->rollup_status=2;m->rollup_source=1;}
        else m->rollup_status=3;
    }
}
static const char *read_status(int status) {
    switch(status){case 1:return "unavailable";case 2:return "ok";case 3:return "parse-error";
        case 4:return "unsupported";
        default:return "not-read";}
}
static void write_detail(FILE *f,const memory_detail *m) {
    if(!m->pid){fputs("null",f);return;}
    fprintf(f,"{\"pid\":%ld,\"at\":%lld,\"mono_ms\":%lld,\"rss_kib\":",m->pid,(long long)m->at,(long long)m->mono);
    number(f,m->rss);fputs(",\"start_ticks\":",f);number(f,m->start_ticks);
    const char *keys[]={"vm_size_kib","vm_data_kib","vm_stack_kib","vm_swap_kib"};
    for(size_t k=0;k<4;k++){fprintf(f,",\"%s\":",keys[k]);number(f,m->vm[k]);}
    fputs(",\"fd_count\":",f);number(f,m->fds);
    fputs(",\"smaps_rollup_status\":",f);js(f,read_status(m->rollup_status));
    fputs(",\"smaps_rollup_source\":",f);js(f,m->rollup_source==1?"smaps_rollup":m->rollup_source==2?"smaps-fallback":"unavailable");
    fputs(",\"smaps_rollup_errno\":",f);if(m->rollup_errno)fprintf(f,"%d",m->rollup_errno);else fputs("null",f);
    fputs(",\"smaps_rollup\":",f);
    if(m->rollup_status!=2&&m->rollup_source!=2)fputs("null",f);
    else {
        const char *keys[]={"rss_kib","pss_kib","anonymous_kib","private_dirty_kib","swap_kib"};
        fputc('{',f);for(size_t k=0;k<5;k++){fprintf(f,"%s\"%s\":",k?",":"",keys[k]);number(f,m->rollup[k]);}fputc('}',f);
    }
    /* Never walk every mapping as a fallback: smaps is optional and more expensive. */
    fputs(",\"smaps_status\":\"not-read\",\"smaps_errno\":null,\"smaps\":null}",f);
}
static void write_limit_reason(FILE *f,const d2k_diag_counts *c) {
    unsigned flags=(c->resources_valid?1u:0u);
    unsigned mask=c->limiter_mask;
    fputs(",\"limit_reason\":[",f);
    if(!(flags&1)) js(f,"resource-data-unavailable");
    else if(!mask) js(f,"no-current-resource-limit");
    else {
        int comma=0;
        if(mask&D2K_DIAG_LIMIT_CPU){js(f,"cpu");comma=1;}
        if(mask&D2K_DIAG_LIMIT_MEMORY){if(comma)fputc(',',f);js(f,"memory");comma=1;}
        if(mask&D2K_DIAG_LIMIT_CONNTRACK){if(comma)fputc(',',f);js(f,"conntrack");comma=1;}
        if(mask&D2K_DIAG_LIMIT_SLOTS){if(comma)fputc(',',f);js(f,"slots");}
    }
    fputc(']',f);
}
static void write_limit_reason_state(FILE *f,unsigned flags,unsigned mask) {
    fputs(",\"limit_reason\":[",f);
    if(!(flags&1u)) js(f,"resource-data-unavailable");
    else if(!mask) js(f,"no-current-resource-limit");
    else {
        int comma=0;
        if(mask&D2K_DIAG_LIMIT_CPU){js(f,"cpu");comma=1;}
        if(mask&D2K_DIAG_LIMIT_MEMORY){if(comma)fputc(',',f);js(f,"memory");comma=1;}
        if(mask&D2K_DIAG_LIMIT_CONNTRACK){if(comma)fputc(',',f);js(f,"conntrack");comma=1;}
        if(mask&D2K_DIAG_LIMIT_SLOTS){if(comma)fputc(',',f);js(f,"slots");}
    }
    fputc(']',f);
}
static void write_memory_tracking(FILE *f){
    d2k_diag_mem_site sites[D2K_DIAG_MEMORY_SITE_COUNT];d2k_diag_memory_snapshot(sites);
    fputs(",\"memory_tracking\":{\"enabled\":",f);fputs(d2k_diag_memory_active()?"true":"false",f);
    fputs(",\"coverage\":\"учитываются объекты, выделенные при включённом сборе; уже существующие объекты задним числом не учитываются\",\"sites\":[",f);
    for(unsigned i=0;i<D2K_DIAG_MEMORY_SITE_COUNT;i++){
        if(i)fputc(',',f);
        fputs("{\"id\":",f);js(f,memory_site_ids[i]);fputs(",\"name\":",f);js(f,memory_site_names[i]);
        fputs(",\"location\":",f);js(f,memory_site_locations[i]);
        fprintf(f,",\"live_bytes\":%u,\"peak_bytes\":%u,\"live_objects\":%u,\"created\":%u,\"destroyed\":%u,\"alloc_failures\":%u}",
            sites[i].live_bytes,sites[i].peak_bytes,sites[i].live_objects,sites[i].created,sites[i].destroyed,sites[i].alloc_failures);
    }
    fputs("]}",f);
}
static void write_madvise(FILE *f,const d2k_diag_madvise *m){
    fprintf(f,",\"madvise\":{\"successes\":%llu,\"failures\":%llu,\"requested_bytes\":%llu,\"failed_requested_bytes\":%llu,\"last_errno\":",
        (unsigned long long)m->successes,(unsigned long long)m->failures,
        (unsigned long long)m->requested_bytes,(unsigned long long)m->failed_requested_bytes);
    if(m->last_errno)fprintf(f,"%d",m->last_errno);else fputs("null",f);
    fprintf(f,",\"other_errno_count\":%llu,\"errno\":[",(unsigned long long)m->other_errno_count);
    int comma=0;
    for(size_t i=0;i<D2K_DIAG_MADVISE_ERRNO_SLOTS;i++)if(m->errno_hist[i].error){
        fprintf(f,"%s{\"code\":%d,\"count\":%llu}",comma?",":"",m->errno_hist[i].error,(unsigned long long)m->errno_hist[i].count);comma=1;
    }
    fputs("]}",f);
}
static void write_anomalies(FILE *f,const d2k_diag *d){
    fprintf(f,",\"anomalies_overwritten\":%llu,\"diagnostic_write_failures\":%llu,\"anomalies\":[",
        (unsigned long long)(d->anomaly_total-d->na),(unsigned long long)d->write_failures);
    for(size_t i=0;i<d->na;i++){
        const anomaly *a=&d->anomalies[(d->anomaly_total-d->na+i)%ANOMALIES];if(i)fputc(',',f);
        fputs("{\"kind\":",f);js(f,a->kind==1?"unattributed-rss-growth":"diagnostic-json-write-error");
        fprintf(f,",\"at\":%llu,\"error_code\":",(unsigned long long)a->at);if(a->code)fprintf(f,"%d",a->code);else fputs("null",f);
        fputs(",\"stage\":",f);js(f,a->stage);fputs(",\"rss_delta_kib\":",f);
        if(a->kind==1)fprintf(f,"%d",a->rss_delta);else fputs("null",f);
        fputs(",\"accounted_delta_kib\":",f);if(a->kind==1)fprintf(f,"%d",a->accounted_delta);else fputs("null",f);
        fprintf(f,",\"window_samples\":%u}",a->kind==1?GROWTH_POINTS:0);
    }fputc(']',f);
}
void d2k_diag_sample(d2k_diag *d,int64_t ms,const d2k_diag_counts *c,const char *proc,const char *run) {
    if(!d||!c||(d->sampled&&ms>=d->last_ms&&ms-d->last_ms<60000))return;
    d->last_ms=ms;d->sampled=1;
    sample *s=&d->samples[d->sample_total++%SAMPLES];memset(s,0,sizeof *s);
    s->at=(int64_t)time(NULL);s->mono=ms;s->counts=*c;s->total=s->available=-1;
    char path[512],line[256];
    if(snprintf(path,sizeof path,"%s/meminfo",proc)<(int)sizeof path) {
        FILE *f=fopen(path,"r");if(f){while(fgets(line,sizeof line,f)) {
            int64_t v;if((v=value(line,"MemTotal:"))>=0)s->total=v;
            if((v=value(line,"MemAvailable:"))>=0)s->available=v;
        }fclose(f);}
    }
    s->conntrack=-1;
    if(snprintf(path,sizeof path,"%s/sys/net/netfilter/nf_conntrack_count",proc)<(int)sizeof path) {
        FILE *f=fopen(path,"r");if(f){long long v;if(fscanf(f,"%lld",&v)==1 && v>=0)s->conntrack=v;fclose(f);}
    }
    for(size_t i=0;i<PROCESS_COUNT;i++){
        read_proc(&s->procs[i],proc,run,i);
        read_detail(&d->latest[i],&s->procs[i],s->at,ms,proc);
        const memory_detail *m=&d->latest[i];
        if(m->pid && (d->first[i].pid!=m->pid ||
           (m->start_ticks>=0 && d->first[i].start_ticks!=m->start_ticks)))d->first[i]=*m;
    }
    if(d->ns<SAMPLES)d->ns++;
    const proc_mem *p=&s->procs[0];
    const memory_detail *m=&d->latest[0];
    memory_sample *h=&d->memory_history[d->memory_total++%MEMORY_HISTORY];
    memset(h,0,sizeof *h);
    h->at_s=s->at<0?0:(uint32_t)(uint64_t)s->at;
    h->mono_s=ms<0?0:(uint32_t)((uint64_t)ms/1000u);
    h->rss=compact_kib(p->rss);h->vm_data=compact_kib(p->vm_data);h->vm_swap=compact_kib(p->vm_swap);
    h->rollup_status=(uint8_t)m->rollup_status;h->rollup_errno=m->rollup_errno;
    if(p->pid>0) {
        if(d->memory_pid_seen && (d->memory_pid!=p->pid ||
           (m->start_ticks>=0 && d->memory_start_ticks>=0 && m->start_ticks!=d->memory_start_ticks)))d->d2kc_epoch++;
        d->memory_pid=p->pid;d->memory_start_ticks=m->start_ticks;d->memory_pid_seen=1;
    } else {d->memory_pid=0;d->memory_start_ticks=-1;d->memory_pid_seen=0;}
    h->d2kc_epoch=d->d2kc_epoch;
    for(size_t k=0;k<5;k++)h->rollup[k]=compact_kib(m->rollup[k]);
    h->rss_anon_kib=compact_kib(p->anon);h->catalog_bytes=compact_bytes(c->catalog_bytes);
    h->http_bytes=compact_bytes(c->http_bytes);h->snapshot_bytes=compact_bytes(c->snapshot_bytes);
    h->tracked_tcp_bytes=compact_bytes(c->tracked_tcp_bytes);h->tracked_quic_bytes=compact_bytes(c->tracked_quic_bytes);
    h->tracked_tls_bytes=compact_bytes(c->tracked_tls_bytes);h->tasks=compact_count(c->tasks);
    h->workers_live=compact_count(c->workers_live);h->workers_result_pending=compact_count(c->workers_result_pending);
    h->workers_join_pending=compact_count(c->workers_join_pending);
    if(d->nm<MEMORY_HISTORY)d->nm++;
    if(p->pid>0&&p->pid<=INT32_MAX&&p->rss>=0){
        if(d->growth_pid!=(int32_t)p->pid){d->growth_pid=(int32_t)p->pid;d->ng=0;d->growth_next=0;d->last_unattributed_ms=0;}
        uint64_t accounted_bytes=c->tracked_tcp_bytes+c->tracked_quic_bytes+c->tracked_tls_bytes+
            c->catalog_bytes+c->http_bytes+c->snapshot_bytes;
        int32_t accounted=compact_bytes_kib(accounted_bytes);
        if(accounted>=0){
            d->growth[d->growth_next]=(growth_point){ms,compact_kib(p->rss),accounted};
            d->growth_next=(d->growth_next+1)%GROWTH_POINTS;if(d->ng<GROWTH_POINTS)d->ng++;
            if(d->ng==GROWTH_POINTS){
                const growth_point *base=&d->growth[d->growth_next];int rising=0;
                for(size_t k=1;k<GROWTH_POINTS;k++){
                    const growth_point *prev=&d->growth[(d->growth_next+k-1)%GROWTH_POINTS];
                    const growth_point *cur=&d->growth[(d->growth_next+k)%GROWTH_POINTS];
                    if(cur->rss>prev->rss)rising++;
                }
                const growth_point *last=&d->growth[(d->growth_next+GROWTH_POINTS-1)%GROWTH_POINTS];
                int64_t rss_delta=(int64_t)last->rss-base->rss;
                int64_t accounted_delta=(int64_t)last->accounted-base->accounted;
                if(last->mono-base->mono>=9*60000&&rising>=7&&rss_delta>=1024&&
                   accounted_delta<rss_delta/4&&(!d->last_unattributed_ms||ms-d->last_unattributed_ms>=30*60000)){
                    int32_t rd=rss_delta>INT32_MAX?INT32_MAX:(int32_t)rss_delta;
                    int32_t ad=accounted_delta>INT32_MAX?INT32_MAX:accounted_delta<INT32_MIN?INT32_MIN:(int32_t)accounted_delta;
                    record_anomaly(d,1,"",10,rd,ad);d->last_unattributed_ms=ms;
                }
            }
        }
    }
}
int d2k_diag_write(const d2k_diag *d,FILE *f) {
    if(!d||!f)return -1;
    fprintf(f,"{\"schema\":1,\"enabled\":true,\"controller_pid\":%ld,\"release\":",(long)getpid());js(f,D2K_RELEASE_ID);
    fprintf(f,",\"ring_bytes\":%zu,\"event_capacity\":64,\"limit_transition_capacity\":32,\"sample_capacity\":120,\"sample_interval_ms\":60000,\"memory_history_capacity\":1440,\"memory_history_interval_ms\":60000,\"events_overwritten\":%llu,\"limit_transitions_overwritten\":%llu,\"samples_overwritten\":%llu,\"memory_history_overwritten\":%llu",sizeof *d,
        (unsigned long long)(d->event_total-d->ne),(unsigned long long)(d->limit_total-d->nl),
        (unsigned long long)(d->sample_total-d->ns),
        (unsigned long long)(d->memory_total-d->nm));
    if(d->ns) {
        const d2k_diag_counts *c=&d->samples[(d->sample_total-1)%SAMPLES].counts;
        fprintf(f,",\"http_storage_limits\":{\"records_bytes\":%llu,\"queue_bytes\":%llu,\"failures_bytes\":%llu,\"failure_record_bytes\":%llu}",
            (unsigned long long)c->http_records_limit_bytes,(unsigned long long)c->http_queue_limit_bytes,
            (unsigned long long)c->http_failure_limit_bytes,(unsigned long long)c->http_failure_record_limit_bytes);
    }
    write_memory_tracking(f);write_madvise(f,&d->madvise);write_anomalies(f,d);
    fputs(",\"events\":[",f);
    for(size_t i=0;i<d->ne;i++) {
        const event *e=&d->events[(d->event_total-d->ne+i)%EVENTS];if(i)fputc(',',f);
        fprintf(f,"{\"id\":%llu,\"at\":%lld,\"family\":%u,\"trigger\":%u,\"elapsed_ms\":",
          (unsigned long long)e->id,(long long)e->at,e->family,e->trigger);
        number(f,e->elapsed);fputs(",\"queue_ms\":",f);number(f,e->queued);
        fputs(",\"probe_units\":",f);number(f,e->units);fputs(",\"target\":",f);
        js(f,e->target);
        fputs(",\"ip\":",f);js(f,e->ip);fputs(",\"path\":",f);js(f,e->path);fputs(",\"kind\":",f);js(f,e->kind);
        fprintf(f,",\"shape\":%u",e->shape);
        fputs(",\"protocol\":",f);js(f,e->protocol);fputs(",\"outcome\":",f);js(f,e->outcome);fputs(",\"reason\":",f);js(f,e->reason);fputs(",\"reason_source\":",f);js(f,!strcmp(e->protocol,"http")?"terminal-code":"last-classifier-context");fputc('}',f);
    }
    fputs("],\"limit_transitions\":[",f);
    for(size_t i=0;i<d->nl;i++) {
        const limit_event *e=&d->limits[(d->limit_total-d->nl+i)%LIMIT_EVENTS];
        if(i)fputc(',',f);
        fprintf(f,"{\"at\":%lld,\"mono_ms\":%lld,\"measurement_limit\":%llu,\"measurement_slots\":%llu,\"limiter_mask\":%u,\"grow_pending\":%s,\"resource_sequence\":%llu,\"limit_sequence\":%llu,\"resources_valid\":%s,\"cpu_valid\":%s,\"cpu_free_pct\":",
            (long long)e->at,(long long)e->mono,(unsigned long long)e->limit,
            (unsigned long long)e->slots,e->mask,(e->flags&16u)?"true":"false",
            (unsigned long long)e->resource_seq,(unsigned long long)e->limit_seq,
            (e->flags&1u)?"true":"false",(e->flags&2u)?"true":"false");
        number(f,e->cpu_free_pct);
        fputs(",\"mem_valid\":",f);fputs((e->flags&4u)?"true":"false",f);
        fputs(",\"mem_available_kib\":",f);if(e->flags&4u)fprintf(f,"%llu",(unsigned long long)e->mem_avail);else fputs("null",f);
        fputs(",\"mem_total_kib\":",f);if(e->flags&4u)fprintf(f,"%llu",(unsigned long long)e->mem_total);else fputs("null",f);
        fputs(",\"mem_reserve_kib\":",f);if(e->flags&4u)fprintf(f,"%llu",(unsigned long long)e->mem_reserve);else fputs("null",f);
        fputs(",\"conntrack_valid\":",f);fputs((e->flags&8u)?"true":"false",f);
        fputs(",\"conntrack_count\":",f);if(e->flags&8u)fprintf(f,"%llu",(unsigned long long)e->ct_count);else fputs("null",f);
        fputs(",\"conntrack_max\":",f);if(e->flags&8u)fprintf(f,"%llu",(unsigned long long)e->ct_max);else fputs("null",f);
        write_limit_reason_state(f,e->flags,e->mask);fputc('}',f);
    }
    const memory_sample *base=d->nm?&d->memory_history[(d->memory_total-d->nm)%MEMORY_HISTORY]:NULL;
    fputs("],\"memory_history\":{\"capacity\":1440,\"sample_interval_ms\":60000,\"time_base\":[",f);
    if(base)fprintf(f,"%u,%u",base->at_s,base->mono_s);else fputs("null,null",f);
    fputs("],\"smaps_rollup_status_codes\":[\"not-read\",\"unavailable\",\"ok\",\"parse-error\",\"unsupported\"],\"fields\":[\"at_delta_s\",\"mono_delta_s\",\"rss_kib\",\"vm_data_kib\",\"vm_swap_kib\",\"smaps_rollup_status_code\",\"smaps_rollup_errno\",\"smaps_rollup_kib\",\"rss_anon_kib\",\"catalog_bytes\",\"http_bytes\",\"snapshot_bytes\",\"tracked_tcp_bytes\",\"tracked_quic_bytes\",\"tracked_tls_bytes\",\"tasks\",\"workers_live\",\"workers_result_pending\",\"workers_join_pending\",\"d2kc_epoch\"],\"samples\":[",f);
    for(size_t i=0;i<d->nm;i++) {
        const memory_sample *h=&d->memory_history[(d->memory_total-d->nm+i)%MEMORY_HISTORY];
        if(i)fputc(',',f);
        /* shortcut: deltas wrap safely within 2^32 seconds; widen if retention grows beyond that. */
        fprintf(f,"[%lld,%u,",(long long)h->at_s-(base?(long long)base->at_s:0),
                (unsigned)(h->mono_s-(base?base->mono_s:0)));number(f,h->rss);fputc(',',f);
        number(f,h->vm_data);fputc(',',f);number(f,h->vm_swap);fputc(',',f);
        fprintf(f,"%u,",(unsigned)h->rollup_status);
        if(h->rollup_errno)fprintf(f,"%d",h->rollup_errno);else fputs("null",f);
        fputc(',',f);
        if(h->rollup_status!=2&&h->rollup[0]<0)fputs("null",f);
        else {fputc('[',f);for(size_t k=0;k<5;k++){if(k)fputc(',',f);number(f,h->rollup[k]);}fputc(']',f);}
        fputc(',',f);number(f,h->rss_anon_kib);fputc(',',f);number(f,h->catalog_bytes);fputc(',',f);number(f,h->http_bytes);
        fputc(',',f);number(f,h->snapshot_bytes);fputc(',',f);number(f,h->tracked_tcp_bytes);fputc(',',f);number(f,h->tracked_quic_bytes);
        fputc(',',f);number(f,h->tracked_tls_bytes);fprintf(f,",%u,%u,%u,%u",(unsigned)h->tasks,(unsigned)h->workers_live,
            (unsigned)h->workers_result_pending,(unsigned)h->workers_join_pending);
        fprintf(f,",%u]",(unsigned)h->d2kc_epoch);
    }
    fputs("]},\"samples\":[",f);
    for(size_t i=0;i<d->ns;i++) {
        const sample *s=&d->samples[(d->sample_total-d->ns+i)%SAMPLES];const d2k_diag_counts *c=&s->counts;if(i)fputc(',',f);
        fprintf(f,"{\"at\":%lld,\"mono_ms\":%lld,\"mem_total_kib\":",(long long)s->at,(long long)s->mono);number(f,s->total);
        fputs(",\"mem_available_kib\":",f);number(f,s->available);
        fputs(",\"system_conntrack\":",f);number(f,s->conntrack);
        fprintf(f,",\"datapath_flows\":null,\"http_records\":%llu,\"http_queued\":%llu",(unsigned long long)c->http_records,(unsigned long long)c->http_queued);
        fprintf(f,",\"boxes\":%llu,\"bindings\":%llu,\"plans\":%llu,\"observations\":%llu,\"active\":%llu,\"queued\":%llu,\"tasks\":%llu,\"snapshots\":%llu",
          (unsigned long long)c->boxes,(unsigned long long)c->bindings,(unsigned long long)c->plans,(unsigned long long)c->observations,
          (unsigned long long)c->active,(unsigned long long)c->queued,(unsigned long long)c->tasks,(unsigned long long)c->snapshots);
        /* Scheduler ownership and limiter state are sampled once per minute;
           these fixed-size counters add no per-event allocation. */
        fprintf(f,",\"snapshot_bytes\":%llu,\"catalog_bytes\":%llu,\"workers_running\":%llu,\"workers_live\":%llu,\"workers_result_pending\":%llu,\"workers_join_pending\":%llu,"
                  "\"worker_oldest_age_ms\":",
          (unsigned long long)c->snapshot_bytes,(unsigned long long)c->catalog_bytes,
          (unsigned long long)c->workers_running,(unsigned long long)c->workers_live,
          (unsigned long long)c->workers_result_pending,(unsigned long long)c->workers_join_pending);
        number(f,c->worker_oldest_age_ms);
        fprintf(f,",\"worker_oldest_type\":\"%s\",\"last_measurement_age_ms\":",c->worker_oldest_type);
        number(f,c->last_measurement_age_ms);
        fprintf(f,",\"workers_started\":%llu,\"workers_joined\":%llu,\"worker_start_failures\":%llu,\"worker_join_failures\":%llu,"
                  "\"http_failures\":%llu,\"http_bytes\":%llu,\"http_records_bytes\":%llu,\"http_queue_bytes\":%llu,\"http_failure_bytes\":%llu,"
                  "\"http_failure_limit_hits\":%llu,\"http_failure_record_limit_hits\":%llu,\"http_failure_alloc_failures\":%llu,"
                  "\"http_record_limit_hits\":%llu,\"http_record_alloc_failures\":%llu,\"http_queue_limit_hits\":%llu,\"http_queue_alloc_failures\":%llu,"
                  "\"measurement_limit\":%llu,\"measurement_slots\":%llu,"
                  "\"resources_valid\":%s,\"cpu_valid\":%s,\"cpu_free_pct\":",
          (unsigned long long)c->workers_started,(unsigned long long)c->workers_joined,
          (unsigned long long)c->worker_start_failures,(unsigned long long)c->worker_join_failures,
          (unsigned long long)c->http_failures,(unsigned long long)c->http_bytes,
          (unsigned long long)c->http_records_bytes,(unsigned long long)c->http_queue_bytes,
          (unsigned long long)c->http_failure_bytes,(unsigned long long)c->http_failure_limit_hits,
          (unsigned long long)c->http_failure_record_limit_hits,(unsigned long long)c->http_failure_alloc_failures,
          (unsigned long long)c->http_record_limit_hits,(unsigned long long)c->http_record_alloc_failures,
          (unsigned long long)c->http_queue_limit_hits,(unsigned long long)c->http_queue_alloc_failures,
          (unsigned long long)c->measurement_limit,
          (unsigned long long)c->measurement_slots,c->resources_valid?"true":"false",
          c->cpu_valid?"true":"false");
        number(f,c->cpu_free_pct);
        fprintf(f,",\"mem_valid\":%s,\"scheduler_mem_avail_kib\":",c->mem_valid?"true":"false");
        if(c->mem_valid)fprintf(f,"%llu",(unsigned long long)c->mem_avail_kb);else fputs("null",f);
        fputs(",\"scheduler_mem_total_kib\":",f);
        if(c->mem_valid)fprintf(f,"%llu",(unsigned long long)c->mem_total_kb);else fputs("null",f);
        fputs(",\"scheduler_mem_reserve_kib\":",f);
        if(c->mem_valid)fprintf(f,"%llu",(unsigned long long)c->mem_reserve_kb);else fputs("null",f);
        fprintf(f,",\"conntrack_valid\":%s,\"conntrack_count\":",c->conntrack_valid?"true":"false");
        if(c->conntrack_valid)fprintf(f,"%llu",(unsigned long long)c->conntrack_count);else fputs("null",f);
        fputs(",\"conntrack_max\":",f);
        if(c->conntrack_valid)fprintf(f,"%llu",(unsigned long long)c->conntrack_max);else fputs("null",f);
        fprintf(f,",\"limiter_mask\":%u,\"grow_pending\":%s,\"resource_sequence\":%llu,\"limit_sequence\":%llu,\"limit_age_ms\":%llu,\"task_states\":{",
          c->limiter_mask,c->grow_pending?"true":"false",(unsigned long long)c->resource_sequence,
          (unsigned long long)c->limit_sequence,(unsigned long long)c->limit_age_ms);
        for(size_t state=0;state<D2K_DIAG_TASK_STATE_COUNT;state++) {
            if(state) fputc(',',f);
            js(f,task_state_names[state]);
            fprintf(f,":%llu",(unsigned long long)c->task_states[state]);
        }
        fputc('}',f);write_limit_reason(f,c);fputs(",\"processes\":[",f);
        for(size_t j=0;j<PROCESS_COUNT;j++) {
            const proc_mem *p=&s->procs[j];if(j)fputc(',',f);fputs("{\"name\":",f);js(f,names[j]);
            fprintf(f,",\"pid\":%ld,\"rss_kib\":",p->pid);number(f,p->rss);fputs(",\"hwm_kib\":",f);number(f,p->hwm);
            fputs(",\"anon_kib\":",f);number(f,p->anon);fputs(",\"vm_data_kib\":",f);number(f,p->vm_data);
            fputs(",\"vm_swap_kib\":",f);number(f,p->vm_swap);fputs(",\"threads\":",f);number(f,p->threads);fputc('}',f);
        }fputs("]}",f);
    }fputs("],\"memory_details\":[",f);
    for(size_t i=0;i<PROCESS_COUNT;i++){
        if(i)fputc(',',f);
        fputs("{\"name\":",f);js(f,names[i]);fputs(",\"first\":",f);write_detail(f,&d->first[i]);
        fputs(",\"latest\":",f);write_detail(f,&d->latest[i]);fputc('}',f);
    }fputs("]}\n",f);return ferror(f)?-1:0;
}
