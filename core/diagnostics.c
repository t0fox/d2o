#define _POSIX_C_SOURCE 200809L
#include "include/d2k_diagnostics.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <errno.h>
#ifndef D2K_RELEASE_ID
#define D2K_RELEASE_ID "dev"
#endif
#define EVENTS 64
#define SAMPLES 120
#define PROCESS_COUNT 3
static const char *const names[PROCESS_COUNT]={"d2kc","d2kd","d2kpanel"};
static const char *const pidfiles[PROCESS_COUNT]={"d2k.pid","d2kd.pid","d2k-panel.pid"};
typedef struct {long pid;int64_t rss,hwm,anon,threads;} proc_mem;
typedef struct {
    uint64_t id; int64_t at,elapsed,queued,units;unsigned family,trigger,shape;
    char target[256],protocol[16],outcome[32],reason[256],ip[48],path[16],kind[8];
} event;
typedef struct {
    int64_t at,mono,total,available,conntrack;d2k_diag_counts counts;proc_mem procs[PROCESS_COUNT];
} sample;
static const char *const task_state_names[D2K_DIAG_TASK_STATE_COUNT]={
    "free","queued","asking","shape_wait","props_contact","props_wait",
    "planning","trial_settle","verify","verify_wait","watching","resting",
    "voice_measure","voice_trial","voice_watch"
};
/* Два снимка на процесс; сырые карты и имена файлов не сохраняются.
 * Группы следуют меткам ядра, а не владельцам аллокатора: безымянные стеки
 * потоков и отображения malloc могут попасть в anonymous. */
typedef struct {
    long pid; int64_t at,mono,rss,start_ticks,vm[4],fds;
    int smaps_ok; int64_t groups[4][5];
} memory_detail;
struct d2k_diag {
    memory_detail first[PROCESS_COUNT],latest[PROCESS_COUNT];
    event events[EVENTS];sample samples[SAMPLES];
    size_t ne,ns;uint64_t event_total,sample_total;int64_t last_ms;int sampled;
};
typedef char bounded_ring[(sizeof(struct d2k_diag)<=128*1024)?1:-1];
static void copy(char *to,size_t cap,const char *s) {
    if(!s)s="";
    size_t n=strlen(s);if(n>=cap)n=cap-1;
    /* Не обрезать многобайтовый символ UTF-8 по границе буфера. */
    while(n && ((unsigned char)s[n]&0xc0)==0x80)n--;
    memcpy(to,s,n);to[n]=0;
}
static void js(FILE *f,const char *s) {
    fputc('"',f);
    for(const unsigned char *p=(const unsigned char *)s;*p;p++) {
        if(*p=='"'||*p=='\\'){fputc('\\',f);fputc(*p,f);}
        else if(*p=='\n') fputs("\\n",f);
        else if(*p<32)fputc('?',f);
        else fputc(*p,f);
    }fputc('"',f);
}
static void number(FILE *f,int64_t v) {if(v<0)fputs("null",f);else fprintf(f,"%lld",(long long)v);}
d2k_diag *d2k_diag_new(void){return calloc(1,sizeof(d2k_diag));}
void d2k_diag_free(d2k_diag *d){free(d);}
size_t d2k_diag_bytes(const d2k_diag *d){return d?sizeof *d:0;}
size_t d2k_diag_event_count(const d2k_diag *d){return d?d->ne:0;}
size_t d2k_diag_sample_count(const d2k_diag *d){return d?d->ns:0;}
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
static int64_t value(const char *line,const char *key) {
    size_t n=strlen(key);long long x;
    if(strncmp(line,key,n)||sscanf(line+n,"%lld",&x)!=1||x<0)return -1;
    return (int64_t)x;
}
static void read_proc(proc_mem *m,const char *proc,const char *run,size_t i) {
    char path[512],line[256];FILE *f;long pid=0;
    *m=(proc_mem){.pid=0,.rss=-1,.hwm=-1,.anon=-1,.threads=-1};
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
    }fclose(f);
}
static void read_detail(memory_detail *m,const proc_mem *p,int64_t at,int64_t ms,const char *proc) {
    memset(m,0,sizeof *m);m->pid=p->pid;m->rss=p->rss;m->at=at;m->mono=ms;
    m->start_ticks=m->fds=-1;for(size_t k=0;k<4;k++)m->vm[k]=-1;
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
    snprintf(path,sizeof path,"%s/%ld/smaps",proc,p->pid);
    f=fopen(path,"r");if(!f)return;
    int group=-1,valid=1;int64_t maps=0,fields=0;
    const char *metrics[]={"Size:","Rss:","Anonymous:","Private_Dirty:"};
    while(fgets(line,sizeof line,f)) {
        unsigned long long a,b,off,inode;unsigned major,minor;char perms[5];int n=0;
        if(sscanf(line,"%llx-%llx %4s %llx %x:%x %llu %n",&a,&b,perms,&off,&major,&minor,&inode,&n)==7 && n>0){
            char *label=line+n;label[strcspn(label,"\r\n")]=0;
            group=!label[0]?0:!strcmp(label,"[heap]")?1:!strncmp(label,"[stack",6)?2:3;
            m->groups[group][0]++;maps++;continue;
        }
        if(group<0)continue;
        for(size_t k=0;k<4;k++){
            int64_t v=value(line,metrics[k]);if(v<0)continue;
            if(v>INT64_MAX-m->groups[group][k+1])valid=0;
            else m->groups[group][k+1]+=v;
            fields++;
        }
    }
    m->smaps_ok=valid && maps>0 && fields==maps*4 && !ferror(f);
    fclose(f);
}
static void write_detail(FILE *f,const memory_detail *m) {
    if(!m->pid){fputs("null",f);return;}
    fprintf(f,"{\"pid\":%ld,\"at\":%lld,\"mono_ms\":%lld,\"rss_kib\":",m->pid,(long long)m->at,(long long)m->mono);
    number(f,m->rss);fputs(",\"start_ticks\":",f);number(f,m->start_ticks);
    const char *keys[]={"vm_size_kib","vm_data_kib","vm_stack_kib","vm_swap_kib"};
    for(size_t k=0;k<4;k++){fprintf(f,",\"%s\":",keys[k]);number(f,m->vm[k]);}
    fputs(",\"fd_count\":",f);number(f,m->fds);fputs(",\"smaps\":",f);
    if(!m->smaps_ok)fputs("null",f);
    else {
        const char *groups[]={"anonymous","heap","stack","other"};
        const char *metrics[]={"maps","size_kib","rss_kib","anonymous_kib","private_dirty_kib"};
        fputc('{',f);
        for(size_t g=0;g<4;g++){
            fprintf(f,"%s\"%s\":{",g?",":"",groups[g]);
            for(size_t k=0;k<5;k++){fprintf(f,"%s\"%s\":",k?",":"",metrics[k]);number(f,m->groups[g][k]);}
            fputc('}',f);
        }fputc('}',f);
    }fputc('}',f);
}
static void write_limit_reason(FILE *f,const d2k_diag_counts *c) {
    fputs(",\"limit_reason\":[",f);
    if(!c->resources_valid) js(f,"resource-data-unavailable");
    else if(!c->limiter_mask) js(f,"no-current-resource-limit");
    else {
        int comma=0;
        if(c->limiter_mask&D2K_DIAG_LIMIT_CPU){js(f,"cpu");comma=1;}
        if(c->limiter_mask&D2K_DIAG_LIMIT_MEMORY){if(comma)fputc(',',f);js(f,"memory");comma=1;}
        if(c->limiter_mask&D2K_DIAG_LIMIT_CONNTRACK){if(comma)fputc(',',f);js(f,"conntrack");comma=1;}
        if(c->limiter_mask&D2K_DIAG_LIMIT_SLOTS){if(comma)fputc(',',f);js(f,"slots");}
    }
    fputc(']',f);
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
}
int d2k_diag_write(const d2k_diag *d,FILE *f) {
    if(!d||!f)return -1;
    fprintf(f,"{\"schema\":1,\"enabled\":true,\"controller_pid\":%ld,\"release\":",(long)getpid());js(f,D2K_RELEASE_ID);
    fprintf(f,",\"ring_bytes\":%zu,\"event_capacity\":64,\"sample_capacity\":120,\"sample_interval_ms\":60000,\"events_overwritten\":%llu,\"samples_overwritten\":%llu,\"events\":[",sizeof *d,
        (unsigned long long)(d->event_total-d->ne),(unsigned long long)(d->sample_total-d->ns));
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
    fputs("],\"samples\":[",f);
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
        fprintf(f,",\"snapshot_bytes\":%llu,\"catalog_bytes\":%llu,\"workers_running\":%llu,\"workers_join_pending\":%llu,"
                  "\"workers_started\":%llu,\"workers_joined\":%llu,\"worker_start_failures\":%llu,"
                  "\"http_failures\":%llu,\"http_bytes\":%llu,\"measurement_limit\":%llu,\"measurement_slots\":%llu,"
                  "\"resources_valid\":%s,\"cpu_valid\":%s,\"cpu_free_pct\":",
          (unsigned long long)c->snapshot_bytes,(unsigned long long)c->catalog_bytes,
          (unsigned long long)c->workers_running,(unsigned long long)c->workers_join_pending,
          (unsigned long long)c->workers_started,(unsigned long long)c->workers_joined,
          (unsigned long long)c->worker_start_failures,(unsigned long long)c->http_failures,
          (unsigned long long)c->http_bytes,(unsigned long long)c->measurement_limit,
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
            fputs(",\"anon_kib\":",f);number(f,p->anon);fputs(",\"threads\":",f);number(f,p->threads);fputc('}',f);
        }fputs("]}",f);
    }fputs("],\"memory_details\":[",f);
    for(size_t i=0;i<PROCESS_COUNT;i++){
        if(i)fputc(',',f);
        fputs("{\"name\":",f);js(f,names[i]);fputs(",\"first\":",f);write_detail(f,&d->first[i]);
        fputs(",\"latest\":",f);write_detail(f,&d->latest[i]);fputc('}',f);
    }fputs("]}\n",f);return ferror(f)?-1:0;
}
