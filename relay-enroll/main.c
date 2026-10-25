#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _DEFAULT_SOURCE /* MAP_ANONYMOUS on glibc */
#define _POSIX_C_SOURCE 200809L
#include "tg_identity.h"
#include "tg_net.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROOF_SIZE 120
/* Connections are admitted in three pools so one route cannot starve the
   other: the handshake/header phase, /register and /resolve. A client
   moves from the first into its route's pool once its headers are read. */
#define POOL_PENDING 16
#define POOL_REGISTER 8
#define POOL_RESOLVE 8
#define MAX_CHILDREN (POOL_PENDING+POOL_REGISTER+POOL_RESOLVE)
/* Open connections per client address, whatever their phase. */
#define CONN_PER_IP 2
/* TLS handshake plus request headers must arrive within this time; only
   then does the route's own (longer) budget start. */
#define HEADER_DEADLINE_SECONDS 4
#define REQUEST_ALARM_SECONDS 12
#define HEADER_LIMIT 4096
#define RESOLVE_BODY_LIMIT 2048
#define RESOLVE_MAX_NAMES 32
#define RESOLVE_MAX_ADDRESSES 8
#define RESOLVE_DEADLINE_SECONDS 10
/* glibc resolver bound per lookup: 2 s per server, one attempt. With at most
   two configured servers a lookup ends within RESOLVE_NAME_BUDGET seconds. */
#define RESOLVE_RES_OPTIONS "timeout:2 attempts:1"
#define RESOLVE_NAME_BUDGET 4
#define LOCK_WAIT_MS 1000
/* Meta's GeoDNS answers for the resolver's location, so the VPS resolver
   alone may give one address that is dead from the router. Independent public
   resolvers are asked too, all names at once over UDP, and the union is kept. */
#define PUBLIC_RESOLVERS 3
#define PUBLIC_WAIT_MS 1500
#define PUBLIC_PHASE_MS 2000
#define DNS_MAX_ANSWERS 32
#define DNS_QUERY_LIMIT 300
static const char *const public_resolvers[PUBLIC_RESOLVERS]={"1.1.1.1","8.8.8.8","9.9.9.9"};
#define RESOLVE_REPLY_LIMIT 8192
#define REGISTER_PER_IP 6
#define REGISTER_TOTAL 120
/* Routers refresh once a day, spread over 01:00-05:00 local time; repeated
   names are answered from the cache below, so a request costs no DNS. */
#define RESOLVE_PER_IP 6
#define RESOLVE_TOTAL 600
#define RATE_SLOTS 600
#define CACHE_TTL_SECONDS 600

enum { ROUTE_NONE, ROUTE_HEALTH, ROUTE_REGISTER, ROUTE_RESOLVE };

/* The only names /resolve answers. Public DNS data for a fixed Meta set; the
   router script and d2ktg --check-instagram-ip carry the same list, and
   scripts/test-instagram-dns.sh compares all three. */
static const char *const resolve_hosts[]={
    /* META_HOSTS_BEGIN */
    "instagram.com","www.instagram.com","graph.instagram.com","api.instagram.com",
    "i.instagram.com","instagram.c10r.instagram.com","static.cdninstagram.com",
    "scontent.cdninstagram.com","static.xx.fbcdn.net","scontent.xx.fbcdn.net",
    "web.whatsapp.com","www.whatsapp.com","scontent.whatsapp.net","graph.whatsapp.com",
    "v.whatsapp.com","static.whatsapp.net","mmg.whatsapp.net","pps.whatsapp.net"
    /* META_HOSTS_END */
};

#define RESOLVE_HOST_COUNT (sizeof(resolve_hosts)/sizeof(resolve_hosts[0]))

typedef struct { uint32_t ip; unsigned count; } ip_bucket;
typedef struct { time_t minute; unsigned total,used; ip_bucket ips[RATE_SLOTS]; } rate_limit;
/* One open connection: its child's PID (0 while forking), client address
   and route (ROUTE_NONE while in the handshake/header phase). */
typedef struct { int used; pid_t pid; uint32_t ip; int route; } conn_slot;
/* Children decide by route after reading the request line, so the counters
   live in memory shared with every forked child. owner is the PID holding
   the lock (0: free). */
typedef struct { atomic_int owner; rate_limit registration,resolution; conn_slot conns[MAX_CHILDREN]; } shared_limits;
static volatile sig_atomic_t stopping;

typedef struct { uint32_t a[RESOLVE_MAX_ADDRESSES]; size_t n; } addr_set;
/* Shared per-name answers, one entry per allowlisted name (so the cache is
   bounded by the allowlist); expires is a monotonic second. */
typedef struct { time_t expires; addr_set set; } cache_entry;
typedef struct { atomic_int owner; cache_entry entries[RESOLVE_HOST_COUNT]; } shared_cache;
static shared_cache *answer_cache; /* NULL: no cache */
static unsigned header_deadline_seconds=HEADER_DEADLINE_SECONDS; /* shortened by the tests */

static int rate_allow(rate_limit *limit,uint32_t ip,time_t now,unsigned per_ip,unsigned total) {
    time_t minute=now/60;
    if(limit->minute!=minute){memset(limit,0,sizeof(*limit));limit->minute=minute;}
    if(limit->total>=total||limit->total>=RATE_SLOTS)return 0;
    unsigned i;
    for(i=0;i<limit->used;i++)if(limit->ips[i].ip==ip)break;
    if(i==limit->used){limit->ips[i].ip=ip;limit->used++;}
    if(limit->ips[i].count>=per_ip)return 0;
    limit->ips[i].count++;limit->total++;return 1;
}

static shared_limits *shared_limits_create(void) {
    shared_limits *limits=mmap(NULL,sizeof(*limits),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(limits==MAP_FAILED)return NULL;
    memset(limits,0,sizeof(*limits));atomic_init(&limits->owner,0);return limits;
}

/* Signals are held only while the lock is owned, so the alarm can always end
   a waiting child. The critical section is a few instructions: a holder that
   is dead (SIGKILL, OOM) or that keeps the lock for the whole wait has lost
   it, and the lock is taken over instead of wedging every later child. */
static void shared_lock(atomic_int *owner,sigset_t *old) {
    sigset_t all;sigfillset(&all);
    int me=(int)getpid(),seen=0;
    for(int waited=0;;waited++){
        sigprocmask(SIG_BLOCK,&all,old);
        int expected=0;
        if(atomic_compare_exchange_strong(owner,&expected,me))return;
        if(waited==0)seen=expected;
        int stale=expected!=seen?0:(kill(expected,0)!=0&&errno==ESRCH)||waited>=LOCK_WAIT_MS;
        if(expected!=seen){seen=expected;waited=0;}
        if(stale&&atomic_compare_exchange_strong(owner,&expected,me))return;
        sigprocmask(SIG_SETMASK,old,NULL);
        struct timespec pause_ms={0,1000000};nanosleep(&pause_ms,NULL);
    }
}
static void shared_unlock(atomic_int *owner,const sigset_t *old) {
    atomic_store(owner,0);sigprocmask(SIG_SETMASK,old,NULL);
}
static void limits_lock(shared_limits *limits,sigset_t *old){shared_lock(&limits->owner,old);}
static void limits_unlock(shared_limits *limits,const sigset_t *old){shared_unlock(&limits->owner,old);}

/* Parent, before fork: a slot for a new connection, or -1 when the client
   already has CONN_PER_IP open or the handshake/header phase is full. */
static int conn_admit(shared_limits *limits,uint32_t ip) {
    sigset_t old;limits_lock(limits,&old);
    int free_slot=-1;unsigned pending=0,same=0;
    for(int i=0;i<MAX_CHILDREN;i++){
        conn_slot *c=&limits->conns[i];
        if(!c->used){if(free_slot<0)free_slot=i;continue;}
        if(c->route!=ROUTE_REGISTER&&c->route!=ROUTE_RESOLVE)pending++;
        if(c->ip==ip)same++;
    }
    if(free_slot>=0&&pending<POOL_PENDING&&same<CONN_PER_IP){
        conn_slot *c=&limits->conns[free_slot];c->used=1;c->pid=0;c->ip=ip;c->route=ROUTE_NONE;
    }else free_slot=-1;
    limits_unlock(limits,&old);return free_slot;
}
static void conn_set_pid(shared_limits *limits,int slot,pid_t pid) {
    if(slot<0||slot>=MAX_CHILDREN)return;
    sigset_t old;limits_lock(limits,&old);limits->conns[slot].pid=pid;limits_unlock(limits,&old);
}
static void conn_release_slot(shared_limits *limits,int slot) {
    if(slot<0||slot>=MAX_CHILDREN)return;
    sigset_t old;limits_lock(limits,&old);memset(&limits->conns[slot],0,sizeof(limits->conns[slot]));limits_unlock(limits,&old);
}
/* Parent, after reaping a child (also one killed by its alarm). */
static void conn_release_pid(shared_limits *limits,pid_t pid) {
    if(pid<=0)return;
    sigset_t old;limits_lock(limits,&old);
    for(int i=0;i<MAX_CHILDREN;i++)if(limits->conns[i].used&&limits->conns[i].pid==pid)memset(&limits->conns[i],0,sizeof(limits->conns[i]));
    limits_unlock(limits,&old);
}
/* Child, after its headers: 1 when the route's own pool has room (the slot
   then counts there), 0 when it is full. /health and errors are not pooled. */
static int conn_route(shared_limits *limits,int slot,int route) {
    if(route!=ROUTE_REGISTER&&route!=ROUTE_RESOLVE)return 1;
    if(slot<0||slot>=MAX_CHILDREN)return 1;
    unsigned cap=route==ROUTE_REGISTER?POOL_REGISTER:POOL_RESOLVE,in=0;
    sigset_t old;limits_lock(limits,&old);
    for(int i=0;i<MAX_CHILDREN;i++)if(i!=slot&&limits->conns[i].used&&limits->conns[i].route==route)in++;
    int ok=in<cap;
    if(ok)limits->conns[slot].route=route;
    limits_unlock(limits,&old);return ok;
}

/* 200 when the route may proceed, 429 when its own counter is exhausted.
   /health is not counted. */
static int route_status(shared_limits *limits,int route,uint32_t ip,time_t now) {
    if(route!=ROUTE_REGISTER&&route!=ROUTE_RESOLVE)return 200;
    sigset_t old;limits_lock(limits,&old);
    int ok=route==ROUTE_REGISTER?
        rate_allow(&limits->registration,ip,now,REGISTER_PER_IP,REGISTER_TOTAL):
        rate_allow(&limits->resolution,ip,now,RESOLVE_PER_IP,RESOLVE_TOTAL);
    limits_unlock(limits,&old);
    return ok?200:429;
}

static int valid_proof(const uint8_t *body,size_t len) {
    uint8_t message[70],hash[SHA256_DIGEST_LENGTH];
    if(len!=PROOF_SIZE)return 0;
    memcpy(message,"d2k-enroll-v1",14);memcpy(message+14,body,56);
    if(!SHA256(message,sizeof(message),hash))return 0;
    return hash[0]==0&&hash[1]==0&&(hash[2]&0xc0)==0&&
        tg_identity_verify(body+16,message,sizeof(message),body+56)==0;
}

/* A strict, single-request HTTP parser. Transfer coding, duplicate lengths and
   extra bodies are unsupported. The connection always closes after one reply. */
static int parse_headers(char *headers,size_t *length,int *route) {
    *route=ROUTE_NONE;
    char *line=strstr(headers,"\r\n");if(!line)return 400;
    *line='\0';line+=2;
    if(strcmp(headers,"GET /health HTTP/1.1")==0){*route=ROUTE_HEALTH;return 204;}
    if(strcmp(headers,"POST /register HTTP/1.1")==0)*route=ROUTE_REGISTER;
    else if(strcmp(headers,"POST /resolve HTTP/1.1")==0)*route=ROUTE_RESOLVE;
    else return 404;
    int have_length=0;
    while(*line) {
        char *end=strstr(line,"\r\n");if(!end)return 400;*end='\0';
        if(!*line)break;
        char *colon=strchr(line,':');if(!colon)return 400;*colon++='\0';
        if(strcasecmp(line,"Transfer-Encoding")==0)return 400;
        if(strcasecmp(line,"Content-Length")==0) {
            if(have_length++)return 400;
            while(*colon==' '||*colon=='\t')colon++;
            if(*route==ROUTE_REGISTER){
                if(strcmp(colon,"120")!=0)return 400;
                *length=PROOF_SIZE;
            }else{
                /* Plain decimal, no sign, no leading zero, 1..2048. */
                size_t digits=strspn(colon,"0123456789");
                if(!digits||digits>4||colon[digits]||colon[0]=='0')return 400;
                unsigned long value=strtoul(colon,NULL,10);
                if(value>RESOLVE_BODY_LIMIT)return 400;
                *length=(size_t)value;
            }
        }
        line=end+2;
    }
    return have_length?200:400;
}

/* Writes up to cap IPv4 addresses (network order) for host; returns the count. */
typedef int (*resolve_fn)(const char *host,uint32_t *out,size_t cap);

static int system_resolve(const char *host,uint32_t *out,size_t cap) {
    struct addrinfo hints,*list=NULL;memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&hints,&list)!=0)return 0;
    size_t n=0;
    for(struct addrinfo *ai=list;ai&&n<cap;ai=ai->ai_next)
        if(ai->ai_family==AF_INET&&ai->ai_addrlen>=sizeof(struct sockaddr_in))
            out[n++]=((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(list);return (int)n;
}
static resolve_fn resolver=system_resolve; /* replaced by the tests */

static int64_t monotonic_ms(void) {
    struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts)!=0)return 0;
    return (int64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
static int64_t (*clock_ms)(void)=monotonic_ms; /* replaced by the tests */
static time_t monotonic_seconds(void){return (time_t)(monotonic_ms()/1000);}
static time_t clock_now(void){return (time_t)(clock_ms()/1000);}

/* ---- Direct DNS A queries --------------------------------------------- */

static size_t dns_build_query(uint16_t id,const char *name,uint8_t *out,size_t cap) {
    size_t off=12,len=strlen(name);
    if(cap<12+len+2+4||len>253)return 0;
    memset(out,0,12);out[0]=(uint8_t)(id>>8);out[1]=(uint8_t)id;out[2]=0x01;out[5]=1; /* RD, QDCOUNT 1 */
    while(*name){
        const char *dot=strchr(name,'.');size_t n=dot?(size_t)(dot-name):strlen(name);
        if(n<1||n>63)return 0;
        out[off++]=(uint8_t)n;memcpy(out+off,name,n);off+=n;name+=n;if(*name=='.')name++;
    }
    out[off++]=0;out[off++]=0;out[off++]=1;out[off++]=0;out[off++]=1; /* A, IN */
    return off;
}

static unsigned dns16(const uint8_t *p){return (unsigned)p[0]<<8|p[1];}

/* Decodes a (possibly compressed) name at *off into lower-case dotted text.
   *off moves past the name as stored; pointers must point backwards. */
static int dns_read_name(const uint8_t *msg,size_t len,size_t *off,char out[256]) {
    size_t pos=*off,used=0;int jumped=0,hops=0;
    for(;;){
        if(pos>=len)return -1;
        unsigned c=msg[pos];
        if(c==0){if(!jumped)*off=pos+1;break;}
        if((c&0xc0)==0xc0){
            if(pos+1>=len||++hops>16)return -1;
            size_t target=(c&0x3f)<<8|msg[pos+1];
            if(target>=pos)return -1;
            if(!jumped){*off=pos+2;jumped=1;}
            pos=target;continue;
        }
        if(c&0xc0||pos+1+c>len||used+c+1>255)return -1;
        if(used)out[used++]='.';
        for(unsigned i=0;i<c;i++){char ch=(char)msg[pos+1+i];out[used++]=(ch>='A'&&ch<='Z')?(char)(ch+32):ch;}
        pos+=1+c;
    }
    out[used]='\0';return 0;
}

/* A records for qname, following CNAMEs inside the answer section only.
   The reply must match the query's ID and question exactly; truncated,
   erroneous or malformed replies yield -1. */
static int dns_parse_reply(const uint8_t *msg,size_t len,const uint8_t *query,size_t qlen,
                           const char *qname,uint32_t *out,size_t cap) {
    if(len<qlen||qlen<12+5)return -1;
    if(msg[0]!=query[0]||msg[1]!=query[1])return -1;            /* ID */
    if(!(msg[2]&0x80)||(msg[2]&0x78)||(msg[2]&0x02))return -1;   /* QR, opcode 0, not TC */
    if((msg[3]&0x0f)!=0)return -1;                               /* RCODE */
    if(dns16(msg+4)!=1||memcmp(msg+12,query+12,qlen-12)!=0)return -1;
    unsigned answers=dns16(msg+6);size_t off=qlen;
    struct { unsigned type; char owner[256],target[256]; uint32_t a; } *rr=NULL;
    size_t kept=0;
    rr=calloc(DNS_MAX_ANSWERS,sizeof(*rr));if(!rr)return -1;
    for(unsigned i=0;i<answers;i++){
        char owner[256];
        if(dns_read_name(msg,len,&off,owner)!=0||off+10>len){free(rr);return -1;}
        unsigned type=dns16(msg+off),klass=dns16(msg+off+2),rdlen=dns16(msg+off+8);off+=10;
        if(off+rdlen>len){free(rr);return -1;}
        if(kept<DNS_MAX_ANSWERS&&klass==1){
            if(type==1&&rdlen==4){rr[kept].type=1;strcpy(rr[kept].owner,owner);memcpy(&rr[kept].a,msg+off,4);kept++;}
            else if(type==5){
                size_t t=off;char target[256];
                if(dns_read_name(msg,off+rdlen,&t,target)!=0||t!=off+rdlen){free(rr);return -1;}
                rr[kept].type=5;strcpy(rr[kept].owner,owner);strcpy(rr[kept].target,target);kept++;
            }
        }
        off+=rdlen;
    }
    char current[256];snprintf(current,sizeof(current),"%s",qname);
    size_t n=0;
    for(int hop=0;hop<8;hop++){
        for(size_t i=0;i<kept;i++){
            if(rr[i].type!=1||strcmp(rr[i].owner,current)!=0)continue;
            size_t k;for(k=0;k<n;k++)if(out[k]==rr[i].a)break;
            if(k==n&&n<cap)out[n++]=rr[i].a;
        }
        size_t i;for(i=0;i<kept;i++)if(rr[i].type==5&&strcmp(rr[i].owner,current)==0)break;
        if(i==kept||strcmp(rr[i].target,current)==0)break;
        snprintf(current,sizeof(current),"%s",rr[i].target);
    }
    free(rr);return (int)n;
}

/* One datagram per send; recv waits up to timeout_ms for any reply and
   returns its length, 0 on timeout, <0 when no server can answer any more. */
typedef struct dns_transport {
    void *ctx;
    int (*open)(void *ctx);
    int (*send)(void *ctx,size_t server,const uint8_t *query,size_t len);
    int (*recv)(void *ctx,size_t *server,uint8_t *buf,size_t cap,int timeout_ms);
    void (*close)(void *ctx);
} dns_transport;

typedef struct { int fd[PUBLIC_RESOLVERS]; } udp_dns;
static int udp_open(void *ctx) {
    udp_dns *u=ctx;int any=0;
    for(size_t i=0;i<PUBLIC_RESOLVERS;i++){
        struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(53)};
        u->fd[i]=socket(AF_INET,SOCK_DGRAM,0);
        /* connect() also drops datagrams from any other source. */
        if(u->fd[i]>=0&&(inet_pton(AF_INET,public_resolvers[i],&a.sin_addr)!=1||
           connect(u->fd[i],(struct sockaddr *)&a,sizeof(a))!=0)){close(u->fd[i]);u->fd[i]=-1;}
        if(u->fd[i]>=0)any=1;
    }
    return any?0:-1;
}
static int udp_send(void *ctx,size_t server,const uint8_t *query,size_t len) {
    udp_dns *u=ctx;if(server>=PUBLIC_RESOLVERS||u->fd[server]<0)return -1;
    return send(u->fd[server],query,len,0)==(ssize_t)len?0:-1;
}
static int udp_recv(void *ctx,size_t *server,uint8_t *buf,size_t cap,int timeout_ms) {
    udp_dns *u=ctx;struct pollfd p[PUBLIC_RESOLVERS];size_t map[PUBLIC_RESOLVERS],n=0;
    for(size_t i=0;i<PUBLIC_RESOLVERS;i++)if(u->fd[i]>=0){p[n].fd=u->fd[i];p[n].events=POLLIN;p[n].revents=0;map[n++]=i;}
    if(!n)return -1;
    int r=poll(p,(nfds_t)n,timeout_ms);if(r<=0)return 0;
    for(size_t i=0;i<n;i++){
        if(!p[i].revents)continue;
        ssize_t got=recv(p[i].fd,buf,cap,0);
        if(got<=0){close(u->fd[map[i]]);u->fd[map[i]]=-1;return 0;} /* e.g. ICMP refused */
        *server=map[i];return (int)got;
    }
    return 0;
}
static void udp_close(void *ctx) {
    udp_dns *u=ctx;for(size_t i=0;i<PUBLIC_RESOLVERS;i++)if(u->fd[i]>=0){close(u->fd[i]);u->fd[i]=-1;}
}
static udp_dns udp_state;
static dns_transport udp_transport={&udp_state,udp_open,udp_send,udp_recv,udp_close};
static dns_transport *public_dns=&udp_transport; /* replaced by the tests */

static void addr_add(addr_set *set,const uint32_t *a,size_t n) {
    for(size_t i=0;i<n&&set->n<RESOLVE_MAX_ADDRESSES;i++){
        size_t k;for(k=0;k<set->n;k++)if(set->a[k]==a[i])break;
        if(k==set->n)set->a[set->n++]=a[i];
    }
}

static shared_cache *answer_cache_create(void) {
    shared_cache *cache=mmap(NULL,sizeof(*cache),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(cache==MAP_FAILED)return NULL;
    memset(cache,0,sizeof(*cache));atomic_init(&cache->owner,0);return cache;
}
static int cache_get(int index,addr_set *out) {
    if(!answer_cache)return 0;
    sigset_t old;shared_lock(&answer_cache->owner,&old);
    const cache_entry *e=&answer_cache->entries[index];
    int hit=e->set.n>0&&e->expires>clock_now();
    if(hit)*out=e->set;
    shared_unlock(&answer_cache->owner,&old);return hit;
}
/* Only non-empty answers: a failed lookup is retried by the next request. */
static void cache_put(int index,const addr_set *set) {
    if(!answer_cache||!set->n)return;
    sigset_t old;shared_lock(&answer_cache->owner,&old);
    answer_cache->entries[index].set=*set;answer_cache->entries[index].expires=clock_now()+CACHE_TTL_SECONDS;
    shared_unlock(&answer_cache->owner,&old);
}

/* Asks every public resolver for every name at once and waits at most
   PUBLIC_WAIT_MS. Answers land in pub[name][server]. */
static void public_phase(const int *order,size_t count,addr_set pub[][PUBLIC_RESOLVERS]) {
    uint8_t queries[RESOLVE_MAX_NAMES][DNS_QUERY_LIMIT];size_t qlen[RESOLVE_MAX_NAMES];
    unsigned char answered[RESOLVE_MAX_NAMES*PUBLIC_RESOLVERS]={0};
    uint16_t base=0;if(RAND_bytes((unsigned char *)&base,sizeof(base))!=1)base=(uint16_t)getpid();
    if(!public_dns||public_dns->open(public_dns->ctx)!=0)return;
    size_t pending=0;
    for(size_t i=0;i<count;i++){
        qlen[i]=dns_build_query(0,resolve_hosts[order[i]],queries[i],sizeof(queries[i]));
        if(!qlen[i])continue;
        for(size_t s=0;s<PUBLIC_RESOLVERS;s++){
            uint16_t id=(uint16_t)(base+i*PUBLIC_RESOLVERS+s);uint8_t q[DNS_QUERY_LIMIT];
            memcpy(q,queries[i],qlen[i]);q[0]=(uint8_t)(id>>8);q[1]=(uint8_t)id;
            if(public_dns->send(public_dns->ctx,s,q,qlen[i])==0)pending++;
            else answered[i*PUBLIC_RESOLVERS+s]=1;
        }
    }
    int64_t start=clock_ms();
    while(pending){
        int64_t left=PUBLIC_WAIT_MS-(clock_ms()-start);if(left<=0)break;
        uint8_t reply[512];size_t server=0;
        int got=public_dns->recv(public_dns->ctx,&server,reply,sizeof(reply),(int)left);
        if(got<0)break;
        if(got<12)continue;
        size_t k=(uint16_t)(dns16(reply)-base);
        if(k>=count*PUBLIC_RESOLVERS||k%PUBLIC_RESOLVERS!=server||answered[k])continue;
        size_t i=k/PUBLIC_RESOLVERS;uint8_t q[DNS_QUERY_LIMIT];
        memcpy(q,queries[i],qlen[i]);q[0]=reply[0];q[1]=reply[1];
        uint32_t a[RESOLVE_MAX_ADDRESSES];
        int n=dns_parse_reply(reply,(size_t)got,q,qlen[i],resolve_hosts[order[i]],a,RESOLVE_MAX_ADDRESSES);
        if(n<0)continue; /* malformed or mismatched: wait for a valid one */
        answered[k]=1;pending--;addr_add(&pub[i][server],a,(size_t)n);
    }
    public_dns->close(public_dns->ctx);
}

static void json_space(const char **p,const char *end) {
    while(*p<end&&(**p==' '||**p=='\t'||**p=='\r'||**p=='\n'))(*p)++;
}
static int json_char(const char **p,const char *end,char c) {
    json_space(p,end);if(*p<end&&**p==c){(*p)++;return 1;}return 0;
}
/* Only escape-free strings of name characters; anything else is rejected. */
static int json_name(const char **p,const char *end,const char **start,size_t *len) {
    if(!json_char(p,end,'"'))return 0;
    *start=*p;
    while(*p<end&&**p!='"'){
        char c=**p;
        if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='-'))return 0;
        (*p)++;
    }
    if(*p>=end)return 0;
    *len=(size_t)(*p-*start);(*p)++;return *len>0;
}
static int allowed_host(const char *name,size_t len) {
    for(size_t i=0;i<sizeof(resolve_hosts)/sizeof(resolve_hosts[0]);i++)
        if(strlen(resolve_hosts[i])==len&&memcmp(resolve_hosts[i],name,len)==0)return (int)i;
    return -1;
}

/* Strict body {"hosts":[...]} → {"results":{"host":["a.b.c.d",...],...}}.
   deadline is a monotonic second (0: none). A name is looked up only while a
   whole bounded lookup still fits before it; the rest get [], so the reply is
   always sent before the connection's hard alarm. */
static int handle_resolve(const char *body,size_t length,char *out,size_t cap,size_t *out_len,time_t deadline) {
    const char *p=body,*end=body+length,*name;size_t name_len;
    int order[RESOLVE_MAX_NAMES];size_t count=0;int seen[sizeof(resolve_hosts)/sizeof(resolve_hosts[0])]={0};
    if(memchr(body,'\0',length))return 400;
    if(!json_char(&p,end,'{')||!json_name(&p,end,&name,&name_len)||name_len!=5||memcmp(name,"hosts",5)!=0||
       !json_char(&p,end,':')||!json_char(&p,end,'['))return 400;
    size_t total=0;
    do{
        if(!json_name(&p,end,&name,&name_len))return 400;
        int index=allowed_host(name,name_len);if(index<0)return 400;
        if(++total>RESOLVE_MAX_NAMES)return 400;
        if(!seen[index]){seen[index]=1;order[count++]=index;}
    }while(json_char(&p,end,','));
    if(!json_char(&p,end,']')||!json_char(&p,end,'}'))return 400;
    json_space(&p,end);if(p!=end)return 400;
    /* Cached names need no DNS; the rest are looked up together. */
    addr_set answers[RESOLVE_MAX_NAMES];int cached[RESOLVE_MAX_NAMES]={0},missing[RESOLVE_MAX_NAMES];size_t misses=0;
    for(size_t i=0;i<count;i++){answers[i].n=0;if(cache_get(order[i],&answers[i]))cached[i]=1;else missing[misses++]=order[i];}
    /* Public resolvers first in time (bounded, all at once), only when the
       phase and the reply still fit before the deadline. */
    addr_set pub[RESOLVE_MAX_NAMES][PUBLIC_RESOLVERS];memset(pub,0,sizeof(pub));
    if(misses&&(!deadline||clock_ms()+PUBLIC_PHASE_MS<=(int64_t)deadline*1000))public_phase(missing,misses,pub);
    for(size_t i=0,m=0;i<count;i++){
        if(cached[i])continue;
        uint32_t raw[32];size_t got=0;
        if(!deadline||clock_now()+RESOLVE_NAME_BUDGET<=deadline){
            int r=resolver(resolve_hosts[order[i]],raw,sizeof(raw)/sizeof(raw[0]));got=r>0?(size_t)r:0;
        }
        /* The VPS's own answer first, then each public resolver in order. */
        addr_add(&answers[i],raw,got);
        for(size_t s=0;s<PUBLIC_RESOLVERS;s++)addr_add(&answers[i],pub[m][s].a,pub[m][s].n);
        m++;cache_put(order[i],&answers[i]);
    }
    size_t used=0;int n;
#define EMIT(...) do{n=snprintf(out+used,cap-used,__VA_ARGS__);if(n<0||(size_t)n>=cap-used)return 502;used+=(size_t)n;}while(0)
    EMIT("{\"results\":{");
    for(size_t i=0;i<count;i++){
        const char *host=resolve_hosts[order[i]];
        const uint32_t *unique=answers[i].a;size_t kept=answers[i].n;
        EMIT("%s\"%s\":[",i?",":"",host);
        for(size_t j=0;j<kept;j++){
            char text[INET_ADDRSTRLEN];struct in_addr a={.s_addr=unique[j]};
            if(!inet_ntop(AF_INET,&a,text,sizeof(text)))return 502;
            EMIT("%s\"%s\"",j?",":"",text);
        }
        EMIT("]");
    }
    EMIT("}}");
#undef EMIT
    *out_len=used;return 200;
}

static int socket_write_all(int fd,const char *data,size_t length) {
    while(length){ssize_t n=send(fd,data,length,0);if(n<0&&errno==EINTR)continue;
        if(n<=0)return -1;
        data+=n;length-=(size_t)n;}return 0;
}

static int forward_registration(const char *secret,const char *peer,const uint8_t *proof,uint16_t port) {
    static const char hex[]="0123456789abcdef";
    char id[33],pub[45],body[180],auth[65],request[1024],response[1024];
    for(size_t i=0;i<16;i++){id[2*i]=hex[proof[i]>>4];id[2*i+1]=hex[proof[i]&15];}id[32]='\0';
    if(EVP_EncodeBlock((unsigned char *)pub,proof+16,32)!=44)return 502;
    pub[44]='\0';
    int size=snprintf(body,sizeof(body),"{\"install_id\":\"%s\",\"pubkey\":\"%s\"}",id,pub);
    if(size<0||(size_t)size>=sizeof(body)||tg_register_hmac_hex(secret,body,(size_t)size,auth)!=0)return 502;
    int n=snprintf(request,sizeof(request),
        "POST /register HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
        "X-Z2K-Auth: %s\r\nX-Forwarded-For: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        auth,peer,size,body);
    OPENSSL_cleanse(auth,sizeof(auth));
    if(n<=0||(size_t)n>=sizeof(request))return 502;
    int fd=tg_tcp_connect_ipv4("127.0.0.1",port,8000);if(fd<0)return 502;
    int ok=socket_write_all(fd,request,(size_t)n)==0;OPENSSL_cleanse(request,sizeof(request));
    size_t used=0;
    while(ok&&used<sizeof(response)-1) {
        ssize_t got=recv(fd,response+used,1,0);if(got<0&&errno==EINTR)continue;
        if(got!=1){ok=0;break;}used++;
        if(used>=2&&memcmp(response+used-2,"\r\n",2)==0)break;
    }
    close(fd);response[used]='\0';int code=0;
    if(!ok||sscanf(response,"HTTP/1.%*1[01] %3d",&code)!=1)return 502;
    return code==200||code==409||code==429?code:502;
}

static void ssl_write_all(SSL *ssl,const char *data,size_t length) {
    size_t off=0;
    while(off<length){size_t sent=0;if(SSL_write_ex(ssl,data+off,length-off,&sent)!=1||!sent)break;off+=sent;}
}

static void reply_json(SSL *ssl,const char *body,size_t length) {
    char head[256];
    int n=snprintf(head,sizeof(head),"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",length);
    if(n<=0||(size_t)n>=sizeof(head))return;
    ssl_write_all(ssl,head,(size_t)n);ssl_write_all(ssl,body,length);
}

static void reply(SSL *ssl,int code) {
    const char *reason=code==200?"OK":code==204?"No Content":code==400?"Bad Request":
        code==404?"Not Found":code==409?"Conflict":code==429?"Too Many Requests":
        code==503?"Service Unavailable":"Bad Gateway";
    char response[256];
    int n=snprintf(response,sizeof(response),"HTTP/1.1 %d %s\r\nContent-Length: 0\r\n"
        "Cache-Control: no-store\r\n%sConnection: close\r\n\r\n",code,reason,
        code==429?"Retry-After: 60\r\n":code==503?"Retry-After: 30\r\n":"");
    if(n>0&&(size_t)n<sizeof(response))ssl_write_all(ssl,response,(size_t)n);
}

static void serve_client(int fd,const char *peer,uint32_t peer_ip,shared_limits *limits,int slot,
                         const char *certificate,const char *key,const char *secret,uint16_t upstream_port) {
    /* A short wall-clock limit for the handshake and headers bounds idle and
       byte-at-a-time clients before they reach a route's pool. */
    alarm(header_deadline_seconds);
    struct timeval timeout={.tv_sec=(time_t)header_deadline_seconds,.tv_usec=0};
    (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    (void)setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());SSL *ssl=NULL;
    if(!ctx||SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION)!=1||
       SSL_CTX_use_certificate_chain_file(ctx,certificate)!=1||
       SSL_CTX_use_PrivateKey_file(ctx,key,SSL_FILETYPE_PEM)!=1||SSL_CTX_check_private_key(ctx)!=1)goto done;
    ssl=SSL_new(ctx);if(!ssl||SSL_set_fd(ssl,fd)!=1||SSL_accept(ssl)!=1)goto done;
    char headers[HEADER_LIMIT+1];size_t used=0,length=0;
    while(used<HEADER_LIMIT){size_t n=0;if(SSL_read_ex(ssl,headers+used,1,&n)!=1||n!=1)goto done;used++;
        if(used>=4&&memcmp(headers+used-4,"\r\n\r\n",4)==0)break;}
    if(used==HEADER_LIMIT){reply(ssl,400);goto done;}headers[used]='\0';
    /* Embedded NUL must not hide a header from the parser. */
    if(strlen(headers)!=used){reply(ssl,400);goto done;}
    int route=ROUTE_NONE;
    int code=parse_headers(headers,&length,&route);
    /* The route's own budget starts now; DNS and the body fit inside it. */
    alarm(REQUEST_ALARM_SECONDS);
    time_t deadline=monotonic_seconds()+RESOLVE_DEADLINE_SECONDS;
    timeout.tv_sec=8;
    (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    (void)setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    /* A full pool turns the client away before it spends a rate counter. */
    if(!conn_route(limits,slot,route)){reply(ssl,503);goto done;}
    /* Each route spends only its own counter, also on malformed requests. */
    if(route_status(limits,route,peer_ip,time(NULL))==429){reply(ssl,429);goto done;}
    if(code!=200){reply(ssl,code);goto done;}
    if(route==ROUTE_RESOLVE){
        char body[RESOLVE_BODY_LIMIT],out[RESOLVE_REPLY_LIMIT];size_t out_len=0;used=0;
        while(used<length){size_t n=0;if(SSL_read_ex(ssl,body+used,length-used,&n)!=1||!n)goto done;used+=n;}
        code=handle_resolve(body,length,out,sizeof(out),&out_len,deadline);
        if(code==200)reply_json(ssl,out,out_len);else reply(ssl,code);
        goto done;
    }
    uint8_t proof[PROOF_SIZE];used=0;
    while(used<length){size_t n=0;if(SSL_read_ex(ssl,proof+used,length-used,&n)!=1||!n)goto done;used+=n;}
    if(!valid_proof(proof,used)){reply(ssl,400);goto done;}
    reply(ssl,forward_registration(secret,peer,proof,upstream_port));
done:
    SSL_free(ssl);SSL_CTX_free(ctx);close(fd);
}

static void stop_server(int signal_number){(void)signal_number;stopping=1;}
static void child_exited(int signal_number){(void)signal_number;}

int main(int argc,char **argv) {
    const char *certificate="/var/lib/z2k-relay/acme/192.0.2.44.nip.io",*key=NULL,*bootstrap=NULL;
    uint16_t port=9443,upstream=8080;
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"--certificate")==0&&i+1<argc)certificate=argv[++i];
        else if(strcmp(argv[i],"--key")==0&&i+1<argc)key=argv[++i];
        else if(strcmp(argv[i],"--bootstrap-file")==0&&i+1<argc)bootstrap=argv[++i];
        else if((strcmp(argv[i],"--port")==0||strcmp(argv[i],"--upstream-port")==0)&&i+1<argc){
            int is_up=strcmp(argv[i],"--upstream-port")==0;char *end;
            unsigned long value=strtoul(argv[++i],&end,10);if(!value||value>65535||*end)return 2;
            if(is_up)upstream=(uint16_t)value;else port=(uint16_t)value;
        }else return 2;
    }
    if(!bootstrap){fputs("bootstrap credential path required\n",stderr);return 2;}
    if(!key)key=certificate;
    char secret[1024];int credential=open(bootstrap,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    if(credential<0||fstat(credential,&st)!=0||!S_ISREG(st.st_mode)||st.st_size<1||st.st_size>=(off_t)sizeof(secret)){
        fputs("cannot read server credential\n",stderr);if(credential>=0)close(credential);return 1;
    }
    ssize_t n=read(credential,secret,sizeof(secret)-1);close(credential);if(n!=st.st_size)return 1;
    while(n>0&&isspace((unsigned char)secret[n-1]))n--;
    secret[n]='\0';if(n==0)return 1;
    /* Validate the PEM before declaring the service ready. Each child reloads
       it for renewals, without restarting the existing shared relay. */
    SSL_CTX *check=SSL_CTX_new(TLS_server_method());
    if(!check||SSL_CTX_use_certificate_chain_file(check,certificate)!=1||
       SSL_CTX_use_PrivateKey_file(check,key,SSL_FILETYPE_PEM)!=1||SSL_CTX_check_private_key(check)!=1){
        SSL_CTX_free(check);fputs("cannot load relay TLS certificate\n",stderr);return 1;}
    SSL_CTX_free(check);
    struct sigaction sa;memset(&sa,0,sizeof(sa));sa.sa_handler=stop_server;
    (void)sigaction(SIGTERM,&sa,NULL);(void)sigaction(SIGINT,&sa,NULL);
    /* Children read it on their first lookup; an operator's value wins. */
    (void)setenv("RES_OPTIONS",RESOLVE_RES_OPTIONS,0);
    sa.sa_handler=child_exited;(void)sigaction(SIGCHLD,&sa,NULL);(void)signal(SIGPIPE,SIG_IGN);
    int listener=socket(AF_INET,SOCK_STREAM,0),one=1;if(listener<0)return 1;
    (void)setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr={.s_addr=htonl(INADDR_ANY)}};
    if(bind(listener,(struct sockaddr *)&addr,sizeof(addr))!=0||listen(listener,32)!=0){close(listener);perror("enrollment listener");return 1;}
    fprintf(stderr,"D2K C enrollment listening on %u\n",(unsigned)port);
    shared_limits *limits=shared_limits_create();
    if(!limits){close(listener);fputs("cannot allocate rate limits\n",stderr);return 1;}
    answer_cache=answer_cache_create();
    if(!answer_cache)fputs("no shared /resolve cache; every request asks DNS\n",stderr);
    while(!stopping){
        pid_t done;while((done=waitpid(-1,NULL,WNOHANG))>0)conn_release_pid(limits,done);
        struct sockaddr_in peer;socklen_t peer_len=sizeof(peer);
        int fd=accept(listener,(struct sockaddr *)&peer,&peer_len);
        if(fd<0){if(errno==EINTR)continue;break;}
        char ip[INET_ADDRSTRLEN];if(!inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip))){close(fd);continue;}
        /* Per-address and handshake-phase caps are applied before TLS. */
        int slot=conn_admit(limits,peer.sin_addr.s_addr);
        if(slot<0){close(fd);continue;}
        pid_t pid=fork();
        if(pid==0){close(listener);(void)signal(SIGTERM,SIG_DFL);(void)signal(SIGINT,SIG_DFL);
            serve_client(fd,ip,peer.sin_addr.s_addr,limits,slot,certificate,key,secret,upstream);OPENSSL_cleanse(secret,sizeof(secret));_exit(0);}
        close(fd);
        if(pid>0)conn_set_pid(limits,slot,pid);else conn_release_slot(limits,slot);
    }
    close(listener);OPENSSL_cleanse(secret,sizeof(secret));return 0;
}
