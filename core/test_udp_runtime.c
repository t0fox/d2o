/* Two production runtimes: actual measurement Plan/sink versus session Plan.
 * Socket-generated IP headers are not packet-capture evidence. The full-IP
 * comparison covers lowering; the syscall capture separately covers its sink. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE 1
#include <stdio.h>
#include <errno.h>

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#define d2k_verdict d2k_core_verdict
#include "d2k_udpruntime.h"
#include "d2k_compose.h"
#include "d2k_quichello.h"
#include "d2k_stun.h"
#include "../datapath/test_runtime_trace.h"
static int fails;
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);fails++;}}while(0)
static d2k_conn context;
static unsigned sent_count,lower_count;static uint32_t elapsed;
static int current_ttl,fail_send;
static struct {uint8_t bytes[4096];size_t len;uint32_t at;int ttl;} sent[192],lowered[192];
static int mock_name(int fd,struct sockaddr *out,socklen_t *n,int peer){
    (void)fd;memset(out,0,*n);
    if(context.family==6){struct sockaddr_in6 *a=(void *)out;a->sin6_family=AF_INET6;
        a->sin6_port=peer?context.dst_port:context.src_port;
        memcpy(&a->sin6_addr,peer?context.dst_ip6:context.src_ip6,16);*n=sizeof *a;
    }else{struct sockaddr_in *a=(void *)out;a->sin_family=AF_INET;a->sin_port=peer?context.dst_port:context.src_port;
        a->sin_addr.s_addr=peer?context.dst_ip:context.src_ip;*n=sizeof *a;}
    return 0;
}
static int mock_local(int fd,struct sockaddr *a,socklen_t *n){return mock_name(fd,a,n,0);}
static int mock_peer(int fd,struct sockaddr *a,socklen_t *n){return mock_name(fd,a,n,1);}
static int mock_get(int fd,int l,int o,void *v,socklen_t *n){(void)fd;(void)l;(void)o;(void)n;*(int *)v=current_ttl;return 0;}
static int mock_set(int fd,int l,int o,const void *v,socklen_t n){(void)fd;(void)l;(void)o;(void)n;current_ttl=*(const int *)v;return 0;}
static ssize_t mock_send(int fd,const void *p,size_t n,int flags){
    (void)fd;(void)flags;if(fail_send){errno=EIO;return -1;}
    if(sent_count>=192 || n>4096)return -1;
    memcpy(sent[sent_count].bytes,p,n);sent[sent_count].len=n;sent[sent_count].at=elapsed;
    sent[sent_count++].ttl=current_ttl;return (ssize_t)n;
}
static int mock_sleep(const struct timespec *a,struct timespec *b){(void)b;elapsed+=(uint32_t)(a->tv_sec*1000000+a->tv_nsec/1000);return 0;}
static size_t trace_wire(const d2k_conn *c,const d2k_emit *e,uint8_t *p,size_t cap){
    size_t n=d2k_wire_build_udp(c,e,p,cap);
    if(n && lower_count<192){memcpy(lowered[lower_count].bytes,p,n);lowered[lower_count++].len=n;}
    return n;
}
#define getsockname mock_local
#define getpeername mock_peer
#define getsockopt mock_get
#define setsockopt mock_set
#define send mock_send
#define nanosleep mock_sleep
#define d2k_wire_build_udp trace_wire
#include "udpruntime.c"
#undef getsockname
#undef getpeername
#undef getsockopt
#undef setsockopt
#undef send
#undef nanosleep
#undef d2k_wire_build_udp
static unsigned raw_prepared,raw_expected,raw_sent;
static int raw_fail_prepare,raw_fail_send;
static uint32_t fixed_id(void){return 0x12345678;}
static int capture_prepare(udp_raw_sink *s,const uint8_t *p,size_t n,uint32_t mark){
    (void)s;CHECK(n>=28 && (p[0]>>4==4 || p[0]>>4==6));CHECK(mark==0x23);
    raw_prepared++;return raw_fail_prepare?-1:0;
}
static int capture_raw(udp_raw_sink *s,const uint8_t *p,size_t n,uint32_t mark){
    (void)s;CHECK(raw_prepared==raw_expected && mark==0x23);
    if(raw_fail_send)return -1;
    if(sent_count>=192 || n>4096)return -1;
    memcpy(sent[sent_count].bytes,p,n);sent[sent_count].len=n;sent[sent_count].at=elapsed;
    sent_count++;raw_sent++;return 0;
}
/* Private state is visible only in this test: deterministic fragment ID,
 * without a production hook or rewriting output bytes in the comparison. */
#undef d2k_verdict
#include "../datapath/session.c"
static int nat4(const char *p,uint8_t proto,uint32_t s,uint16_t sp,uint32_t d,uint16_t dp,uint32_t *o,uint16_t *op){
    (void)p;(void)proto;(void)d;(void)dp;*o=s;*op=sp;return 0;
}
static int nat6(const char *p,uint8_t proto,const uint8_t *s,uint16_t sp,const uint8_t *d,uint16_t dp,uint8_t f,uint8_t *o,uint16_t *op){
    (void)p;(void)proto;(void)d;(void)dp;memcpy(o,s,f==6?16:4);*op=sp;return 0;
}
static void ctx(int family){
    memset(&context,0,sizeof context);context.family=(uint8_t)family;context.ttl=47;
    context.src_port=htons(51001);context.dst_port=htons(443);
    inet_pton(AF_INET,"192.0.2.10",&context.src_ip);inet_pton(AF_INET,"198.51.100.20",&context.dst_ip);
    inet_pton(AF_INET6,"2001:db8::10",context.src_ip6);inet_pton(AF_INET6,"2001:db8::20",context.dst_ip6);
}
static unsigned cases;static int force_divergence;
static void gate(const char *question,const char *exported,const uint8_t *payload,size_t len,int frag,int voice){
    for(int family=4;family<=6;family+=2){
        ctx(family);if(voice)context.dst_port=htons(50003);
        uint8_t pkt[4096],tlv[65000];size_t tn=0;char err[200];
        d2k_plan *plan=NULL;d2k_udp_batch measure={0};
        CHECK(d2k_udp_plan_build(question,&context,0x12345678,payload,len,&measure)==0);
        CHECK(d2k_plan_text_to_tlv(exported,tlv,sizeof tlv,&tn,err,sizeof err)==0);
        CHECK(d2k_plan_load(tlv,tn,&plan,err,sizeof err)==0);
        if(!plan || !measure.bytes){d2k_udp_batch_free(&measure);continue;}
        d2k_conn input=context;input.ip_id=65535;
        d2k_emit e={0};e.kind=D2K_EMIT_PAYLOAD;e.bytes=payload;e.len=len;
        size_t pn=d2k_wire_build_udp(&input,&e,pkt,sizeof pkt);
        d2k_session *s=d2k_session_new(64,64);d2k_session_set_plan(s,plan);
        s->fragment_seeded=1;s->fragment_id=0x12345677;
        d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
        uint8_t *out=malloc(D2K_UDP_BATCH_BYTES);d2k_result r;
        d2k_session_packet(s,pkt,pn,1000,out,D2K_UDP_BATCH_BYTES,&r);
        CHECK(r.applied && r.n_out==measure.n);
        d2k_test_packet left[192],right[192];
        for(size_t i=0;i<measure.n;i++)left[i]=(d2k_test_packet){measure.bytes+measure.v[i].off,measure.v[i].len,measure.v[i].delay_us};
        for(size_t i=0;i<r.n_out;i++)right[i]=(d2k_test_packet){out+r.out[i].off,r.out[i].len,r.out[i].delay_us};
        if(force_divergence && r.n_out)out[r.out[0].off+r.out[0].len-1]^=1;
        CHECK(d2k_test_trace_equal(left,measure.n,right,r.n_out));
        if(r.n_out){
            right[0].delay_us++;CHECK(!d2k_test_trace_equal(left,measure.n,right,r.n_out));right[0].delay_us--;
            CHECK(!d2k_test_trace_equal(left,measure.n,right,r.n_out-1));
            out[r.out[0].off+r.out[0].len-1]^=1;
            if(!force_divergence)CHECK(!d2k_test_trace_equal(left,measure.n,right,r.n_out));
            out[r.out[0].off+r.out[0].len-1]^=1;
        }
        /* Repeat on the same flow: no second prefix/fragment application. */
        d2k_session_packet(s,pkt,pn,2000,out,D2K_UDP_BATCH_BYTES,&r);CHECK(!r.applied && !r.n_out);
        sent_count=lower_count=elapsed=raw_prepared=raw_sent=0;current_ttl=context.ttl;
        raw_expected=(unsigned)measure.n;
        CHECK(d2k_udp_plan_send(42,question,payload,len,0x23)==0);
        CHECK(sent_count==measure.n && (frag || lower_count==measure.n));
        uint32_t at=0;
        for(size_t i=0;i<sent_count && i<measure.n;i++){
            const uint8_t *p=measure.bytes+measure.v[i].off;size_t offset=frag?0:family==6?48:28;
            at+=measure.v[i].delay_us;
            if(!frag)CHECK(lowered[i].len==measure.v[i].len && !memcmp(lowered[i].bytes,p,measure.v[i].len));
            CHECK(sent[i].len==measure.v[i].len-offset && !memcmp(sent[i].bytes,p+offset,sent[i].len));
            CHECK(sent[i].at==at);
            if(!frag)CHECK(sent[i].ttl==(family==6?p[7]:p[8]));
        }
        CHECK(current_ttl==context.ttl);
        if(frag){
            raw_fail_prepare=1;sent_count=raw_prepared=0;
            CHECK(d2k_udp_plan_send(42,question,payload,len,0x23)<0 && !sent_count);raw_fail_prepare=0;
            raw_fail_send=1;sent_count=raw_prepared=0;
            CHECK(d2k_udp_plan_send(42,question,payload,len,0x23)<0 && !sent_count);raw_fail_send=0;
        }
        free(out);d2k_session_free(s);d2k_udp_batch_free(&measure);cases++;
    }
}
static const uint8_t *matrix_initial;
static size_t matrix_initial_len;
static char *seen_questions[128];static size_t n_questions;
/* Every question actually emitted by the strategy goes through the gate,
 * including losing hypotheses. Winner-to-export comparison remains separate. */
static void question_gate(const d2k_quic_arm_question *q){
    char text[16384];CHECK(!d2k_quic_question_plan(q,text,sizeof text));
    for(size_t i=0;i<n_questions;i++)if(!strcmp(text,seen_questions[i]))return;
    CHECK(n_questions<128);if(n_questions>=128)return;
    seen_questions[n_questions++]=strdup(text);
    gate(text,text,matrix_initial,matrix_initial_len,q->frag,0);
}
static d2k_quic_arm_question winner;
static int chosen_blob,chosen_copies,chosen_ttl,chosen_frag,strategy_mode;
static d2k_tally oracle(const d2k_quic_arm_question *q,void *u,int *sent_out){
    (void)u;question_gate(q);d2k_tally t={0};t.marked=1;t.fail=3;*sent_out=3;
    size_t n=0;const uint8_t *blob=chosen_blob>=0?d2k_quic_original_blob((size_t)chosen_blob,&n,NULL):NULL;
    int yes=q->control || (q->frag==chosen_frag && q->ttl==chosen_ttl &&
        q->copies==chosen_copies && q->blob_len==n && (!n || !memcmp(q->blob,blob,n)));
    if(strategy_mode){
        yes=(strategy_mode==1 && q->benign) || (strategy_mode==2 && q->split && !q->blob_len) ||
            (strategy_mode==3 && q->ttl==3 && q->copies==2) ||
            (strategy_mode==4 && q->split && q->blob_len && q->copies==11) ||
            (strategy_mode==5 && q->udplen==D2K_QUIC_LENGTH_INCREMENT);
        if(strategy_mode==4 && !q->split && q->copies==11 && q->blob_len==620){t.pass=2;t.fail=1;}
    }
    if(yes){t.pass=3;t.fail=0;if(!q->control)winner=*q;}return t;
}
static d2k_quic_arm_data data(const d2k_quic_arm_question *q,void *u){(void)q;(void)u;d2k_quic_arm_data d={0};d.verdict=D2K_QAD_PASS;return d;}
int main(int argc,char **argv){
    force_divergence=argc==2 && !strcmp(argv[1],"--diverge");
    d2k_nat_hook=nat4;d2k_nat_family_hook=nat6;
    udp_prepare_io=capture_prepare;udp_send_io=capture_raw;udp_fragment_id_io=fixed_id;
    uint32_t last_id=udp_next_fragment_id();
    for(unsigned i=0;i<100;i++){uint32_t id=udp_next_fragment_id();CHECK(id>last_id && (id&65535));last_id=id;}
    uint8_t initial[4096];size_t len=0;CHECK(d2k_quic_probe_initial("example.com",initial,sizeof initial,&len)==0);
    uint8_t longer[4096];size_t longer_len=0;
    CHECK(!d2k_quic_probe_initial_longer("example.com",longer,sizeof longer,&longer_len));
    matrix_initial=initial;matrix_initial_len=len;
    const char pool[][D2K_QUIC_ADDR_LEN]={"192.0.2.1"};
    for(int mode=0;mode<15;mode++){
        chosen_blob=mode<5?mode:mode<11?0:-1;
        chosen_copies=mode<5?1:mode<7?(mode==5?6:11):mode<11?2:0;
        chosen_ttl=mode>=7 && mode<11?(int[]){3,5,8,12}[mode-7]:0;
        chosen_frag=mode>=11?mode-10:0;memset(&winner,0,sizeof winner);
        d2k_quic_arm_context c={0};c.pool=pool;c.n_pool=1;c.marked=1;c.probe=oracle;c.data=data;
        d2k_quic_arm a=d2k_quic_original_arms(&c);char qtext[16384],rtext[16384];
        CHECK(a.kind!=D2K_QA_NOT_FOUND && winner.addr);
        CHECK(d2k_quic_question_plan(&winner,qtext,sizeof qtext)==0);
        CHECK(d2k_quic_arm_plan(&a,a.len?a.bytes:NULL,a.len,rtext,sizeof rtext)==0);
        gate(qtext,rtext,initial,len,chosen_frag,0);
        gate(qtext,rtext,longer,longer_len,chosen_frag,0);
    }
    for(strategy_mode=1;strategy_mode<=5;strategy_mode++){
        d2k_quic_arm_context c={0};c.pool=pool;c.n_pool=1;c.marked=1;c.probe=oracle;c.data=data;
        c.need_complete=strategy_mode==3;c.budget_pk=strategy_mode==3?50:0;
        d2k_quic_arm a=d2k_quic_strategy_arms(&c);char qtext[16384],rtext[16384];
        d2k_quic_props p={0};p.junk_ahead=p.longer=D2K_PROP_YES;
        CHECK(!d2k_quic_question_plan(&winner,qtext,sizeof qtext));
        CHECK(!d2k_quic_compose_plan(&a,&p,rtext,sizeof rtext));
        gate(qtext,rtext,initial,len,0,0);gate(qtext,rtext,longer,longer_len,0,0);
    }
    strategy_mode=6;
    d2k_quic_arm_context all_no={0};all_no.pool=pool;all_no.n_pool=1;all_no.marked=1;
    all_no.probe=oracle;all_no.data=data;all_no.need_complete=1;all_no.budget_pk=50;
    d2k_quic_arm negative=d2k_quic_strategy_arms(&all_no);
    CHECK(negative.kind==D2K_QA_NOT_FOUND);
    for(int property=0;property<2;property++){
        d2k_quic_props p={0};char text[16384];
        if(property)p.longer=D2K_PROP_YES;else p.junk_ahead=D2K_PROP_YES;
        CHECK(!d2k_quic_compose_plan(NULL,&p,text,sizeof text));
        gate(text,text,initial,len,0,0);gate(text,text,longer,longer_len,0,0);
    }
    uint8_t txid[12],request[20],prefix[20]={0};d2k_stun_request(request,sizeof request,txid);
    char voice[16384];CHECK(d2k_voice_arm_plan(prefix,sizeof prefix,1,voice,sizeof voice)==0);
    gate(voice,voice,request,sizeof request,0,1);
    for(unsigned copies=6;copies<=10;copies+=4){
        CHECK(!d2k_voice_arm_plan(prefix,sizeof prefix,copies,voice,sizeof voice));
        gate(voice,voice,request,sizeof request,0,1);
    }
    uint8_t discovery[74]={0,1,0,70};discovery[7]=1;
    CHECK(!d2k_voice_arm_plan(prefix,sizeof prefix,1,voice,sizeof voice));
    gate(voice,voice,discovery,sizeof discovery,0,1);
    /* Failure after TTL prefix preparation must restore socket TTL. */
    ctx(4);current_ttl=context.ttl;fail_send=1;d2k_quic_arm_question q={.blob=prefix,.blob_len=20,.copies=2,.ttl=3};
    char text[16384];CHECK(!d2k_quic_question_plan(&q,text,sizeof text));
    CHECK(d2k_udp_plan_send(42,text,initial,len,0)<0 && current_ttl==47);fail_send=0;
    sent_count=0;CHECK(d2k_udp_plan_send(42,"invalid",initial,len,0)<0 && !sent_count);
    d2k_udp_batch invalid={0};
    CHECK(d2k_udp_plan_build("d2k-plan 1 1\nid 00000000000000000000000000000000\nproto udp quic\npayload 1 00\npoison 1 ipidzero\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\n",&context,1,initial,len,&invalid)<0);
    CHECK(!d2k_voice_arm_plan(prefix,sizeof prefix,32,voice,sizeof voice));
    CHECK(d2k_udp_plan_build(voice,&context,1,request,sizeof request,&invalid)<0);
    printf("UDP runtime: %u full-packet cases, %zu distinct actual questions, %d failures\n",cases,n_questions,fails);
    for(size_t i=0;i<n_questions;i++)free(seen_questions[i]);
    return fails?1:0;
}
