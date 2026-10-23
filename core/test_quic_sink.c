#define __APPLE_USE_RFC_3542
/* Keep the syscall capture and real Session comparator in one reusable gate. */
#define main udp_runtime_gate_main
#include "test_udp_runtime.c"
#undef main
#define getsockname mock_local
#define getpeername mock_peer
#define getsockopt mock_get
#define setsockopt mock_set
#define send mock_send
#define nanosleep mock_sleep
#include "quicprobe.c"
#undef send
#include "test_quic_pq.h"
#define send mock_send
#undef getsockname
#undef getpeername
#undef getsockopt
#undef setsockopt
#undef send
#undef nanosleep
int main(void){
    ctx(4);current_ttl=47;sent_count=0;uint8_t prefix[16]={0},bad[32]={0};
    d2k_quic_arm_question q={.blob=prefix,.blob_len=sizeof prefix,.copies=11,.split=1};
    qp_arm_action a={0};a.q=&q;a.family=AF_INET;
    /* In the former sender fake11 escaped BEFORE the split was validated. */
    CHECK(qp_arm_first_send(42,bad,sizeof bad,&a)<0);
    CHECK(sent_count==0 && !a.initial_out);
    uint8_t initial[4096];size_t n=0;CHECK(!d2k_quic_probe_initial("example.com",initial,sizeof initial,&n));
    q.split=0;q.ttl=3;q.copies=2;fail_send=1;current_ttl=47;
    CHECK(qp_arm_first_send(42,initial,n,&a)<0);
    CHECK(current_ttl==47);fail_send=0;
    for(int family=4;family<=6;family+=2){
        ctx(family);current_ttl=47;sent_count=lower_count=elapsed=0;
        CHECK(qp_arm_first_send(42,initial,n,&a)==1);
        CHECK(sent_count==3 && sent[0].ttl==3 && sent[1].ttl==3 && sent[2].ttl==47);
        CHECK(sent[2].len==n && !memcmp(sent[2].bytes,initial,n));
        CHECK(current_ttl==47 && elapsed==0);
        d2k_quic_arm_question length={.udplen=D2K_QUIC_LENGTH_INCREMENT};
        a.q=&length;a.initial_out=0;sent_count=0;
        CHECK(qp_arm_first_send(42,initial,n,&a)==1 && a.initial_out);
        CHECK(sent_count==1 && sent[0].len==n+D2K_QUIC_LENGTH_INCREMENT);
        CHECK(!memcmp(sent[0].bytes,initial,n));
        const uint8_t zeros[D2K_QUIC_LENGTH_INCREMENT]={0};
        CHECK(!memcmp(sent[0].bytes+n,zeros,sizeof zeros));
        a.q=&q;
    }
    /* ПАЧКА УЕЗЖАЕТ ЦЕЛИКОМ И ПО ПОРЯДКУ (задача 66). Приветствие Chrome с
       ML-KEM — две Initial-датаграммы; одна посылка на пачку означала бы
       датаграмму в 2,4 КБ, которой клиент не слал и которую сеть порежет. */
    {
        uint8_t d1[1500],d2[1500];
        size_t l1=0,l2=0;
        CHECK(d2k_test_pq_initials("rutracker.org",d1,&l1,d2,&l2)==0);
        const uint8_t *dgs[2]={d1,d2};
        size_t lens[2]={l1,l2};
        static uint8_t blob[D2K_SHAPE_MAX];
        size_t bl=d2k_qsnap_pack(dgs,lens,2,blob,sizeof blob);
        CHECK(bl>0);
        ctx(4);current_ttl=47;sent_count=lower_count=elapsed=0;
        int marked=0;
        d2k_hello msg={blob,bl,NULL,0,0, 0};
        int fd=qp_send_one("127.0.0.1",443,NULL,0,0,0,0,msg,0,&marked,0,0);
        CHECK(sent_count==2);
        CHECK(sent[0].len==l1 && sent[1].len==l2);
        CHECK(!memcmp(sent[0].bytes,d1,l1) && !memcmp(sent[1].bytes,d2,l2));
        if(fd>=0)close(fd);
    }
    printf("QUIC actual first-send sink: %d failures\n",fails);return fails?1:0;
}
