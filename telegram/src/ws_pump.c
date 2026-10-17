#define _POSIX_C_SOURCE 200809L
#include "tg_ws.h"

#include <fcntl.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct tg_ws_tx_frame { struct tg_ws_tx_frame *next; uint8_t *bytes; size_t len,offset,allocated; int mtproto_payload; };
#define TG_WS_PUMP_TX_LIMIT (TG_WS_MAX_MESSAGE + 14u + sizeof(struct tg_ws_tx_frame))
#define TG_WS_PUMP_RX_RETAIN (64u * 1024u)
#define TG_WS_PUMP_RX_LIMIT (TG_WS_MAX_MESSAGE + 10u)

static void release_frames(tg_ws_pump *p,tg_ws_tx_frame *frame) {
    while(frame){tg_ws_tx_frame *next=frame->next;
        size_t charged=frame->allocated+sizeof(*frame);
        p->tx_memory_bytes-=charged;
        OPENSSL_clear_free(frame->bytes,frame->allocated);free(frame);
        tg_memory_budget_release(p->memory_budget,charged);
        frame=next;}
}

int tg_ws_pump_init(tg_ws_pump *p,SSL *ssl) {
    return tg_ws_pump_init_accounted(p, ssl, NULL);
}

int tg_ws_pump_init_accounted(tg_ws_pump *p, SSL *ssl,
                              tg_memory_budget *memory_budget) {
    if(!p||!ssl)return -1;
    memset(p,0,sizeof(*p));p->ssl=ssl;p->fd=SSL_get_fd(ssl);
    p->memory_budget = memory_budget;
    p->reassembly.memory_budget = memory_budget;
    if(p->fd<0)return -1;
    if (memory_budget &&
        tg_memory_budget_reserve(memory_budget, TG_WS_PUMP_RX_INITIAL) != 0)
        return -1;
    p->rx=malloc(TG_WS_PUMP_RX_INITIAL);
    if(!p->rx){tg_memory_budget_release(memory_budget,
                                         TG_WS_PUMP_RX_INITIAL);return -1;}
    p->rx_cap=TG_WS_PUMP_RX_INITIAL;
    int flags=fcntl(p->fd,F_GETFL,0);
    if(flags<0||fcntl(p->fd,F_SETFL,flags|O_NONBLOCK)<0){free(p->rx);
        tg_memory_budget_release(memory_budget, p->rx_cap);
        memset(p,0,sizeof(*p));return -1;}
    return 0;
}

static int reserve_rx(tg_ws_pump *p,size_t needed) {
    if(needed>TG_WS_PUMP_RX_LIMIT)return -1;
    if(needed<=p->rx_cap)return 0;
    size_t cap=p->rx_cap?p->rx_cap:TG_WS_PUMP_RX_INITIAL;
    while(cap<needed){
        if(cap>TG_WS_PUMP_RX_LIMIT/2u){cap=TG_WS_PUMP_RX_LIMIT;break;}
        cap*=2u;
    }
    if(cap<needed)return -1;
    if(p->memory_budget&&tg_memory_budget_reserve(p->memory_budget,cap)!=0)
        return -1;
    uint8_t *grown=realloc(p->rx,cap);
    if(!grown){tg_memory_budget_release(p->memory_budget,cap);return -1;}
    tg_memory_budget_release(p->memory_budget,p->rx_cap);
    p->rx=grown;p->rx_cap=cap;
    return 0;
}

static void trim_idle_buffers(tg_ws_pump *p) {
    if(p->rx_len==0&&p->rx_cap>TG_WS_PUMP_RX_RETAIN){
        uint8_t *small=realloc(p->rx,TG_WS_PUMP_RX_INITIAL);
        if(small){
            tg_memory_budget_release(p->memory_budget,
                p->rx_cap-TG_WS_PUMP_RX_INITIAL);
            p->rx=small;p->rx_cap=TG_WS_PUMP_RX_INITIAL;
        }
    }
    if(!p->reassembly.fragmented&&p->reassembly.len==0&&
       p->reassembly.cap>TG_WS_PUMP_RX_RETAIN){
        size_t old_cap=p->reassembly.cap;
        OPENSSL_clear_free(p->reassembly.data,old_cap);
        p->reassembly.data=NULL;
        p->reassembly.cap=0;
        tg_memory_budget_release(p->memory_budget,old_cap);
        if(!p->memory_budget||tg_memory_budget_reserve(p->memory_budget,
                TG_WS_PUMP_RX_INITIAL)==0){
            uint8_t *small=OPENSSL_malloc(TG_WS_PUMP_RX_INITIAL);
            if(small){
                p->reassembly.data=small;
                p->reassembly.cap=TG_WS_PUMP_RX_INITIAL;
            }else{
                tg_memory_budget_release(p->memory_budget,
                    TG_WS_PUMP_RX_INITIAL);
            }
        }
    }
}

void tg_ws_pump_destroy(tg_ws_pump *p) {
    if(!p) { return; }
    release_frames(p,p->tx_head);tg_ws_reassembly_destroy(&p->reassembly);
    free(p->rx);tg_memory_budget_release(p->memory_budget,p->rx_cap);
    memset(p,0,sizeof(*p));p->fd=-1;
}

static int queue_opcode(tg_ws_pump *p,uint8_t opcode,const uint8_t *data,
                        size_t len,int mtproto_payload) {
    if(!p||p->failed||p->closed||(!data&&len)||len>TG_WS_MAX_MESSAGE)return -1;
    size_t alloc=len+14,written=0;
    if(p->tx_memory_bytes>TG_WS_PUMP_TX_LIMIT||
       alloc+sizeof(tg_ws_tx_frame)>TG_WS_PUMP_TX_LIMIT-p->tx_memory_bytes)return -1;
    size_t charge=alloc+sizeof(tg_ws_tx_frame);
    if(p->memory_budget&&tg_memory_budget_reserve(p->memory_budget,charge)!=0)
        return -1;
    tg_ws_tx_frame *f=calloc(1,sizeof(*f));if(!f){
        tg_memory_budget_release(p->memory_budget,charge);return -1;}
    f->bytes=OPENSSL_malloc(alloc);if(!f->bytes){free(f);
        tg_memory_budget_release(p->memory_budget,charge);return -1;}
    if(tg_ws_encode_client_frame(f->bytes,alloc,opcode,data,len,&written)!=0){
        OPENSSL_clear_free(f->bytes,alloc);free(f);
        tg_memory_budget_release(p->memory_budget,charge);return -1;}
    f->len=written;f->allocated=alloc;f->mtproto_payload=mtproto_payload;
    if(p->tx_tail) { p->tx_tail->next=f; }
    else { p->tx_head=f; }
    p->tx_tail=f;p->tx_bytes+=written;
    p->tx_memory_bytes+=alloc+sizeof(*f);
    return 0;
}

int tg_ws_pump_queue_binary(tg_ws_pump *p,const uint8_t *data,size_t len){return queue_opcode(p,TG_WS_BINARY,data,len,0);}
int tg_ws_pump_queue_mtproto_payload(tg_ws_pump *p,const uint8_t *data,
                                     size_t len){return queue_opcode(p,TG_WS_BINARY,data,len,1);}
int tg_ws_pump_queue_ping(tg_ws_pump *p,const uint8_t *data,size_t len){return queue_opcode(p,TG_WS_PING,data,len,0);}
int tg_ws_pump_queue_close(tg_ws_pump *p){return queue_opcode(p,TG_WS_CLOSE,NULL,0,0);}
int tg_ws_pump_fd(const tg_ws_pump *p){return p?p->fd:-1;}
short tg_ws_pump_events(const tg_ws_pump *p){
    if(!p||p->failed||p->closed)return 0;
    short events=POLLIN;
    if(p->tx_head||p->read_wants_write)events|=POLLOUT;
    return events;
}

static int append_fragment(tg_ws_reassembly *state, const uint8_t *data,
                           size_t len, size_t limit) {
    if (state->len > limit || len > limit - state->len) return -1;
    size_t needed = state->len + len;
    if (needed > state->cap) {
        size_t cap = state->cap ? state->cap : 256u;
        while (cap < needed) {
            if (cap > limit / 2u) { cap = limit; break; }
            cap *= 2u;
        }
        if (cap < needed) return -1;
        if(state->memory_budget&&
           tg_memory_budget_reserve(state->memory_budget,cap)!=0)return -1;
        uint8_t *buffer = OPENSSL_malloc(cap);
        if (!buffer) {
            tg_memory_budget_release(state->memory_budget,cap);
            return -1;
        }
        if (state->len) memcpy(buffer, state->data, state->len);
        OPENSSL_clear_free(state->data, state->cap);
        tg_memory_budget_release(state->memory_budget,state->cap);
        state->data = buffer;
        state->cap = cap;
    }
    if (len) memcpy(state->data + state->len, data, len);
    state->len = needed;
    return 0;
}

void tg_ws_reassembly_destroy(tg_ws_reassembly *state) {
    if (!state) return;
    OPENSSL_clear_free(state->data, state->cap);
    tg_memory_budget_release(state->memory_budget,state->cap);
    memset(state, 0, sizeof(*state));
}

static int valid_utf8(const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t lead = data[i++];
        if (lead <= 0x7fu) continue;
        size_t tails;
        uint8_t second_min = 0x80u, second_max = 0xbfu;
        if (lead >= 0xc2u && lead <= 0xdfu) tails = 1;
        else if (lead == 0xe0u) { tails = 2; second_min = 0xa0u; }
        else if ((lead >= 0xe1u && lead <= 0xecu) ||
                 (lead >= 0xeeu && lead <= 0xefu)) tails = 2;
        else if (lead == 0xedu) { tails = 2; second_max = 0x9fu; }
        else if (lead == 0xf0u) { tails = 3; second_min = 0x90u; }
        else if (lead >= 0xf1u && lead <= 0xf3u) tails = 3;
        else if (lead == 0xf4u) { tails = 3; second_max = 0x8fu; }
        else return 0;
        if (tails > len - i || data[i] < second_min ||
            data[i] > second_max) return 0;
        for (size_t j = 1; j < tails; ++j)
            if ((data[i + j] & 0xc0u) != 0x80u) return 0;
        i += tails;
    }
    return 1;
}

/* Обрабатывает один серверный кадр и собирает фрагментированные сообщения. */
int tg_ws_reassembly_feed(tg_ws_reassembly *state, const uint8_t *src,
                          size_t len, size_t max_payload, uint8_t *opcode,
                          const uint8_t **payload, size_t *payload_len,
                          size_t *consumed) {
    uint64_t wire_len;
    size_t header;
    if (!state || !src || !opcode || !payload || !payload_len || !consumed)
        return -1;
    *payload = NULL;
    *payload_len = 0;
    *consumed = 0;
    if (max_payload > TG_WS_MAX_MESSAGE) max_payload = TG_WS_MAX_MESSAGE;
    if (len < 2) return 0;
    if ((src[0] & 0x70u) != 0 || (src[1] & 0x80u) != 0) return -1;

    uint8_t fin = src[0] >> 7;
    uint8_t op = src[0] & 0x0fu;
    if (op != TG_WS_CONTINUATION && op != TG_WS_TEXT && op != TG_WS_BINARY &&
        op != TG_WS_CLOSE && op != TG_WS_PING && op != TG_WS_PONG)
        return -1;

    if ((src[1] & 0x7fu) < 126u) {
        wire_len = src[1] & 0x7fu;
        header = 2;
    } else if ((src[1] & 0x7fu) == 126u) {
        if (len < 4) return 0;
        wire_len = ((uint64_t)src[2] << 8) | src[3];
        if (wire_len < 126u) return -1;
        header = 4;
    } else {
        if (len < 10) return 0;
        if ((src[2] & 0x80u) != 0) return -1;
        wire_len = 0;
        for (size_t i = 0; i < 8; ++i)
            wire_len = (wire_len << 8) | src[2 + i];
        if (wire_len <= UINT16_MAX) return -1;
        header = 10;
    }
    if (wire_len > max_payload || wire_len > SIZE_MAX - header) return -1;
    if (op >= TG_WS_CLOSE && (wire_len > 125u || !fin)) return -1;
    size_t total = header + (size_t)wire_len;
    if (len < total) return 0;
    *consumed = total;

    if (op == TG_WS_CLOSE &&
        (wire_len == 1u ||
         (wire_len > 2u && !valid_utf8(src + header + 2u,
                                      (size_t)wire_len - 2u))))
        return -1;
    if (op >= TG_WS_CLOSE) {
        *opcode = op;
        *payload = src + header;
        *payload_len = (size_t)wire_len;
        return 1;
    }

    if (op == TG_WS_TEXT || op == TG_WS_BINARY) {
        if (state->fragmented) return -1;
        if (fin) {
            if (op == TG_WS_TEXT &&
                !valid_utf8(src + header, (size_t)wire_len))
                return -1;
            *opcode = op;
            *payload = src + header;
            *payload_len = (size_t)wire_len;
            return 1;
        }
        state->fragmented = 1;
        state->opcode = op;
        state->len = 0;
        return append_fragment(state, src + header, (size_t)wire_len,
                               max_payload) == 0 ? 2 : -1;
    }

    if (!state->fragmented) return -1;
    if (append_fragment(state, src + header, (size_t)wire_len,
                        max_payload) != 0)
        return -1;
    if (!fin) return 2;
    if (state->opcode == TG_WS_TEXT && !valid_utf8(state->data, state->len))
        return -1;
    *opcode = state->opcode;
    *payload = state->data;
    *payload_len = state->len;
    state->fragmented = 0;
    state->opcode = 0;
    state->len = 0;
    return 1;
}

static int dispatch_frames(tg_ws_pump *p,tg_ws_message_cb callback,void *ctx) {
    while(p->rx_len){
        uint8_t op=0;const uint8_t *data=NULL;size_t len=0,used=0;
        int ready=tg_ws_reassembly_feed(&p->reassembly,p->rx,p->rx_len,
                    TG_WS_MAX_MESSAGE,&op,&data,&len,&used);
        if(ready<0)return -1;
        if(ready==0)return 0;
        if(ready==1){
            if(op==TG_WS_PING){if(queue_opcode(p,TG_WS_PONG,data,len,0)!=0)return -1;}
            else if(op==TG_WS_CLOSE){p->closed=1;return 0;}
            else if(op==TG_WS_TEXT)return -1;
            else if(op==TG_WS_BINARY&&callback&&
                    callback(ctx,data,len)!=0)return -1;
            trim_idle_buffers(p);
        }
        memmove(p->rx,p->rx+used,p->rx_len-used);p->rx_len-=used;
    }
    return 0;
}

static int flush_tx(tg_ws_pump *p) {
    p->write_wants_read=0;
    while(p->tx_head){tg_ws_tx_frame *f=p->tx_head;size_t n=0;
        if(f->mtproto_payload)p->mtproto_payload_write_attempted=1;
        int rc=SSL_write_ex(p->ssl,f->bytes+f->offset,f->len-f->offset,&n);
        if(rc!=1){int error=SSL_get_error(p->ssl,rc);
            if(error==SSL_ERROR_WANT_READ){p->write_wants_read=1;return 0;}
            if(error==SSL_ERROR_WANT_WRITE)return 0;
            p->failed=1;return -1;
        }
        if(!n){p->failed=1;return -1;}f->offset+=n;p->tx_bytes-=n;
        if(f->offset==f->len){p->tx_head=f->next;if(!p->tx_head)p->tx_tail=NULL;f->next=NULL;release_frames(p,f);}
    }
    return 0;
}

int tg_ws_pump_process(tg_ws_pump *p,short revents,tg_ws_message_cb callback,void *ctx) {
    if(!p||p->failed)return -1;
    if(revents&(POLLERR|POLLNVAL)){p->failed=1;return -1;}
    if((revents&POLLOUT)||p->tx_head||p->write_wants_read)if(flush_tx(p)!=0)return -1;
    if((revents&POLLIN)||p->read_wants_write||SSL_pending(p->ssl)>0){
        p->read_wants_write=0;
        for(;;){
            if(p->rx_len==p->rx_cap&&reserve_rx(p,p->rx_len+1u)!=0){p->failed=1;return -1;}
            size_t n=0;int rc=SSL_read_ex(p->ssl,p->rx+p->rx_len,p->rx_cap-p->rx_len,&n);
            if(rc!=1){int error=SSL_get_error(p->ssl,rc);
                if(error==SSL_ERROR_WANT_READ)break;
                if(error==SSL_ERROR_WANT_WRITE){p->read_wants_write=1;break;}
                if(error==SSL_ERROR_ZERO_RETURN){p->closed=1;trim_idle_buffers(p);return 0;}
                p->failed=1;return -1;
            }
            if(!n){p->failed=1;return -1;}p->rx_len+=n;
            if(dispatch_frames(p,callback,ctx)!=0){p->failed=1;return -1;}
            if(p->closed){trim_idle_buffers(p);return 0;}
        }
    }
    if(revents&POLLHUP)p->closed=1;
    trim_idle_buffers(p);
    return p->failed?-1:0;
}
