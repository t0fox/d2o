#define _POSIX_C_SOURCE 200809L
#include "tg_config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static char *trim(char *s) {
    while(isspace((unsigned char)*s))s++;
    size_t n=strlen(s);while(n&&isspace((unsigned char)s[n-1]))s[--n]='\0';
    return s;
}

static int copy_value(char *dst,size_t cap,const char *src) {
    size_t n=strlen(src);if(n>=cap)return -1;memcpy(dst,src,n+1);return 0;
}

static int normalize_domain(const char *input, char output[TG_CONFIG_DOMAIN_SIZE]) {
    char value[1024];
    size_t length = strlen(input);
    if (!length || length >= sizeof(value)) return -1;
    for (size_t i = 0; i <= length; ++i)
        value[i] = (char)tolower((unsigned char)input[i]);
    char *domain = value;
    if (strncmp(domain, "https://", 8) == 0) domain += 8;
    else if (strncmp(domain, "http://", 7) == 0) domain += 7;
    char *path = strchr(domain, '/');
    if (path) *path = '\0';
    length = strlen(domain);
    while (length && domain[length - 1] == '.') domain[--length] = '\0';
    if (!length || length > TG_CONFIG_DOMAIN_SIZE - 1u ||
        strpbrk(domain, ":@?#\\ \t\r\n")) return -1;
    struct in_addr address;
    if (inet_pton(AF_INET, domain, &address) == 1) return -1;
    size_t label_start = 0, label_count = 0;
    int tld_has_alpha = 0;
    for (size_t i = 0; i <= length; ++i) {
        if (i < length && domain[i] != '.') {
            unsigned char c = (unsigned char)domain[i];
            if (!(isalnum(c) || c == '-')) return -1;
            continue;
        }
        size_t label_length = i - label_start;
        if (!label_length || label_length > 63 || domain[label_start] == '-' ||
            domain[i - 1] == '-') return -1;
        ++label_count;
        if (i == length) {
            if (label_length < 2) return -1;
            for (size_t j = label_start; j < i; ++j)
                if (isalpha((unsigned char)domain[j])) tld_has_alpha = 1;
        }
        label_start = i + 1;
    }
    if (label_count < 2 || !tld_has_alpha) return -1;
    memcpy(output, domain, length + 1u);
    return 0;
}

static int parse_domain_list(char domains[][TG_CONFIG_DOMAIN_SIZE],
                             size_t *count, size_t capacity,
                             const char *input) {
    char list[2048];
    if (!input || !*input || strlen(input) >= sizeof(list) ||
        copy_value(list, sizeof(list), input) != 0) return -1;
    size_t used = 0;
    char *item = list;
    for (;;) {
        char *separator = strchr(item, ',');
        if (separator) *separator = '\0';
        item = trim(item);
        char normalized[TG_CONFIG_DOMAIN_SIZE];
        if (!*item || normalize_domain(item, normalized) != 0) return -1;
        int duplicate = 0;
        for (size_t i = 0; i < used; ++i)
            if (strcmp(domains[i], normalized) == 0) duplicate = 1;
        if (!duplicate) {
            if (used == capacity) return -1;
            memcpy(domains[used++], normalized, strlen(normalized) + 1u);
        }
        if (!separator) break;
        item = separator + 1;
    }
    *count = used;
    return 0;
}

static int parse_boolean(const char *value, int *out) {
    if (strcmp(value, "1") == 0 || strcmp(value, "yes") == 0) *out = 1;
    else if (strcmp(value, "0") == 0 || strcmp(value, "no") == 0) *out = 0;
    else return -1;
    return 0;
}

static int parse_bounded_uint(const char *value, uint32_t maximum,
                              uint32_t *out) {
    if (!*value) return -1;
    for (const char *p = value; *p; ++p)
        if (!isdigit((unsigned char)*p)) return -1;
    errno = 0;
    unsigned long long number = strtoull(value, NULL, 10);
    if (errno || number > maximum) return -1;
    *out = (uint32_t)number;
    return 0;
}

static int normalize_shell_value(char *value) {
    size_t n=strlen(value);
    if(!n)return 0;
    if(value[0]=='\''||value[0]=='"') {
        if(n<2||value[n-1]!=value[0])return -1;
        char quote=value[0];size_t inner=n-2;value[n-1]='\0';
        for(size_t i=0;i<inner;i++)value[i]=value[i+1];
        value[inner]='\0';
        if(strchr(value,quote))return -1;
    } else if(value[n-1]=='\''||value[n-1]=='"')return -1;
    return 0;
}

int tg_config_read(const char *path,tg_config *out) {
    enum { K_ENABLED=1u<<0,K_CA=1u<<1,K_STATUS=1u<<2,K_PORT=1u<<3,
           K_STATE=1u<<4,K_MODE=1u<<5,K_DC_MAP=1u<<6,K_STATS_SOCKET=1u<<7,
           K_CF_WORKER=1u<<8,K_CF_PROXY=1u<<9,K_CF_BALANCE=1u<<10,
           K_WS_ROUTING=1u<<11,K_WS_HEDGE_DELAY=1u<<12,K_WS_HEDGE_LIMIT=1u<<13,
           K_DEFAULT_DOMAINS=1u<<14,K_CF_CACHE=1u<<15 };
    FILE *f;char line[2048],state_dir[512]="/opt/d2k/state";unsigned seen=0;int rc=-1;
    int have_status=0,have_dc_map=0,have_stats_socket=0;
    int have_cf_cache=0;
    if(!path||!out)return -1;
    memset(out,0,sizeof(*out));out->listen_port=1443;
    out->ws_routing=TG_WS_ROUTING_ADAPTIVE;
    out->ws_hedge_delay_ms=125;
    out->ws_hedge_limit=8;
    if(copy_value(out->ca_bundle,sizeof(out->ca_bundle),"/opt/d2k/files/tg-roots.pem")||
       copy_value(out->status_path,sizeof(out->status_path),"/opt/d2k/state/telegram.status")||
       copy_value(out->dc_map_path,sizeof(out->dc_map_path),"/opt/d2k/state/telegram-dc-map.json")||
       copy_value(out->stats_socket_path,sizeof(out->stats_socket_path),"/opt/d2k/state/telegram.stats.sock"))return -1;
    const char *managed_ca=getenv("D2K_TG_CA_BUNDLE");
    if(managed_ca&&*managed_ca&&copy_value(out->ca_bundle,sizeof(out->ca_bundle),managed_ca))return -1;
    f=fopen(path,"r");if(!f)return -1;
    while(fgets(line,sizeof(line),f)) {
        if(!strchr(line,'\n')&&!feof(f))goto done;
        char *s=trim(line);if(!*s||*s=='#')continue;
        char *eq=strchr(s,'=');if(!eq)continue;*eq++='\0';char *key=trim(s),*value=trim(eq);
        unsigned bit=0;char *dst=NULL;size_t cap=0;
        if(strcmp(key,"TG_ENABLED")==0)bit=K_ENABLED;
        else if(strcmp(key,"TG_CA_BUNDLE")==0){bit=K_CA;dst=out->ca_bundle;cap=sizeof(out->ca_bundle);}
        else if(strcmp(key,"TG_STATUS")==0){bit=K_STATUS;dst=out->status_path;cap=sizeof(out->status_path);}
        else if(strcmp(key,"TG_PORT")==0)bit=K_PORT;
        else if(strcmp(key,"TG_MODE")==0)bit=K_MODE;
        else if(strcmp(key,"TG_DC_MAP_PATH")==0){bit=K_DC_MAP;dst=out->dc_map_path;cap=sizeof(out->dc_map_path);}
        else if(strcmp(key,"TG_STATS_SOCKET")==0){bit=K_STATS_SOCKET;dst=out->stats_socket_path;cap=sizeof(out->stats_socket_path);}
        else if(strcmp(key,"TG_CF_WORKER_DOMAIN")==0)bit=K_CF_WORKER;
        else if(strcmp(key,"TG_CF_DOMAIN")==0)bit=K_CF_PROXY;
        else if(strcmp(key,"TG_CF_BALANCE")==0)bit=K_CF_BALANCE;
        else if(strcmp(key,"TG_WS_ROUTING")==0)bit=K_WS_ROUTING;
        else if(strcmp(key,"TG_WS_HEDGE_DELAY_MS")==0)bit=K_WS_HEDGE_DELAY;
        else if(strcmp(key,"TG_WS_HEDGE_LIMIT")==0)bit=K_WS_HEDGE_LIMIT;
        else if(strcmp(key,"TG_DEFAULT_DOMAINS")==0)bit=K_DEFAULT_DOMAINS;
        else if(strcmp(key,"TG_CF_DOMAIN_CACHE_PATH")==0){bit=K_CF_CACHE;dst=out->cf_domain_cache_path;cap=sizeof(out->cf_domain_cache_path);}
        else if(strcmp(key,"STATE_DIR")==0){bit=K_STATE;dst=state_dir;cap=sizeof(state_dir);}
        if(!bit)continue;
        if (seen & bit) { goto done; }
        seen |= bit;
        if(normalize_shell_value(value)!=0)goto done;
        if(bit==K_ENABLED) {
            if(strcmp(value,"1")==0||strcmp(value,"yes")==0)out->enabled=1;
            else if(strcmp(value,"0")==0||strcmp(value,"no")==0)out->enabled=0;
            else goto done;
        } else if(bit==K_MODE) {
            if(strcmp(value,"local")==0)out->local_mode=1;
            else goto done;
        } else if(bit==K_PORT) {
            if(!*value)goto done;
            for(const char *p=value;*p;p++)if(!isdigit((unsigned char)*p))goto done;
            errno=0;unsigned long v=strtoul(value,NULL,10);if(errno||v==0||v>65535)goto done;
            if(v!=1443)goto done;
            out->listen_port=(uint16_t)v;
        } else if(bit==K_CF_WORKER) {
            if(parse_domain_list(out->cf_worker_domains,
                &out->cf_worker_domain_count,
                TG_CONFIG_MAX_CF_WORKER_DOMAINS,value)!=0)goto done;
        } else if(bit==K_CF_PROXY) {
            if(parse_domain_list(out->cf_proxy_domains,
                &out->cf_proxy_domain_count,
                TG_CONFIG_MAX_CF_PROXY_DOMAINS,value)!=0)goto done;
        } else if(bit==K_CF_BALANCE) {
            if(parse_boolean(value,&out->cf_balance)!=0)goto done;
        } else if(bit==K_WS_ROUTING) {
            if(strcmp(value,"adaptive")==0)out->ws_routing=TG_WS_ROUTING_ADAPTIVE;
            else if(strcmp(value,"sequential")==0)out->ws_routing=TG_WS_ROUTING_SEQUENTIAL;
            else if(strcmp(value,"cf-first")==0)out->ws_routing=TG_WS_ROUTING_CF_FIRST;
            else if(strcmp(value,"hedged")==0)out->ws_routing=TG_WS_ROUTING_HEDGED;
            else goto done;
        } else if(bit==K_WS_HEDGE_DELAY) {
            if(parse_bounded_uint(value,60000,&out->ws_hedge_delay_ms)!=0)goto done;
        } else if(bit==K_WS_HEDGE_LIMIT) {
            if(parse_bounded_uint(value,32,&out->ws_hedge_limit)!=0)goto done;
        } else if(bit==K_DEFAULT_DOMAINS) {
            if(parse_boolean(value,&out->default_domains)!=0)goto done;
        } else if(!*value||copy_value(dst,cap,value)!=0)goto done;
        if(bit==K_STATUS)have_status=1;
        if(bit==K_DC_MAP)have_dc_map=1;
        if(bit==K_STATS_SOCKET)have_stats_socket=1;
        if(bit==K_CF_CACHE)have_cf_cache=1;
    }
    if(ferror(f))goto done;
    if(state_dir[0]!='/')goto done;
    if(!have_status&&snprintf(out->status_path,sizeof(out->status_path),"%s/telegram.status",state_dir)>=(int)sizeof(out->status_path))goto done;
    if(!have_dc_map&&snprintf(out->dc_map_path,sizeof(out->dc_map_path),"%s/telegram-dc-map.json",state_dir)>=(int)sizeof(out->dc_map_path))goto done;
    if(!have_stats_socket&&snprintf(out->stats_socket_path,sizeof(out->stats_socket_path),"%s/telegram.stats.sock",state_dir)>=(int)sizeof(out->stats_socket_path))goto done;
    if(!have_cf_cache&&snprintf(out->cf_domain_cache_path,sizeof(out->cf_domain_cache_path),"%s/telegram-cf-domains.cache",state_dir)>=(int)sizeof(out->cf_domain_cache_path))goto done;
    if(out->ca_bundle[0]!='/'||out->status_path[0]!='/'||out->dc_map_path[0]!='/'||out->stats_socket_path[0]!='/'||out->cf_domain_cache_path[0]!='/')goto done;
    rc=0;
done:
    fclose(f);if(rc!=0)tg_config_clean(out);return rc;
}

void tg_config_clean(tg_config *cfg) {
    if (!cfg) { return; }
    memset(cfg,0,sizeof(*cfg));
}
