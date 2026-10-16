#define _POSIX_C_SOURCE 200809L
#include "tg_listener.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

int tg_listener_decode_original_dst(const uint8_t *raw,size_t len,uint16_t *port,uint8_t ipv4[4]) {
    uint16_t family,network_port;
    if(!raw||!port||!ipv4||len<8)return -1;
    memcpy(&family,raw,sizeof(family));
    if(family!=AF_INET)return -1;
    memcpy(&network_port,raw+2,sizeof(network_port));*port=ntohs(network_port);
    memcpy(ipv4,raw+4,4);return *port?0:-1;
}

int tg_listener_is_self_dial(const uint8_t ip[4],uint16_t port,const uint16_t *ports,size_t count) {
    if(!ip)return 1;
    for(size_t i=0;i<count;i++)if(ports&&ports[i]==port)return 1;
    if(ip[0]==0 || ip[0]==10 || ip[0]==127 ||
       (ip[0]==169&&ip[1]==254) || (ip[0]==172&&ip[1]>=16&&ip[1]<=31) ||
       (ip[0]==192&&ip[1]==168))return 1;
    return 0;
}

int tg_listener_get_original_dst(int fd,uint16_t *port,uint8_t ipv4[4]) {
#if defined(__linux__)
    struct sockaddr_in addr; socklen_t len=sizeof(addr);
    memset(&addr,0,sizeof(addr));
    if(getsockopt(fd,SOL_IP,TG_SO_ORIGINAL_DST,&addr,&len)!=0)return -1;
    return tg_listener_decode_original_dst((const uint8_t *)&addr,len,port,ipv4);
#else
    (void)fd;(void)port;(void)ipv4;return -1;
#endif
}

int tg_listener_decode_original_dst_any(const uint8_t *raw, size_t len,
                                        tg_listener_destination *out) {
    if (!raw || !out || len < sizeof(sa_family_t)) return -1;
    sa_family_t family;
    memcpy(&family, raw, sizeof(family));
    memset(out, 0, sizeof(*out));
    if (family == AF_INET) {
        struct sockaddr_in addr;
        if (len < sizeof(addr)) return -1;
        memcpy(&addr, raw, sizeof(addr));
        if (addr.sin_family != AF_INET || addr.sin_port == 0) return -1;
        out->family = AF_INET;
        out->port = ntohs(addr.sin_port);
        memcpy(out->address, &addr.sin_addr, sizeof(addr.sin_addr));
        return 0;
    }
    if (family == AF_INET6) {
        struct sockaddr_in6 addr;
        if (len < sizeof(addr)) return -1;
        memcpy(&addr, raw, sizeof(addr));
        if (addr.sin6_family != AF_INET6 || addr.sin6_port == 0) return -1;
        out->family = AF_INET6;
        out->port = ntohs(addr.sin6_port);
        memcpy(out->address, &addr.sin6_addr, sizeof(addr.sin6_addr));
        return 0;
    }
    return -1;
}

#if defined(__linux__)
static int original_dst_option(int fd, int level, int option,
                               tg_listener_destination *out) {
    uint8_t raw[sizeof(struct sockaddr_in6)];
    socklen_t len = sizeof(raw);
    memset(raw, 0, sizeof(raw));
    if (getsockopt(fd, level, option, raw, &len) != 0) return -1;
    return tg_listener_decode_original_dst_any(raw, len, out);
}
#endif

int tg_listener_get_original_dst_any(int fd, tg_listener_destination *out) {
#if defined(__linux__)
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    if (fd < 0 || !out || getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0)
        return -1;
    if (peer.ss_family == AF_INET) {
        if (original_dst_option(fd, SOL_IP, TG_SO_ORIGINAL_DST, out) == 0) return 0;
        return original_dst_option(fd, IPPROTO_IPV6, TG_SO_ORIGINAL_DST, out);
    }
    if (peer.ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)&peer;
        if (IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr)) {
            if (original_dst_option(fd, SOL_IP, TG_SO_ORIGINAL_DST, out) == 0) return 0;
            return original_dst_option(fd, IPPROTO_IPV6, TG_SO_ORIGINAL_DST, out);
        }
        if (original_dst_option(fd, IPPROTO_IPV6, TG_SO_ORIGINAL_DST, out) == 0) return 0;
        return original_dst_option(fd, SOL_IP, TG_SO_ORIGINAL_DST, out);
    }
    return -1;
#else
    (void)fd;
    (void)out;
    return -1;
#endif
}

static int ipv4_non_global(const uint8_t ip[4]) {
    return ip[0] == 0 || ip[0] == 10 || ip[0] == 127 || ip[0] >= 224 ||
           (ip[0] == 100 && (ip[1] & 0xc0) == 0x40) ||
           (ip[0] == 169 && ip[1] == 254) ||
           (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
           (ip[0] == 192 && (ip[1] == 168 ||
                             (ip[1] == 0 && (ip[2] == 0 || ip[2] == 2)))) ||
           (ip[0] == 198 && (ip[1] == 18 || ip[1] == 19 ||
                             (ip[1] == 51 && ip[2] == 100))) ||
           (ip[0] == 203 && ip[1] == 0 && ip[2] == 113);
}

int tg_listener_is_self_dial_addr(const tg_listener_destination *destination,
                                  const uint16_t *listen_ports,
                                  size_t port_count) {
    if (!destination || !destination->port || destination->port == 80)
        return 1;
    for (size_t i = 0; i < port_count; ++i)
        if (listen_ports && destination->port == listen_ports[i]) return 1;
    if (destination->family == AF_INET)
        return ipv4_non_global(destination->address);
    if (destination->family != AF_INET6) return 1;

    const uint8_t *ip = destination->address;
    static const uint8_t v4_mapped_prefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
    };
    if (memcmp(ip, v4_mapped_prefix, sizeof(v4_mapped_prefix)) == 0)
        return ipv4_non_global(ip + 12);
    static const uint8_t zero[16] = {0};
    if (memcmp(ip, zero, sizeof(zero)) == 0 ||
        (memcmp(ip, zero, 15) == 0 && ip[15] == 1) ||
        (ip[0] & 0xfe) == 0xfc || ip[0] == 0xff ||
        (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) ||
        (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8))
        return 1;
    return 0;
}
