#define _POSIX_C_SOURCE 200809L
#include "tg_dc_map.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENDPOINTS 16u

static int split_fields(char *text, char separator, char **fields, size_t count) {
    fields[0] = text;
    for (size_t i = 1; i < count; ++i) {
        char *next = strchr(fields[i - 1], separator);
        if (!next) return -1;
        *next = '\0';
        fields[i] = next + 1;
    }
    return strchr(fields[count - 1], separator) ? -1 : 0;
}

static int parse_number(const char *text, unsigned long max,
                        unsigned long *out) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (!text[0] || errno || !end || *end || value > max) return -1;
    *out = value;
    return 0;
}

static int parse_endpoint(char *text, tg_dc_endpoint *out) {
    char *fields[8];
    unsigned long id, port, flags[5];
    if (split_fields(text, ',', fields, 8) != 0) return -1;
    if (parse_number(fields[0], 999, &id) != 0 ||
        parse_number(fields[2], 65535, &port) != 0)
        return -1;
    for (size_t i = 0; i < 5; ++i)
        if (parse_number(fields[i + 3], 1, &flags[i]) != 0) return -1;

    memset(out, 0, sizeof(*out));
    out->id = (uint32_t)id;
    out->family = strchr(fields[1], ':') ? AF_INET6 : AF_INET;
    if (inet_pton(out->family, fields[1], out->address) != 1) return -1;
    out->port = (uint16_t)port;
    out->media_only = (int)flags[0];
    out->tcpo_only = (int)flags[1];
    out->cdn = (int)flags[2];
    out->is_static = (int)flags[3];
    out->this_port_only = (int)flags[4];
    out->last_seen = 1;
    return 0;
}

static int parse_destination(const char *text, uint16_t port,
                             tg_listener_destination *out) {
    memset(out, 0, sizeof(*out));
    out->port = port;
    out->family = strchr(text, ':') ? AF_INET6 : AF_INET;
    return inet_pton(out->family, text, out->address) == 1 ? 0 : -1;
}

static const char *status_text(int status) {
    switch (status) {
    case TG_DC_LOOKUP_OK: return "OK";
    case TG_DC_LOOKUP_NOT_LISTED: return "not-listed";
    case TG_DC_LOOKUP_PORT: return "port";
    case TG_DC_LOOKUP_MEDIA: return "media";
    case TG_DC_LOOKUP_DC: return "dc";
    case TG_DC_LOOKUP_CDN: return "cdn";
    case TG_DC_LOOKUP_AMBIGUOUS: return "ambiguous";
    default: return "invalid";
    }
}

static int run_line(char *line) {
    char *fields[7];
    unsigned long port, media_hint, dc_hint, endpoint_count = 0;
    tg_dc_endpoint endpoints[MAX_ENDPOINTS];
    tg_dc_snapshot snapshot = {0};
    tg_dc_snapshot *snapshot_ptr = NULL;
    tg_listener_destination destination;
    tg_dc_endpoint route;
    tg_dc_map_source source;
    if (split_fields(line, '\t', fields, 7) != 0 ||
        parse_number(fields[3], 65535, &port) != 0 || port == 0 ||
        parse_number(fields[4], 1, &media_hint) != 0 ||
        parse_number(fields[5], 999, &dc_hint) != 0 ||
        parse_destination(fields[2], (uint16_t)port, &destination) != 0)
        return -1;

    if (strcmp(fields[1], "official") == 0) {
        char *save = NULL;
        for (char *item = strtok_r(fields[6], "/", &save); item;
             item = strtok_r(NULL, "/", &save)) {
            if (endpoint_count == MAX_ENDPOINTS ||
                parse_endpoint(item, &endpoints[endpoint_count]) != 0)
                return -1;
            ++endpoint_count;
        }
        if (endpoint_count == 0) return -1;
        snapshot.endpoints = endpoints;
        snapshot.endpoint_count = endpoint_count;
        snapshot_ptr = &snapshot;
    } else if (strcmp(fields[1], "builtin") != 0 || fields[6][0]) {
        return -1;
    }

    int status = tg_dc_resolve(snapshot_ptr, &destination, (int)media_hint,
                               (uint32_t)dc_hint, 0, &route, &source);
    printf("%s\t%s", fields[0], status_text(status));
    if (status == TG_DC_LOOKUP_OK) {
        char address[INET6_ADDRSTRLEN];
        if (!inet_ntop(route.family, route.address, address, sizeof(address)))
            return -1;
        printf("\t%u\t%s\t%u\t%d\t%d\t%d\t%d\t%d", route.id,
               address, route.port, route.media_only, route.tcpo_only,
               route.cdn, route.is_static, route.this_port_only);
    }
    putchar('\n');
    return 0;
}

int main(void) {
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    size_t line_number = 0;
    while ((length = getline(&line, &capacity, stdin)) >= 0) {
        ++line_number;
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        if (run_line(line) != 0) {
            fprintf(stderr, "неверный сценарий карты DC, строка %zu\n", line_number);
            free(line);
            return 2;
        }
    }
    free(line);
    return ferror(stdin) ? 1 : 0;
}
