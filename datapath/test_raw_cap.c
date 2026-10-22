/* test_raw_cap.c — предел посылки берётся с выхода сырой посылки. */
#define _DEFAULT_SOURCE 1
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>

#include "d2k_raw.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "test_raw_cap OUT LOW (имена интерфейсов)\n");
        return 2;
    }
    const char *out = argv[1], *low = argv[2];
    uint32_t oif = if_nametoindex(out), lowif = if_nametoindex(low);
    uint32_t none = 0x7ffffff0u;
    assert(oif && lowif);
    char err[256], names[128];

    d2k_raw *r = d2k_raw_open(0, NULL, err, sizeof err);
    if (!r) { fprintf(stderr, "d2k_raw_open: %s\n", err); return 1; }
    assert(d2k_raw_maxlen(r) == 1280);
    assert(d2k_raw_adopt_egress(r, &oif, 1, names, sizeof names) == 1);
    assert(d2k_raw_maxlen(r) == 1500);
    assert(strstr(names, out) != NULL && strstr(names, "1500") != NULL);
    assert(d2k_raw_adopt_egress(r, &oif, 1, NULL, 0) == 0);
    assert(d2k_raw_maxlen(r) == 1500);

    uint32_t both[2] = {oif, lowif};
    assert(d2k_raw_adopt_egress(r, both, 2, names, sizeof names) == 1);
    assert(d2k_raw_maxlen(r) == 1280);
    assert(strstr(names, low) != NULL && strstr(names, out) != NULL);
    assert(d2k_raw_adopt_egress(r, &none, 1, NULL, 0) == -1);
    assert(d2k_raw_maxlen(r) == 1280);
    assert(d2k_raw_adopt_egress(r, &oif, 1, NULL, 0) == 1);
    assert(d2k_raw_maxlen(r) == 1500);
    d2k_raw_close(r);

    d2k_raw *d = d2k_raw_open(0, low, err, sizeof err);
    if (!d) { fprintf(stderr, "d2k_raw_open(%s): %s\n", low, err); return 1; }
    assert(d2k_raw_maxlen(d) == 1280);
    assert(d2k_raw_adopt_egress(d, &oif, 1, NULL, 0) == -1);
    assert(d2k_raw_maxlen(d) == 1280);
    d2k_raw_close(d);

    puts("test_raw_cap: ok");
    return 0;
}
