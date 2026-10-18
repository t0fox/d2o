/* test_plans.c — таблица планов по целям.
 *
 * Главное здесь: порядок поиска, владение памятью и вытеснение по давности.
 * Порядок «имя, потом адрес» — не вкус: обратный дал бы плану соседа по CDN
 * перебить план, подтверждённый для конкретного имени. Владение проверяется
 * тем, что санитайзер гоняет этот же набор. Вытеснение проверяется
 * ПОВЕДЕНИЕМ таблицы (что находится, а не что отказало) — по требованию
 * задачи: внутреннее поле давности наружу не выставлено и не должно быть.
 */
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include "d2k_plans.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Минимальный годный план: только порядок. */
static const uint8_t tiny[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 1,
    0x01, 0x03, 0x00, 0x01, 0x00
};

static d2k_plan *mkplan(void) {
    d2k_plan *p = NULL;
    char err[128];
    if (d2k_plan_load(tiny, sizeof tiny, &p, err, sizeof err) != 0) {
        printf("ПРОВАЛ: тестовый план не грузится: %s\n", err);
        fails++;
        return NULL;
    }
    return p;
}

/* quicdeny (задача 50): UDP, исполнитель 11, одна запись QDENY. */
static const uint8_t deny_tlv[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 11, 0, 0, 0, 2,
    0x00, 0x02, 0x00, 0x02, 17, 2,
    0x01, 0x10, 0x00, 0x01, 0x01,
};
static d2k_plan *mkdeny(void) {
    d2k_plan *p = NULL;
    char err[128];
    if (d2k_plan_load(deny_tlv, sizeof deny_tlv, &p, err, sizeof err) != 0) return NULL;
    return p;
}

static uint32_t addr(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    uint8_t v[4] = {a, b, c, d};
    uint32_t r;
    memcpy(&r, v, 4);
    return r;
}

int main(void) {
    /* Entropy unavailable: keep packet plans usable, but do not invent proof. */
    {
        struct rlimit saved, closed;
        int got = getrlimit(RLIMIT_NOFILE, &saved) == 0;
        CHECK(got, "read descriptor limit");
        if (got) {
            closed = saved; closed.rlim_cur = 0;
            int limited = setrlimit(RLIMIT_NOFILE, &closed) == 0;
            CHECK(limited, "entropy failure fixture");
            if (limited) {
                d2k_plantab *tab = d2k_plantab_new(1);
                int restored = setrlimit(RLIMIT_NOFILE, &saved) == 0;
                CHECK(restored, "restore descriptor limit");
                d2k_plan *plan = mkplan();
                CHECK(!d2k_plantab_set_name_family(tab, (const uint8_t *)"unknown.test", 12,
                      1, plan, D2K_PLAN_SHAPE_MODERN, 0, 4), "unknown identity plan install");
                d2k_binding_context context;
                memset(&context, 0xff, sizeof context);
                const d2k_binding_context zero = {0};
                CHECK(!d2k_plantab_binding(tab, plan, &context) &&
                      !memcmp(&context, &zero, sizeof context), "entropy failure fabricated identity");
                CHECK(d2k_plantab_find_target(tab, (const uint8_t *)"unknown.test", 12,
                      NULL, 4, 2, D2K_PLAN_SHAPE_MODERN, 0) == plan,
                      "identity failure disabled existing packet program");
                d2k_plantab_free(tab);
            }
        }
    }
    /* A restarted table installs the same program first. Delayed evidence
       from its predecessor must never identify this new installation. */
    {
        d2k_binding_context previous = {0}, current = {0};
        for (int restart = 0; restart < 2; restart++) {
            d2k_plantab *tab = d2k_plantab_new(1);
            d2k_plan *plan = mkplan();
            CHECK(!d2k_plantab_set_name_family(tab, (const uint8_t *)"restart.test", 12,
                  1, plan, D2K_PLAN_SHAPE_MODERN, 0, 4), "restart fixture install");
            CHECK(d2k_plantab_binding(tab, plan, &current), "restart fixture identity");
            if (restart) CHECK(memcmp(&previous, &current, sizeof current),
                               "restart reused complete installation identity");
            previous = current;
            d2k_plantab_free(tab);
        }
    }
    {
        /* Issue #2: a new ECH/GREASE member inherits the learned TLS 1.3
           suffix, while dedicated ECH families and exceptions keep priority. */
        const uint8_t root[] = "discord.media", child[] = "new.discord.media";
        const uint8_t narrow[] = "region.discord.media", leaf[] = "new.region.discord.media";
        for (uint8_t family = 4; family <= 6; family += 2) {
            d2k_plantab *t = d2k_plantab_new(8);
            d2k_plan *modern = mkplan(), *ech = mkplan(), *specific = mkplan();
            CHECK(t && modern && ech && specific, "suffix ECH fixture");
            CHECK(!d2k_plantab_set_suffix_family(t, root, sizeof root-1, 1,
                  modern, D2K_PLAN_SHAPE_MODERN, family), "learned TLS13 suffix");
            CHECK(d2k_plantab_find_family(t, child, sizeof child-1, 0, 2,
                  D2K_PLAN_SHAPE_ECH_TCP, 0, family) == modern,
                  "new ECH/GREASE member inherits TLS13 suffix on first lookup");
            CHECK(!d2k_plantab_has_ech_target(t, child, sizeof child-1, NULL, family, 0),
                  "TLS13 fallback does not claim dedicated ECH evidence");
            CHECK(!d2k_plantab_find_family(t, child, sizeof child-1, 0, 2,
                  D2K_PLAN_SHAPE_LEGACY, 0, family), "TLS13 suffix never leaks to TLS12");
            CHECK(!d2k_plantab_set_suffix_family(t, narrow, sizeof narrow-1, 2,
                  specific, D2K_PLAN_SHAPE_MODERN, family), "narrow TLS13 suffix");
            CHECK(d2k_plantab_find_family(t, leaf, sizeof leaf-1, 0, 3,
                  D2K_PLAN_SHAPE_ECH_TCP, 0, family) == specific,
                  "ECH fallback preserves longest suffix");
            CHECK(!d2k_plantab_set_suffix_family(t, root, sizeof root-1, 3,
                  ech, D2K_PLAN_SHAPE_ECH_TCP, family), "dedicated ECH suffix");
            CHECK(d2k_plantab_find_family(t, leaf, sizeof leaf-1, 0, 4,
                  D2K_PLAN_SHAPE_ECH_TCP, 0, family) == ech,
                  "dedicated ECH suffix precedes even narrower TLS13 fallback");
            CHECK(d2k_plantab_find_family(t, child, sizeof child-1, 0, 4,
                  D2K_PLAN_SHAPE_MODERN, 0, family) == modern,
                  "ECH suffix does not replace ordinary TLS13 family");
            CHECK(d2k_plantab_del_suffix_family(t, root, sizeof root-1, 6,
                  D2K_PLAN_SHAPE_ECH_TCP, family) == 1, "remove dedicated ECH suffix");
            CHECK(!d2k_plantab_set_bypass_family(t, child, sizeof child-1, 6,
                  D2K_PLAN_SHAPE_ECH_TCP, family), "ECH-specific exception");
            CHECK(!d2k_plantab_find_family(t, child, sizeof child-1, 0, 5,
                  D2K_PLAN_SHAPE_ECH_TCP, 0, family), "ECH bypass blocks TLS13 fallback");
            CHECK(d2k_plantab_del_bypass_family(t, child, sizeof child-1, 6,
                  D2K_PLAN_SHAPE_ECH_TCP, family) == 1, "remove ECH exception");
            CHECK(!d2k_plantab_set_bypass_family(t, child, sizeof child-1, 6,
                  D2K_PLAN_SHAPE_MODERN, family), "TLS13 family exception");
            CHECK(!d2k_plantab_find_family(t, child, sizeof child-1, 0, 6,
                  D2K_PLAN_SHAPE_ECH_TCP, 0, family), "TLS13 bypass also blocks inherited fallback");
            d2k_plantab_free(t);
        }
    }
    {
        d2k_plantab *t = d2k_plantab_new(1);
        char name[64];
        for (size_t i = 0; i < D2K_PLAN_SUFFIX_MAX; i++) {
            snprintf(name, sizeof name, "g%zu.example.com", i);
            CHECK(!d2k_plantab_set_suffix_family(t, (const uint8_t *)name, strlen(name), 1, mkplan(), 1, 4),
                "bounded area insertion");
        }
        CHECK(d2k_plantab_set_suffix_family(t, (const uint8_t *)"overflow.example.com", 20, 1, mkplan(), 1, 4) == -1,
            "area overflow refuses without eviction");
        CHECK(d2k_plantab_find(t, (const uint8_t *)"new.g0.example.com", 18, 0, 2, 1), "old group survives overflow");
        CHECK(d2k_plantab_set_suffix_family(t, (const uint8_t *)"bad..example.com", 16, 1, mkplan(), 1, 4) == -2,
            "invalid labels rejected");
        CHECK(d2k_plantab_set_suffix_family(t, (const uint8_t *)"example.com", 11, 1, mkplan(), 0, 4) == -2,
            "unknown shape cannot broaden learned group");
        d2k_plantab_free(t);
    }
    {
        const uint8_t root[] = "googlevideo.com", child[] = "rr-new.googlevideo.com";
        const uint8_t narrow[] = "edge.googlevideo.com", leaf[] = "rr.edge.googlevideo.com";
        d2k_plantab *t = d2k_plantab_new(2);
        d2k_plan *group = mkplan(), *specific = mkplan(), *exact = mkplan(), *trial = mkplan();
        CHECK(!d2k_plantab_set_suffix_family(t, root, sizeof root-1, 1, group, 1, 4), "install suffix");
        CHECK(d2k_plantab_find(t, child, sizeof child-1, 0, 2, 1) == group, "unseen child inherits immediately");
        CHECK(d2k_plantab_count(t) == 0, "inheritance creates no exact slots");
        CHECK(d2k_plantab_find(t, root, sizeof root-1, 0, 2, 1) == group, "suffix includes root");
        CHECK(!d2k_plantab_find(t, (const uint8_t *)"evilgooglevideo.com", 19, 0, 2, 1), "DNS label boundary");
        CHECK(!d2k_plantab_find(t, child, sizeof child-1, 0, 2, 2), "TLS12 does not inherit TLS13");
        CHECK(!d2k_plantab_find_family(t, child, sizeof child-1, 0, 2, 1, 0, 6), "family isolation");
        CHECK(!d2k_plantab_find(t, NULL, 0, 0, 2, 1), "no SNI means no suffix inheritance");
        CHECK(!d2k_plantab_set_suffix_family(t, narrow, sizeof narrow-1, 3, specific, 1, 4), "narrow suffix");
        CHECK(d2k_plantab_find(t, leaf, sizeof leaf-1, 0, 4, 1) == specific, "longest suffix wins");
        CHECK(!d2k_plantab_set_name_shaped(t, child, sizeof child-1, 3, exact, 1), "exact override");
        CHECK(d2k_plantab_find(t, child, sizeof child-1, 0, 4, 1) == exact, "exact overrides suffix");
        CHECK(!d2k_plantab_set_bypass_family(t, child, sizeof child-1, 6, 1, 4), "install exact bypass");
        /* Task 22: an exception learnt for the family never overrides the
           member's own exact entry of the observed shape (§7/§9.10). */
        CHECK(d2k_plantab_find(t, child, sizeof child-1, 0, 5, 1) == exact,
              "exact name entry of observed shape wins over family bypass");
        {
            const uint8_t other[] = "rr-other.googlevideo.com";
            CHECK(d2k_plantab_find(t, other, sizeof other-1, 0, 5, 1) == group,
                  "sibling without exception still inherits");
            CHECK(!d2k_plantab_set_bypass_family(t, other, sizeof other-1, 6, 1, 4), "sibling bypass");
            CHECK(!d2k_plantab_find(t, other, sizeof other-1, 0, 5, 1),
                  "bypass without exact entry prevents suffix plan");
            CHECK(!d2k_plantab_find(t, child, sizeof child-1, 0, 5, 2),
                  "exact TLS13 entry does not leak to TLS12 through bypass precedence");
            CHECK(d2k_plantab_del_bypass_family(t, other, sizeof other-1, 6, 1, 4) == 1,
                  "remove sibling bypass");
        }
        CHECK(!d2k_plantab_set_name_probe(t, child, sizeof child-1, 5, trial, 1, 123), "trial setup");
        CHECK(d2k_plantab_find_sport(t, child, sizeof child-1, 0, 6, 1, 123) == trial, "trial overrides bypass");
        CHECK(d2k_plantab_del_bypass_family(t, child, sizeof child-1, 6, 1, 4) == 1, "remove bypass");
        CHECK(d2k_plantab_find(t, child, sizeof child-1, 0, 7, 1) == exact, "exact survives bypass removal");
        CHECK(d2k_plantab_del_suffix_family(t, root, sizeof root-1, 6, 1, 4) == 1, "remove only broad suffix");
        CHECK(d2k_plantab_find(t, leaf, sizeof leaf-1, 0, 8, 1) == specific, "narrow suffix survives");
        d2k_plan *ech_group = mkplan();
        CHECK(!d2k_plantab_set_suffix_family(t, root, sizeof root-1, 9, ech_group, 6, 6), "IPv6 ECH suffix");
        CHECK(d2k_plantab_has_ech_target(t, child, sizeof child-1, NULL, 6, 0), "fragmented ECH gets group hold");
        CHECK(!d2k_plantab_has_ech_target(t, NULL, 0, NULL, 6, 0), "ECH group never inferred from IP");
        CHECK(!d2k_plantab_set_bypass_family(t, child, sizeof child-1, 6, 6, 6), "ECH bypass");
        CHECK(!d2k_plantab_has_ech_target(t, child, sizeof child-1, NULL, 6, 0), "ECH exception suppresses hold");
        {
            d2k_plan *own_ech = mkplan();
            CHECK(!d2k_plantab_set_name_family(t, child, sizeof child-1, 10, own_ech,
                                               D2K_PLAN_SHAPE_ECH_TCP, 0, 6), "own exact ECH entry");
            CHECK(d2k_plantab_has_ech_target(t, child, sizeof child-1, NULL, 6, 0),
                  "own exact ECH entry keeps hold despite family bypass");
        }
        d2k_plantab_free(t);
    }
    {
        const uint8_t nm[] = "outer.test";
        d2k_plantab *t = d2k_plantab_new(8);
        d2k_plan *ordinary = mkplan(), *ech = mkplan();
        CHECK(t && ordinary && ech, "ECH fixture allocation");
        if (t && ordinary && ech) {
            CHECK(!d2k_plantab_set_name_shaped(t, nm, sizeof nm - 1, 1, ordinary,
                                               D2K_PLAN_SHAPE_MODERN), "ordinary TLS seed");
            CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, 0, 2,
                                  D2K_PLAN_SHAPE_ECH_TCP) == ordinary, "GREASE retains old TLS plan");
            CHECK(!d2k_plantab_set_name_shaped(t, nm, sizeof nm - 1, 3, ech,
                                               D2K_PLAN_SHAPE_ECH_TCP), "ECH seed");
            CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, 0, 4,
                                  D2K_PLAN_SHAPE_ECH_TCP) == ech, "dedicated ECH preferred");
            CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, 0, 5,
                                  D2K_PLAN_SHAPE_MODERN) == ordinary, "ECH does not replace plain TLS");
        }
        d2k_plantab_free(t);
    }
    {
        /* Final review #3/#6: the member's OWN exact entry beats a family
           BYPASS also through the ECH->MODERN fallback and through a
           grandfathered (unshaped legacy) name entry for TCP TLS shapes.
           BYPASS still removes the inherited suffix plan elsewhere, and a
           grandfather entry does not override a QUIC exception. */
        const uint8_t root[] = "own.test", child[] = "m.own.test", sib[] = "s.own.test";
        const uint8_t old[] = "g.own.test";
        d2k_plantab *t = d2k_plantab_new(8);
        d2k_plan *group = mkplan(), *ech_group = mkplan(), *quic_group = mkplan();
        d2k_plan *modern = mkplan(), *legacy_gf = mkplan();
        CHECK(t && group && ech_group && quic_group && modern && legacy_gf, "own/bypass fixture");
        if (t) {
            CHECK(!d2k_plantab_set_suffix_family(t, root, sizeof root-1, 1, group,
                                                 D2K_PLAN_SHAPE_MODERN, 4), "modern suffix");
            CHECK(!d2k_plantab_set_suffix_family(t, root, sizeof root-1, 1, ech_group,
                                                 D2K_PLAN_SHAPE_ECH_TCP, 4), "ech suffix");
            CHECK(!d2k_plantab_set_suffix_family(t, root, sizeof root-1, 1, quic_group,
                                                 D2K_PLAN_SHAPE_QUIC, 4), "quic suffix");
            CHECK(!d2k_plantab_set_name_shaped(t, child, sizeof child-1, 2, modern,
                                               D2K_PLAN_SHAPE_MODERN), "own exact TLS1.3");
            CHECK(!d2k_plantab_set_bypass_family(t, child, sizeof child-1, 6,
                                                 D2K_PLAN_SHAPE_ECH_TCP, 4), "ECH bypass");
            CHECK(d2k_plantab_find(t, child, sizeof child-1, 0, 3,
                                   D2K_PLAN_SHAPE_ECH_TCP) == modern,
                  "ECH-shaped flow: own exact TLS1.3 entry must win over family BYPASS");
            CHECK(!d2k_plantab_set_bypass_family(t, sib, sizeof sib-1, 6,
                                                 D2K_PLAN_SHAPE_ECH_TCP, 4), "sibling ECH bypass");
            CHECK(!d2k_plantab_find(t, sib, sizeof sib-1, 0, 3, D2K_PLAN_SHAPE_ECH_TCP),
                  "ECH bypass without own entry still removes inherited plan");
            CHECK(!d2k_plantab_set_name(t, old, sizeof old-1, 4, legacy_gf), "grandfather entry");
            CHECK(!d2k_plantab_set_bypass_family(t, old, sizeof old-1, 6,
                                                 D2K_PLAN_SHAPE_MODERN, 4), "modern bypass on legacy");
            CHECK(!d2k_plantab_set_bypass_family(t, old, sizeof old-1, 17,
                                                 D2K_PLAN_SHAPE_QUIC, 4), "quic bypass on legacy");
            CHECK(d2k_plantab_find(t, old, sizeof old-1, 0, 5, D2K_PLAN_SHAPE_MODERN) == legacy_gf,
                  "grandfathered exact name entry must win over family BYPASS (TCP TLS)");
            CHECK(!d2k_plantab_find(t, old, sizeof old-1, 0, 5, D2K_PLAN_SHAPE_QUIC),
                  "grandfather entry must not override a QUIC family exception");
            d2k_plantab_free(t);
        }
    }
    {
        d2k_plantab *t = d2k_plantab_new(8);
        const uint8_t a[16] = {0x20,1,0xdb,8,0,0,0,0,0,0,0,0,192,0,2,1};
        uint8_t b[16]; memcpy(b, a, 16); b[4] = 1;
        d2k_plan *p = mkplan(), *q = mkplan(), *v4 = mkplan();
        CHECK(d2k_plantab_set_addr_family(t, a, 6, 1, p) == 0, "IPv6 address plan");
        CHECK(d2k_plantab_set_addr_family(t, b, 6, 1, q) == 0, "upper bits address plan");
        CHECK(d2k_plantab_set_addr_family(t, a + 12, 4, 1, v4) == 0, "IPv4 address plan");
        CHECK(d2k_plantab_count(t) == 3, "address families/upper bits merged");
        CHECK(d2k_plantab_find_target(t, NULL, 0, a, 6, 2, 0, 0) == p, "IPv6 address lookup");
        CHECK(d2k_plantab_find_target(t, NULL, 0, b, 6, 2, 0, 0) == q, "IPv6 upper bits lookup");
        CHECK(d2k_plantab_find_target(t, NULL, 0, a + 12, 4, 2, 0, 0) == v4, "IPv4 address lookup");
        CHECK(d2k_plantab_del_addr_family(t, a, 6) == 1, "IPv6 address removal");
        CHECK(d2k_plantab_find_target(t, NULL, 0, b, 6, 3, 0, 0) == q &&
              d2k_plantab_find_target(t, NULL, 0, a + 12, 4, 3, 0, 0) == v4,
              "IPv6 delete removed other target");
        d2k_plantab_free(t);
    }
    {
        d2k_plantab *t = d2k_plantab_new(8);
        const uint8_t name[] = "dual.example";
        d2k_plan *v4 = mkplan(), *v6 = mkplan(), *trial = mkplan();
        CHECK(d2k_plantab_set_name_family(t, name, 12, 1, v4, D2K_PLAN_SHAPE_MODERN, 0, 4) == 0,
              "IPv4 family plan setup");
        CHECK(d2k_plantab_set_name_family(t, name, 12, 1, v6, D2K_PLAN_SHAPE_MODERN, 0, 6) == 0,
              "IPv6 family plan setup");
        CHECK(d2k_plantab_count(t) == 2, "one family overwrote another");
        CHECK(d2k_plantab_find_family(t, name, 12, 0, 2, D2K_PLAN_SHAPE_MODERN, 0, 4) == v4,
              "IPv4 received IPv6 plan");
        CHECK(d2k_plantab_find_family(t, name, 12, 0, 2, D2K_PLAN_SHAPE_MODERN, 0, 6) == v6,
              "IPv6 received IPv4 plan");
        CHECK(d2k_plantab_set_name_family(t, name, 12, 3, trial, D2K_PLAN_SHAPE_MODERN, 123, 6) == 0,
              "IPv6 trial setup");
        d2k_plantab_clear_probes(t);
        CHECK(d2k_plantab_count(t) == 2 &&
              d2k_plantab_find_family(t, name, 12, 0, 4, D2K_PLAN_SHAPE_MODERN, 123, 6) == v6,
              "controller disconnect must remove trials but preserve confirmed families");
        /* Раунд 4 (M3): запрет QUIC — не знание каталога. Контроллер ушёл —
           снимается вместе с опытами, иначе осиротевший запрет жил бы до
           перезапуска d2kd. Подтверждённое не трогается. */
        {
            const uint8_t dn[] = "deny.example";
            d2k_plan *dp = mkdeny();
            CHECK(dp != NULL, "quicdeny fixture");
            CHECK(d2k_plantab_set_name_family(t, dn, 12, 2, dp, D2K_PLAN_SHAPE_QUIC, 0, 4) == 0,
                  "quicdeny setup");
            d2k_plantab_clear_probes(t);
            CHECK(d2k_plantab_find_family(t, dn, 12, 0, 3, D2K_PLAN_SHAPE_QUIC, 0, 4) == NULL,
                  "quicdeny пережил уход контроллера");
            CHECK(d2k_plantab_count(t) == 2, "уход контроллера задел подтверждённое");
        }
        trial = mkplan();
        CHECK(d2k_plantab_set_name_family(t, name, 12, 3, trial, D2K_PLAN_SHAPE_MODERN, 123, 6) == 0,
              "new controller trial setup");
        CHECK(d2k_plantab_find_family(t, NULL, 0, 0, 4, D2K_PLAN_SHAPE_MODERN, 123, 4) == NULL,
              "nameless IPv4 received IPv6 trial");
        CHECK(d2k_plantab_find_family(t, NULL, 0, 0, 4, D2K_PLAN_SHAPE_MODERN, 123, 6) == trial,
              "nameless IPv6 lost exact trial");
        CHECK(d2k_plantab_del_name_probe_family(t, name, 12, D2K_PLAN_SHAPE_MODERN, 123, 4) == 0,
              "IPv4 cleanup deleted IPv6 trial");
        CHECK(d2k_plantab_del_name_probe_family(t, name, 12, D2K_PLAN_SHAPE_MODERN, 123, 6) == 1,
              "IPv6 trial cleanup");
        CHECK(d2k_plantab_del_name_family(t, name, 12, 4) == 1, "IPv4 plan cleanup");
        CHECK(d2k_plantab_find_family(t, name, 12, 0, 5, D2K_PLAN_SHAPE_MODERN, 0, 6) == v6,
              "IPv4 cleanup deleted persistent IPv6");
        d2k_plantab_free(t);
    }
    {
        d2k_plantab *t = d2k_plantab_new(4);
        d2k_addr_probe_flow f = {.family=6, .transport=17,
            .src_port_be=0x3412, .dst_port_be=0xbb01,
            .src_ip6={0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,1},
            .dst_ip6={0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,2}};
        uint8_t trial[D2K_TRIAL_ID_LEN] = {1};
        d2k_plan *p = mkplan();
        CHECK(d2k_plantab_set_addr_probe(t, &f, trial, 1, 100, p) == 0,
              "IPv6 exact probe rejected");
        CHECK(d2k_plantab_find_addr_probe(t, &f, 2, NULL) == p, "IPv6 probe not found");
        d2k_addr_probe_flow other = f;
        other.src_ip6[2]++;
        CHECK(d2k_plantab_find_addr_probe(t, &other, 2, NULL) == NULL,
              "IPv6 probe matched only lower address bits");
        CHECK(d2k_plantab_del_addr_probe(t, &other, trial) == 0,
              "another IPv6 source deleted trial");
        other = f; other.family = 4;
        memcpy(other.src_ip4, f.src_ip6, 4); memcpy(other.dst_ip4, f.dst_ip6, 4);
        CHECK(d2k_plantab_find_addr_probe(t, &other, 2, NULL) == NULL,
              "IPv4 matched IPv6 trial");
        CHECK(d2k_plantab_del_addr_probe(t, &f, trial) == 1, "IPv6 cleanup failed");
        d2k_plantab_free(t);
    }
    {
        d2k_plantab *t = d2k_plantab_new(8);
        const uint8_t old[] = "old.example", next[] = "new.example";
        d2k_plan *confirmed = mkplan(), *prior = mkplan(), *current = mkplan();
        d2k_plan *udp = mkplan(), *ipv4 = mkplan();
        CHECK(d2k_plantab_set_name_family(t, old, 11, 1, confirmed,
                  D2K_PLAN_SHAPE_MODERN, 0, 6) == 0, "confirmed port-reuse fixture");
        CHECK(d2k_plantab_set_name_family(t, old, 11, 2, prior,
                  D2K_PLAN_SHAPE_MODERN, 123, 6) == 0, "old probe owner");
        CHECK(d2k_plantab_set_name_family(t, old, 11, 2, udp,
                  D2K_PLAN_SHAPE_QUIC, 123, 6) == 0, "independent UDP port owner");
        CHECK(d2k_plantab_set_name_family(t, old, 11, 2, ipv4,
                  D2K_PLAN_SHAPE_MODERN, 123, 4) == 0, "independent IPv4 port owner");
        CHECK(d2k_plantab_set_name_family(t, next, 11, 3, current,
                  D2K_PLAN_SHAPE_MODERN, 123, 6) == 0, "new probe owner");
        CHECK(d2k_plantab_find_family(t, NULL, 0, 0, 4,
                  D2K_PLAN_SHAPE_MODERN, 123, 6) == current,
              "reused probe port must not select old target's trial");
        CHECK(d2k_plantab_count(t) == 4, "only the old TCP IPv6 port owner must be retired");
        CHECK(d2k_plantab_find_family(t, NULL, 0, 0, 4,
                  D2K_PLAN_SHAPE_QUIC, 123, 6) == udp, "TCP reuse preserves UDP owner");
        CHECK(d2k_plantab_find_family(t, NULL, 0, 0, 4,
                  D2K_PLAN_SHAPE_MODERN, 123, 4) == ipv4, "IPv6 reuse preserves IPv4 owner");
        CHECK(d2k_plantab_find_family(t, old, 11, 0, 4,
                  D2K_PLAN_SHAPE_MODERN, 0, 6) == confirmed,
              "port reuse must preserve confirmed strategies");
        d2k_plantab_free(t);
    }
    /* --- поиск по имени и по адресу ---------------------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(8);
        CHECK(t != NULL, "таблица не создалась");
        CHECK(d2k_plantab_count(t) == 0, "новая таблица не пуста");

        const uint8_t nm[] = "linkedin.com";
        d2k_plan *a = mkplan(), *b = mkplan();
        CHECK(d2k_plantab_set_name(t, nm, sizeof nm - 1, 1, a) == 0, "план по имени не встал");
        CHECK(d2k_plantab_set_addr(t, addr(1, 2, 3, 4), 1, b) == 0, "план по адресу не встал");
        CHECK(d2k_plantab_count(t) == 2, "счётчик записей неверен");

        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, addr(9, 9, 9, 9), 2, D2K_PLAN_SHAPE_ANY) == a,
              "план по имени не нашёлся");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(1, 2, 3, 4), 2, D2K_PLAN_SHAPE_ANY) == b,
              "план по адресу не нашёлся");
        CHECK(d2k_plantab_find(t, (const uint8_t *)"nope.example", 12,
                               addr(9, 9, 9, 9), 2, D2K_PLAN_SHAPE_ANY) == NULL,
              "нашёлся план для незнакомой цели");
        d2k_plantab_free(t);
    }

    /* --- имя важнее адреса --------------------------------------------------
     * За одним адресом CDN стоят сотни имён. Если адрес будет перебивать имя,
     * подтверждённый план цели заменится планом соседа.                       */
    {
        d2k_plantab *t = d2k_plantab_new(8);
        const uint8_t nm[] = "discord.com";
        d2k_plan *by_name = mkplan(), *by_addr = mkplan();
        d2k_plantab_set_name(t, nm, sizeof nm - 1, 1, by_name);
        d2k_plantab_set_addr(t, addr(162, 159, 135, 232), 1, by_addr);
        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, addr(162, 159, 135, 232), 2, D2K_PLAN_SHAPE_ANY) == by_name,
              "адрес перебил имя");
        /* Другое имя на том же адресе падает на адресный план — это законный
           запасной путь, а не приписывание домена. */
        CHECK(d2k_plantab_find(t, (const uint8_t *)"other.example", 13,
                               addr(162, 159, 135, 232), 2, D2K_PLAN_SHAPE_ANY) == by_addr,
              "запасной поиск по адресу не сработал");
        d2k_plantab_free(t);
    }

    /* --- регистр имени незначим ---------------------------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        d2k_plan *p = mkplan();
        d2k_plantab_set_name(t, (const uint8_t *)"Example.COM", 11, 1, p);
        CHECK(d2k_plantab_find(t, (const uint8_t *)"example.com", 11, 0, 2, D2K_PLAN_SHAPE_ANY) == p,
              "регистр имени оказался значимым");
        CHECK(d2k_plantab_find(t, (const uint8_t *)"example.co", 10, 0, 2, D2K_PLAN_SHAPE_ANY) == NULL,
              "префикс имени принят за имя");
        d2k_plantab_free(t);
    }

    /* --- замена плана цели: прежний освобождается ---------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        const uint8_t nm[] = "a.example";
        d2k_plan *first = mkplan(), *second = mkplan();
        d2k_plantab_set_name(t, nm, sizeof nm - 1, 1, first);
        d2k_plantab_set_name(t, nm, sizeof nm - 1, 2, second);
        CHECK(d2k_plantab_count(t) == 1, "замена завела вторую запись");
        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, 0, 3, D2K_PLAN_SHAPE_ANY) == second,
              "после замены нашёлся прежний план");
        d2k_plantab_free(t);
    }

    /* --- удаление ------------------------------------------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        const uint8_t nm[] = "b.example";
        d2k_plantab_set_name(t, nm, sizeof nm - 1, 1, mkplan());
        d2k_plantab_set_addr(t, addr(5, 6, 7, 8), 1, mkplan());
        CHECK(d2k_plantab_del_name(t, nm, sizeof nm - 1) == 1, "удаление по имени не сработало");
        CHECK(d2k_plantab_del_name(t, nm, sizeof nm - 1) == 0, "повторное удаление что-то нашло");
        CHECK(d2k_plantab_find(t, nm, sizeof nm - 1, 0, 2, D2K_PLAN_SHAPE_ANY) == NULL, "удалённый план находится");
        CHECK(d2k_plantab_del_addr(t, addr(5, 6, 7, 8)) == 1, "удаление по адресу не сработало");
        CHECK(d2k_plantab_count(t) == 0, "счётчик после удаления неверен");
        /* Освобождённое место снова годится. */
        CHECK(d2k_plantab_set_name(t, nm, sizeof nm - 1, 2, mkplan()) == 0,
              "после удаления место не переиспользуется");
        d2k_plantab_free(t);
    }

    /* Удаление пробного плана не должно сносить подтверждённый план того же
       имени/формы: это отдельное поколение опыта, а не общая запись цели. */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        const uint8_t nm[] = "probe.example";
        uint16_t sport = 0x1234;
        d2k_plan *persistent = mkplan(), *probe = mkplan();
        CHECK(d2k_plantab_set_name_shaped(t, nm, sizeof nm - 1, 1, persistent,
                                          D2K_PLAN_SHAPE_QUIC) == 0,
              "подтверждённый shaped-план не встал");
        CHECK(d2k_plantab_set_name_probe(t, nm, sizeof nm - 1, 2, probe,
                                         D2K_PLAN_SHAPE_QUIC, sport) == 0,
              "пробный shaped-план не встал");
        CHECK(d2k_plantab_del_name_probe(t, nm, sizeof nm - 1,
                                         D2K_PLAN_SHAPE_QUIC, sport) == 1,
              "точное удаление пробного плана не сработало");
        CHECK(d2k_plantab_find_sport(t, nm, sizeof nm - 1, 0, 3,
                                     D2K_PLAN_SHAPE_QUIC, sport) == persistent,
              "удаление пробного плана задело подтверждённый");
        d2k_plantab_free(t);
    }

    /* --- переполнение: вытеснение самой давно не использованной записи, а не
     * отказ навсегда ------------------------------------------------------------
     * Замер на живом роутере (см. d2k_plans.h, 2026-09-06): без вытеснения
     * таблица набивается доверху ещё до живого трафика (каталог 276 записей
     * против вместимости 256), и КАЖДАЯ следующая цель получает отказ, из
     * которого нет выхода. Владение планом переходит таблице и здесь —
     * возврат 0 не бесплатен, план вытесненной записи освобождён внутри.
     *
     * Давности расставлены НЕ по индексу вставки (2,2,2,2 вставлен ПЕРВЫМ, но
     * его давность БОЛЬШЕ): реализация, вытесняющая по индексу или по порядку
     * вставки вместо настоящей давности, эту проверку не пройдёт. */
    {
        d2k_plantab *t = d2k_plantab_new(2);
        d2k_plantab_set_addr(t, addr(2, 2, 2, 2), 10, mkplan()); /* новее */
        d2k_plantab_set_addr(t, addr(1, 1, 1, 1), 5, mkplan());  /* старше */
        CHECK(d2k_plantab_set_addr(t, addr(3, 3, 3, 3), 20, mkplan()) == 0,
              "переполнение отказало вместо вытеснения");
        CHECK(d2k_plantab_count(t) == 2, "вытеснение изменило число записей");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(3, 3, 3, 3), 21, D2K_PLAN_SHAPE_ANY) != NULL,
              "новая запись после вытеснения не находится");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(1, 1, 1, 1), 21, D2K_PLAN_SHAPE_ANY) == NULL,
              "самая давняя запись пережила вытеснение");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(2, 2, 2, 2), 21, D2K_PLAN_SHAPE_ANY) != NULL,
              "вытеснена не самая давняя запись, а более свежая");
        d2k_plantab_free(t);
    }

    /* --- обращение обновляет давность: тронутая запись переживает
     * вытеснение, нетронутая соседка — нет ---------------------------------
     * Проверяем ПОВЕДЕНИЕМ (что нашлось после вытеснения), а не внутренним
     * полем — оно не выставлено наружу нарочно (см. d2k_plans.h). */
    {
        d2k_plantab *t = d2k_plantab_new(2);
        d2k_plantab_set_addr(t, addr(1, 1, 1, 1), 1, mkplan()); /* старше при вставке */
        d2k_plantab_set_addr(t, addr(2, 2, 2, 2), 2, mkplan()); /* новее при вставке */
        /* Без обращения (1,1,1,1) — самая давняя и вытеснилась бы первой.
           Трогаем именно её отметкой новее соседки — порядок вытеснения
           обязан развернуться. */
        CHECK(d2k_plantab_find(t, NULL, 0, addr(1, 1, 1, 1), 100, D2K_PLAN_SHAPE_ANY) != NULL,
              "обращение к записи её не находит");
        CHECK(d2k_plantab_set_addr(t, addr(3, 3, 3, 3), 101, mkplan()) == 0,
              "вытеснение после обращения отказало");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(1, 1, 1, 1), 200, D2K_PLAN_SHAPE_ANY) != NULL,
              "тронутая запись не пережила вытеснение");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(2, 2, 2, 2), 200, D2K_PLAN_SHAPE_ANY) == NULL,
              "нетронутая соседка пережила вытеснение вместо тронутой");
        d2k_plantab_free(t);
    }

    /* --- негодные аргументы: план всё равно не течёт ---------------------------- */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        CHECK(d2k_plantab_set_name(t, NULL, 0, 1, mkplan()) == -2, "пустое имя принято");
        uint8_t huge[D2K_TARGET_NAME_MAX + 1];
        memset(huge, 'x', sizeof huge);
        CHECK(d2k_plantab_set_name(t, huge, sizeof huge, 1, mkplan()) == -2,
              "слишком длинное имя принято");
        CHECK(d2k_plantab_count(t) == 0, "негодные аргументы что-то записали");
        d2k_plantab_free(t);

        CHECK(d2k_plantab_new(0) == NULL, "таблица на ноль записей создалась");
        d2k_plantab_free(NULL);
        CHECK(d2k_plantab_find(NULL, NULL, 0, 0, 1, D2K_PLAN_SHAPE_ANY) == NULL, "поиск в нулевой таблице");
        CHECK(d2k_plantab_count(NULL) == 0, "счётчик нулевой таблицы");
    }

    /* --- ФОРМА ПРИВЕТСТВИЯ ОГРАНИЧИВАЕТ ПРИМЕНЕНИЕ (0009, U5) -----------
     *
     * Успех собственного зонда на TLS 1.3 ничего не говорит про браузер с
     * TLS 1.2: это разные приветствия, и коробка разбирает их по-разному.
     * До этой правки shape жил только в каталоге контроллера и применение
     * плана не ограничивал вовсе — датапат отдавал план любому обращению к
     * имени.
     *
     * Ноль с любой стороны означает «не объявлено» и совместим со всем: у
     * записи это старый каталог, у наблюдения — приветствие, форму которого
     * разобрать не удалось. Молча перестать применять планы старого каталога
     * нельзя, и выдумывать форму неразобранному приветствию — тоже. */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        CHECK(t != NULL, "таблица для проверки формы не создалась");
        static const uint8_t nm[] = "shape.example";
        size_t nl = sizeof nm - 1;

        CHECK(d2k_plantab_set_name_shaped(t, nm, nl, 1, mkplan(),
                                          D2K_PLAN_SHAPE_MODERN) == 0,
              "план с объявленной формой не поставился");
        CHECK(d2k_plantab_find(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_MODERN) != NULL,
              "план не отдан приветствию СВОЕЙ формы");
        CHECK(d2k_plantab_find(t, nm, nl, 0, 3, D2K_PLAN_SHAPE_LEGACY) == NULL,
              "план, подтверждённый на TLS 1.3, отдан приветствию TLS 1.2");
        /* НЕИЗМЕРЕННОЕ наблюдение подтверждённый план НЕ получает. Раньше
           ноль наблюдения проходил к любой записи, то есть «не измерено»
           выдавалось за доказанную совместимость (0009, U5-R3). Утверждение
           теста перевёрнуто вместе с политикой намеренно: прежнее закрепляло
           ровно ту поблажку, которую требовалось снять. */
        CHECK(d2k_plantab_find(t, nm, nl, 0, 4, D2K_PLAN_SHAPE_ANY) == NULL,
              "план, подтверждённый на конкретной форме, отдан обращению, "
              "про форму которого ничего не известно");

        /* QUIC — ОТДЕЛЬНАЯ форма, и план, подтверждённый на TLS, ему не
           достаётся: другой транспорт, другое приветствие, и переносить туда
           подтверждение нечем (0009, U5). До правки путь QUIC звал поиск с
           ANY и такой план получал. */
        CHECK(d2k_plantab_find(t, nm, nl, 0, 8, D2K_PLAN_SHAPE_QUIC) == NULL,
              "план, подтверждённый на TLS, выдан приветствию QUIC");

        /* ДВА ТРАНСПОРТА ОДНОГО ИМЕНИ ЖИВУТ ОДНОВРЕМЕННО.
         *
         * Замер на роутере Марка 13.09.2026: у www.facebook.com подтверждены
         * и TCP-план, и QUIC-план. Пока запись была одна на имя, вторая
         * привязка затирала первую, и какой из двух обходов работает,
         * решал порядок синхронизации каталога — а клиент за роутером не
         * проходил ни по одному транспорту.
         *
         * Проверяется именно ОДНОВРЕМЕННОСТЬ: поставили QUIC — TLS-план
         * остался на месте и наоборот. */
        {
            const uint8_t two[] = "оба.транспорта";
            size_t tl = sizeof two - 1;
            CHECK(d2k_plantab_set_name_shaped(t, two, tl, 10, mkplan(),
                                              D2K_PLAN_SHAPE_MODERN) == 0,
                  "план TLS не поставился");
            CHECK(d2k_plantab_set_name_shaped(t, two, tl, 11, mkplan(),
                                              D2K_PLAN_SHAPE_QUIC) == 0,
                  "план QUIC не поставился");
            CHECK(d2k_plantab_find(t, two, tl, 0, 12, D2K_PLAN_SHAPE_MODERN) != NULL,
                  "план TLS затёрт привязкой QUIC того же имени");
            CHECK(d2k_plantab_find(t, two, tl, 0, 12, D2K_PLAN_SHAPE_QUIC) != NULL,
                  "план QUIC не нашёлся");
            /* И ни один из них не достаётся форме, на которой его не
               подтверждали. */
            CHECK(d2k_plantab_find(t, two, tl, 0, 12, D2K_PLAN_SHAPE_LEGACY) == NULL,
                  "план выдан приветствию формы, на которой не подтверждался");
        }

        /* ФОРМА НЕ ПОНИЖАЕТСЯ. Синхронизация каталога может прийти ПОСЛЕ
           испытания, и порядок команд не должен решать, к каким приветствиям
           применяется план. */
        CHECK(d2k_plantab_set_name_shaped(t, nm, nl, 5, mkplan(),
                                          D2K_PLAN_SHAPE_GRANDFATHER) == 0,
              "перезапись плана не прошла");
        CHECK(d2k_plantab_find(t, nm, nl, 0, 6, D2K_PLAN_SHAPE_LEGACY) == NULL,
              "измеренная форма понижена до дедушкиного права порядком команд");

        d2k_plantab_free(t);
        t = d2k_plantab_new(4);
        CHECK(t != NULL, "таблица для дедушкиного права не создалась");

        /* СТАРАЯ ЗАПИСЬ (формы не записывали) применяется ко всем формам.
           Это весь каталог, заведённый до появления поля: в снятом с роутера
           состоянии формы нет ни у одной записи, и отказать значило бы молча
           выключить работающий у человека обход. */
        CHECK(d2k_plantab_set_name(t, nm, nl, 5, mkplan()) == 0,
              "план без объявленной формы не поставился");
        CHECK(d2k_plantab_find(t, nm, nl, 0, 6, D2K_PLAN_SHAPE_MODERN) != NULL &&
              d2k_plantab_find(t, nm, nl, 0, 7, D2K_PLAN_SHAPE_LEGACY) != NULL &&
              d2k_plantab_find(t, nm, nl, 0, 8, D2K_PLAN_SHAPE_QUIC) != NULL &&
              d2k_plantab_find(t, nm, nl, 0, 9, D2K_PLAN_SHAPE_ANY) != NULL,
              "старый каталог перестал применяться — «не записано» принято за «не подходит»");
        d2k_plantab_free(t);
    }

    /* --- ПРОБНАЯ ЗАПИСЬ ДОСТАЁТСЯ ТОЛЬКО СВОЕМУ ПОТОКУ --------------------
     *
     * Испытывает кандидата зонд, а платил за испытание пользователь: план
     * вставал по ИМЕНИ и доставался всем, кто шёл к этой цели. На роутере
     * владельца 13.09.2026 поиск по i.ytimg.com шёл двадцать одну минуту, и
     * всё это время цель работала через раз. */
    {
        d2k_plantab *t = d2k_plantab_new(8);
        CHECK(t != NULL, "таблица не создалась");
        if (t) {
            d2k_plan *probe_plan = mkplan();
            d2k_plan *common = mkplan();
            const uint8_t nm[] = "i.ytimg.com";
            const size_t nl = sizeof nm - 1;
            const uint16_t sport = 0x3412;   /* сетевой порядок, значение неважно */

            CHECK(d2k_plantab_set_name_probe(t, nm, nl, 1, probe_plan,
                                             D2K_PLAN_SHAPE_MODERN, sport) == 0,
                  "пробная запись не встала");

            /* Свой поток — получает. */
            CHECK(d2k_plantab_find_sport(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_MODERN, sport)
                      == probe_plan,
                  "поток зонда не получил пробный план");
            CHECK(d2k_plantab_find_sport(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_ANY, sport)
                      == probe_plan,
                  "точный поток зонда потерял временный план из-за неполного ClientHello");
            CHECK(d2k_plantab_find_sport(t, NULL, 0, 0, 2, D2K_PLAN_SHAPE_MODERN, sport)
                      == probe_plan,
                  "зонд без собранного SNI потерял свой план по порту");
            const uint8_t other[] = "other.example";
            d2k_plan *next_probe = mkplan();
            CHECK(d2k_plantab_set_name_probe(t, other, sizeof other - 1, 2, next_probe,
                                             D2K_PLAN_SHAPE_MODERN, sport) == 0,
                  "второй тестовый план не поставился");
            CHECK(d2k_plantab_find_sport(t, NULL, 0, 0, 2, D2K_PLAN_SHAPE_MODERN, sport)
                      == next_probe,
                  "переиспользованный порт не перешёл новому владельцу");
            /* Чужой поток — НЕ получает: для него этой записи нет вовсе. */
            CHECK(d2k_plantab_find_sport(t, nm, nl, 0, 3, D2K_PLAN_SHAPE_MODERN, 0x9988)
                      == NULL,
                  "чужой поток получил пробный план — испытание за счёт пользователя");
            /* И тот, кто про порты не знает, тоже не получает. */
            CHECK(d2k_plantab_find(t, nm, nl, 0, 4, D2K_PLAN_SHAPE_MODERN) == NULL,
                  "пробная запись досталась вызову без порта");

            /* Подтверждённый план ставится БЕЗ порта и достаётся всем,
               пробная запись при этом ему не мешает. */
            CHECK(d2k_plantab_set_name_shaped(t, nm, nl, 5, common,
                                              D2K_PLAN_SHAPE_MODERN) == 0,
                  "подтверждённый план не встал рядом с пробным");
            CHECK(d2k_plantab_find(t, nm, nl, 0, 6, D2K_PLAN_SHAPE_MODERN) == common,
                  "подтверждённый план не достался общему потоку");
            CHECK(d2k_plantab_find_sport(t, nm, nl, 0, 7, D2K_PLAN_SHAPE_MODERN, 0x9988)
                      == common,
                  "чужой поток не получил подтверждённый план");
            /* The old name no longer owns this probe port. Its confirmed
               strategy remains usable, but its retired trial cannot return. */
            CHECK(d2k_plantab_find_sport(t, nm, nl, 0, 8, D2K_PLAN_SHAPE_MODERN, sport)
                      == common,
                  "старый владелец порта получил уже снятый пробный план");
            d2k_plantab_free(t);
        }
    }

    /* Временная адресная проба совпадает по ПОЛНОМУ QUIC flow и поколению;
       постоянный Plan по IP не заменяется и переживает любое probe cleanup. */
    {
        d2k_plantab *t = d2k_plantab_new(4);
        d2k_addr_probe_flow f = {
            .src_ip4 = {192, 0, 2, 10}, .src_port_be = 0x3412,
            .dst_ip4 = {203, 0, 113, 7}, .dst_port_be = 0xbb01,
            .transport = 17
        };
        d2k_addr_probe_flow other = f;
        uint8_t trial1[D2K_TRIAL_ID_LEN] = {1};
        uint8_t trial2[D2K_TRIAL_ID_LEN] = {2};
        uint8_t seen[D2K_TRIAL_ID_LEN] = {0};
        d2k_plan *persistent = mkplan();
        d2k_plan *probe = mkplan();
        CHECK(d2k_plantab_set_addr(t, addr(203, 0, 113, 7), 1, persistent) == 0,
              "persistent address plan setup failed");
        CHECK(d2k_plantab_set_addr_probe(t, &f, trial1, 10, 1000, probe) == 0,
              "exact-flow probe plan setup failed");
        CHECK(d2k_plantab_probe_count(t) == 1,
              "temporary probe was not counted separately");
        CHECK(d2k_plantab_find_addr_probe(t, &f, 11, seen) == probe &&
              memcmp(seen, trial1, sizeof seen) == 0,
              "exact QUIC verifier flow did not receive its probe and generation");

        other.src_ip4[3]++;
        CHECK(d2k_plantab_find_addr_probe(t, &other, 12, NULL) == NULL,
              "same source port from another local IP received the probe");
        other = f; other.src_port_be++;
        CHECK(d2k_plantab_find_addr_probe(t, &other, 12, NULL) == NULL,
              "another source port received the probe");
        other = f; other.dst_port_be++;
        CHECK(d2k_plantab_find_addr_probe(t, &other, 12, NULL) == NULL,
              "another destination port received the probe");
        other = f; other.transport = 6;
        CHECK(d2k_plantab_find_addr_probe(t, &other, 12, NULL) == NULL,
              "TCP flow received a QUIC probe");

        CHECK(d2k_plantab_set_addr_probe(t, &f, trial2, 13, 1000, mkplan()) == -3,
              "a concurrent generation silently replaced the same exact flow");
        CHECK(d2k_plantab_del_addr_probe(t, &f, trial2) == 0 &&
              d2k_plantab_find_addr_probe(t, &f, 14, seen) == probe &&
              memcmp(seen, trial1, sizeof seen) == 0,
              "stale-generation delete removed the active probe");

        other = f; other.src_port_be++;
        CHECK(d2k_plantab_set_addr_probe(t, &other, trial2, 15, 1000, mkplan()) == 0 &&
              d2k_plantab_probe_count(t) == 2,
              "independent flow to the same destination could not own a probe");
        CHECK(d2k_plantab_find_addr_probe(t, &f, 1000, NULL) == NULL &&
              d2k_plantab_probe_count(t) == 0,
              "expired address probes remained eligible");
        CHECK(d2k_plantab_find(t, NULL, 0, addr(203, 0, 113, 7), 1001,
                               D2K_PLAN_SHAPE_QUIC) == persistent &&
              d2k_plantab_count(t) == 1,
              "probe expiry altered the permanent address Plan");
        d2k_plantab_free(t);
    }

    /* --- адресная привязка различает протокол (задача 16, §5) ---------------
     * Один IP может нести и QUIC, и STUN/голос. Подтверждённый на одном
     * протоколе план не должен ни затирать подтверждённый на другом, ни
     * применяться к его пакетам. */
    {
        d2k_plantab *t = d2k_plantab_new(8);
        uint32_t ip = addr(198, 51, 100, 9);
        const uint8_t voice[] = D2K_VOICE_CLASS;
        d2k_plan *quic = mkplan(), *stun = mkplan();
        CHECK(d2k_plantab_set_addr_shaped(t, (const uint8_t *)&ip, 4, 1, quic,
                                          D2K_PLAN_SHAPE_QUIC) == 0,
              "QUIC address binding not installed");
        CHECK(d2k_plantab_set_addr_shaped(t, (const uint8_t *)&ip, 4, 2, stun,
                                          D2K_PLAN_SHAPE_VOICE) == 0,
              "voice address binding not installed");
        CHECK(d2k_plantab_count(t) == 2, "voice address binding replaced the QUIC one");
        CHECK(d2k_plantab_find(t, NULL, 0, ip, 3, D2K_PLAN_SHAPE_QUIC) == quic,
              "QUIC Initial to the IP did not get the QUIC plan");
        CHECK(d2k_plantab_find(t, voice, sizeof voice - 1, ip, 3,
                               D2K_PLAN_SHAPE_VOICE) == stun,
              "STUN/voice request to the IP did not get the voice plan");
        size_t misses = d2k_plantab_shape_misses(t);
        CHECK(d2k_plantab_find(t, NULL, 0, ip, 3, D2K_PLAN_SHAPE_MODERN) == NULL &&
              d2k_plantab_find(t, NULL, 0, ip, 3, D2K_PLAN_SHAPE_ANY) == NULL,
              "UDP address binding applied to a TCP/unknown hello");
        CHECK(d2k_plantab_shape_misses(t) == misses + 2,
              "known address with another protocol not counted as shape miss");
        CHECK(d2k_plantab_set_addr_shaped(t, (const uint8_t *)&ip, 4, 4, NULL,
                                          D2K_PLAN_SHAPE_ANY) == -2,
              "address binding without protocol shape accepted");
        d2k_plan *quic2 = mkplan();
        CHECK(d2k_plantab_set_addr_shaped(t, (const uint8_t *)&ip, 4, 5, quic2,
                                          D2K_PLAN_SHAPE_QUIC) == 0 &&
              d2k_plantab_count(t) == 2 &&
              d2k_plantab_find(t, NULL, 0, ip, 6, D2K_PLAN_SHAPE_QUIC) == quic2 &&
              d2k_plantab_find(t, voice, sizeof voice - 1, ip, 6,
                               D2K_PLAN_SHAPE_VOICE) == stun,
              "same-shape replacement touched the other protocol");
        CHECK(d2k_plantab_del_addr_shaped(t, (const uint8_t *)&ip, 4,
                                          D2K_PLAN_SHAPE_VOICE) == 1,
              "voice address binding not removed");
        CHECK(d2k_plantab_find(t, NULL, 0, ip, 7, D2K_PLAN_SHAPE_QUIC) == quic2 &&
              d2k_plantab_find(t, voice, sizeof voice - 1, ip, 7,
                               D2K_PLAN_SHAPE_VOICE) == NULL &&
              d2k_plantab_count(t) == 1,
              "removing the voice address binding touched the QUIC one");
        CHECK(d2k_plantab_del_addr_shaped(t, (const uint8_t *)&ip, 4,
                                          D2K_PLAN_SHAPE_VOICE) == 0,
              "repeated shaped delete found something");
        d2k_plantab_free(t);
    }

    /* ЗАДАЧА 21: снятие по имени — ровно (имя, транспорт, форма, семейство)
       ПОСТОЯННОЙ записи. Прямой проход TCP не снимает ни пробу параллельной
       QUIC-задачи того же имени, ни пробу TCP той же формы, ни подтверждённое
       другой формы (TLS 1.2, ECH) или другого транспорта (QUIC). */
    {
        d2k_plantab *t = d2k_plantab_new(16);
        const uint8_t nm[] = "same.example";
        size_t nl = sizeof nm - 1;
        d2k_plan *modern = mkplan(), *legacy = mkplan(), *ech = mkplan(),
                 *quic = mkplan(), *quic_probe = mkplan(), *tcp_probe = mkplan(),
                 *v6 = mkplan();
        CHECK(d2k_plantab_set_name_family(t, nm, nl, 1, modern, D2K_PLAN_SHAPE_MODERN, 0, 4) == 0 &&
              d2k_plantab_set_name_family(t, nm, nl, 1, legacy, D2K_PLAN_SHAPE_LEGACY, 0, 4) == 0 &&
              d2k_plantab_set_name_family(t, nm, nl, 1, ech, D2K_PLAN_SHAPE_ECH_TCP, 0, 4) == 0 &&
              d2k_plantab_set_name_family(t, nm, nl, 1, quic, D2K_PLAN_SHAPE_QUIC, 0, 4) == 0 &&
              d2k_plantab_set_name_family(t, nm, nl, 1, quic_probe, D2K_PLAN_SHAPE_QUIC, 0x3412, 4) == 0 &&
              d2k_plantab_set_name_family(t, nm, nl, 1, tcp_probe, D2K_PLAN_SHAPE_MODERN, 0x5612, 4) == 0 &&
              d2k_plantab_set_name_family(t, nm, nl, 1, v6, D2K_PLAN_SHAPE_MODERN, 0, 6) == 0 &&
              d2k_plantab_count(t) == 7, "scoped delete fixture");
        CHECK(d2k_plantab_del_name_shaped(t, nm, nl, 6, D2K_PLAN_SHAPE_MODERN, 4) == 1,
              "scoped delete did not remove the permanent TCP/TLS1.3 entry");
        CHECK(d2k_plantab_count(t) == 6, "scoped delete removed more than one entry");
        CHECK(d2k_plantab_find_family(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_MODERN, 0, 4) == NULL,
              "permanent TLS1.3 entry still applies after scoped delete");
        CHECK(d2k_plantab_find_family(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_QUIC, 0x3412, 4) == quic_probe,
              "TCP delete removed a parallel QUIC trial of the same name");
        CHECK(d2k_plantab_find_family(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_MODERN, 0x5612, 4) == tcp_probe,
              "permanent delete removed an exact-flow TCP trial");
        CHECK(d2k_plantab_find_family(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_LEGACY, 0, 4) == legacy,
              "TLS1.3 delete removed the TLS1.2 binding");
        CHECK(d2k_plantab_find_family(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_ECH_TCP, 0, 4) == ech,
              "TLS1.3 delete removed the ECH binding");
        CHECK(d2k_plantab_find_family(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_QUIC, 0, 4) == quic,
              "TCP delete removed the permanent QUIC binding");
        CHECK(d2k_plantab_find_family(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_MODERN, 0, 6) == v6,
              "IPv4 delete removed the IPv6 binding");
        CHECK(d2k_plantab_del_name_shaped(t, nm, nl, 17, D2K_PLAN_SHAPE_MODERN, 4) == 0,
              "transport mismatch still deleted something");
        CHECK(d2k_plantab_del_name_shaped(t, nm, nl, 6, D2K_PLAN_SHAPE_QUIC, 4) == 0,
              "TCP delete with QUIC shape matched the QUIC entry");
        CHECK(d2k_plantab_del_name_shaped(t, nm, nl, 17, D2K_PLAN_SHAPE_QUIC, 4) == 1 &&
              d2k_plantab_find_family(t, nm, nl, 0, 2, D2K_PLAN_SHAPE_QUIC, 0x3412, 4) == quic_probe,
              "QUIC permanent delete must spare the QUIC trial");
        CHECK(d2k_plantab_del_name_shaped(t, nm, nl, 6, D2K_PLAN_SHAPE_ANY, 4) == 0 &&
              d2k_plantab_count(t) == 5, "shape ANY is not a wildcard delete");
        d2k_plantab_free(t);
    }

    /* Same serialized program, new installation: delayed evidence must not
       identify it as the previous binding. Lookup/LRU and unrelated SETs do
       not change the saved identity. Exercise each installation namespace. */
    for (int kind = D2K_BIND_NAME; kind <= D2K_BIND_FLOW; kind++) {
        for (uint8_t family = 4; family <= 6; family += 2) {
            d2k_plantab *t = d2k_plantab_new(4), *other = d2k_plantab_new(4);
            const uint8_t nm[] = "identity.test", ip[16] = {1,2,3,4};
            const uint8_t trial[16] = {1};
            d2k_addr_probe_flow f = {0};
            f.family = family; f.transport = 17;
            memcpy(f.src_ip4, ip, 4); memcpy(f.dst_ip4, ip, 4);
            memcpy(f.src_ip6, ip, 16); memcpy(f.dst_ip6, ip, 16);
            f.src_port_be = 1234; f.dst_port_be = 443;
            d2k_binding_context saved = {0};
            for (int install = 0; install < 2; install++) {
                d2k_plan *p = kind == D2K_BIND_FLOW ? mkdeny() : mkplan(); int rc;
                if (kind == D2K_BIND_NAME)
                    rc = d2k_plantab_set_name_family(t,nm,sizeof nm-1,1,p,D2K_PLAN_SHAPE_MODERN,0,family);
                else if (kind == D2K_BIND_ADDR)
                    rc = d2k_plantab_set_addr_shaped(t,ip,family,1,p,D2K_PLAN_SHAPE_MODERN);
                else if (kind == D2K_BIND_SUFFIX)
                    rc = d2k_plantab_set_suffix_family(t,nm,sizeof nm-1,1,p,D2K_PLAN_SHAPE_MODERN,family);
                else rc = d2k_plantab_set_addr_probe(t,&f,trial,1,100,p);
                CHECK(rc == 0, "binding generation fixture install");
                d2k_binding_context c = {0}, again = {0};
                CHECK(d2k_plantab_binding(t,p,&c) && c.generation && c.kind == kind &&
                      c.family == family && c.shape == (kind == D2K_BIND_FLOW ? D2K_PLAN_SHAPE_QUIC : D2K_PLAN_SHAPE_MODERN) &&
                      c.temporary == (kind == D2K_BIND_FLOW), "installed binding context missing");
                CHECK(!install || c.generation != saved.generation, "same-hash reinstall reused generation");
                saved = c;
                CHECK(!d2k_plantab_set_name_family(t,(const uint8_t *)"other.test",10,2,mkplan(),
                      D2K_PLAN_SHAPE_MODERN,0,family), "unrelated install");
                CHECK(d2k_plantab_binding(t,p,&again) && again.generation == c.generation,
                      "unrelated table change altered this binding generation");
                CHECK(!d2k_plantab_binding(other,p,&again) && !again.generation,
                      "foreign table accepted binding identity");
            }
            d2k_plantab_free(t); d2k_plantab_free(other);
        }
    }

    /* Регрессионный тест (Claude review rx12, п. 2):
       Имя с QUIC-записью, на адресе — TCP-план другого имени (соседа по CDN).
       TCP-поток к имени с QUIC-планом НЕ ДОЛЖЕН получать TCP-план адреса!
       QUIC-поток к имени находит свой QUIC-план имени.
       QUIC-поток к имени с TCP-планом (например, ECH QUIC) находит QUIC-план адреса. */
    {
        d2k_plantab *t = d2k_plantab_new(8);
        uint32_t ip = addr(104, 21, 50, 1);
        const uint8_t name_quic[] = "quiconly.example";
        size_t nq_len = sizeof name_quic - 1;
        d2k_plan *p_name_quic = mkplan();
        d2k_plan *p_addr_tcp = mkplan();

        CHECK(d2k_plantab_set_name_family(t, name_quic, nq_len, 1, p_name_quic,
                                          D2K_PLAN_SHAPE_QUIC, 0, 4) == 0,
              "не удалось установить QUIC-план имени");
        CHECK(d2k_plantab_set_addr_shaped(t, (const uint8_t *)&ip, 4, 2, p_addr_tcp,
                                          D2K_PLAN_SHAPE_MODERN) == 0,
              "не удалось установить TCP-план адреса");

        /* 1. QUIC поток к name_quic находит p_name_quic */
        CHECK(d2k_plantab_find_target(t, name_quic, nq_len, (const uint8_t *)&ip, 4,
                                      10, D2K_PLAN_SHAPE_QUIC, 0) == p_name_quic,
              "QUIC-поток не нашёл QUIC-план имени");

        /* 2. TCP поток к name_quic НЕ должен подхватить TCP-план соседа по CDN с адреса */
        CHECK(d2k_plantab_find_target(t, name_quic, nq_len, (const uint8_t *)&ip, 4,
                                      11, D2K_PLAN_SHAPE_MODERN, 0) == NULL,
              "TCP-поток к QUIC-имени унаследовал соседний CDN TCP-план адреса");

        /* 3. Безымянный TCP поток к адресу получает p_addr_tcp */
        CHECK(d2k_plantab_find_target(t, NULL, 0, (const uint8_t *)&ip, 4,
                                      12, D2K_PLAN_SHAPE_MODERN, 0) == p_addr_tcp,
              "безымянный TCP-поток не нашёл TCP-план адреса");

        /* 4. Имя с TCP-планом (например, домен с ECH): QUIC-поток находит QUIC-план адреса */
        const uint8_t name_tcp[] = "tcponly.example";
        size_t nt_len = sizeof name_tcp - 1;
        d2k_plan *p_name_tcp = mkplan();
        d2k_plan *p_addr_quic = mkplan();
        CHECK(d2k_plantab_set_name_family(t, name_tcp, nt_len, 3, p_name_tcp,
                                          D2K_PLAN_SHAPE_MODERN, 0, 4) == 0,
              "не удалось установить TCP-план имени");
        CHECK(d2k_plantab_set_addr_shaped(t, (const uint8_t *)&ip, 4, 4, p_addr_quic,
                                          D2K_PLAN_SHAPE_QUIC) == 0,
              "не удалось установить QUIC-план адреса");

        CHECK(d2k_plantab_find_target(t, name_tcp, nt_len, (const uint8_t *)&ip, 4,
                                      13, D2K_PLAN_SHAPE_QUIC, 0) == p_addr_quic,
              "QUIC-поток к TCP-имени не перешёл к QUIC-плану адреса");

        d2k_plantab_free(t);
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("планы целей: все проверки прошли\n");
    return 0;
}
