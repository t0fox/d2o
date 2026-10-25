/* d2k_sched.h — планировщик поисков: один на оба транспорта.
 *
 * ЧТО ЭТО. Датапат (d2kd) видит пакеты и применяет планы; он ничего не
 * подбирает. Подбирает планировщик: получает от датапата подозрение
 * (D2K_EV_SUSPECT), заводит по цели задачу, ведёт её до плана, который даёт
 * прикладной обмен, и кладёт найденное в каталог. До этого модуля ту же работу
 * делала Go-сторона (internal/controller); этот модуль её заменяет, и заменяет
 * ЦЕЛИКОМ на обоих транспортах сразу — в этом смысл задачи 5 плана
 * docs/superpowers/plans/2026-09-07-engine-c-both-transports.md.
 *
 * РАЗВИЛКА ПО ТРАНСПОРТУ — ГЛАВНЫЙ ШОВ. Подозрение по TCP идёт в дерево
 * вердиктов (d2k_classify, d2k_verdict.h), подозрение по UDP — в вопросник
 * QUIC (d2k_quic_classify, d2k_quicprobe.h). Это РАЗНЫЕ механизмы, а не один с
 * параметром: TCP-дерево стоит на разрезе потока, которого в QUIC нет вовсе
 * (см. большой комментарий в шапке d2k_quicprobe.h). Обе ветки кладут привязку
 * в ОДИН каталог с заполненным transport — без него привязки двух транспортов
 * к одной цели легли бы под один ключ и перетёрли друг друга (d2k_catalog.h,
 * разбор про d2k_cat_binding.transport).
 *
 * ЦИКЛ НЕ БЛОКИРУЕТСЯ НИКОГДА. Управляющее подключение к датапату ровно одно
 * (d2k_ctl.h: «Ровно одно подключение… не является сервером общего
 * пользования», datapath/ctl.c: listen(lfd, 1)), поэтому «поток на поиск со
 * своей связью» невозможен физически. Go-сторона решила это так же и написала
 * почему (internal/controller/controller.go, комментарий у Run): «зонд уходит в
 * сеть и отвечает секундами позже, а цикл событий останавливать на это время
 * нельзя — датапат за секунду присылает сотни наблюдений». Отсюда разделение:
 *
 *   - сетевые оракулы (d2k_classify, d2k_quic_classify) — блокирующие, секунды,
 *     со СВОИМИ сокетами; управляющего сокета не касаются вовсе и потому
 *     уезжают в рабочие потоки, результат возвращается в цикл;
 *   - вопросы о свойствах коробки — НЕ сетевой оракул: они ставят план
 *     командой и ждут события обмена, то есть читают то самое единственное
 *     подключение. Их двигает сам цикл, шагами, по приходящим событиям
 *     (d2k_props_question_plan/d2k_props_question_passed,
 *     d2k_compose_internal.h — смысл вопроса живёт в одном месте на обоих
 *     двигателей).
 *
 * ОТРИЦАТЕЛЬНОЕ НЕ СОХРАНЯЕТСЯ (§10/§13). Неудачный поиск не оставляет в
 * каталоге ничего: ни цели, ни коробки, ни «пробовали и не вышло». Это
 * проверяется тестом отдельно, а не подразумевается.
 *
 * КАНДИДАТА ИСПЫТЫВАЕТ САМ ПЛАНИРОВЩИК. Поставленный план не ждёт, пока цель
 * откроет человек: задача идёт к цели собственным зондом (d2k_verify.h),
 * который ведёт СВОЁ рукопожатие TLS 1.3 и разбирает ответ приложения. Успех
 * засчитывается только при совпадении двух вещей — прикладной ответ зонду И
 * событие применения ЭТОГО плана по ключу ЕГО потока. Внешний тип записи 23 в
 * чужом обмене успехом больше не считается вовсе: в TLS 1.3 им едет и второй
 * полёт рукопожатия (RFC 8446 §5.2). Подробности — в шапке sched.c.
 */
#ifndef D2K_SCHED_H
#define D2K_SCHED_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>

#include "d2k_catalog.h"
#include "d2k_link.h"
#include "d2k_verdict.h"
#include "d2k_quicprobe.h"
#include "d2k_verify.h"
#include "d2k_volume.h"
#include "d2k_voice.h"

#include "d2k_diagnostics.h"
typedef struct d2k_sched d2k_sched;
void d2k_sched_diagnostics(d2k_sched *,d2k_diag_observer,void *);
void d2k_sched_diagnostic_counts(d2k_sched *,d2k_diag_counts *);
d2k_vres d2k_sched_ech_baseline_result(const d2k_ver_result *baseline,
    d2k_vol_result *volume, const char *origin);

/* Точки подмены сетевых оракулов — тот же приём, что d2k_mark_hook
 * (d2k_meas.h) и по той же причине: тест обязан утверждать развилку по
 * транспорту, не выходя в сеть и не завися от того, что сегодня отвечает
 * настоящий instagram.com. По умолчанию указывают на настоящие d2k_classify и
 * d2k_quic_classify. */
/* stop — ПРОСЬБА БРОСИТЬ, взводится циклом, читается измерителем.
 *
 * Без неё цикл вставал целиком. task_fail и task_done зовут pthread_join
 * безусловно, и когда у задачи истекал срок при живом замере, главный поток
 * ждал окончания сетевого оракула: один зонд до шести секунд, полный перебор
 * — десятки минут. Всё это время контроллер не читал событий датапата, не
 * тикал и не выходил по сигналу (стенд транзита 17.09 повис ровно так).
 *
 * Флаг СВОЙ У КАЖДОЙ ЗАДАЧИ, а не один на всех: срок истекает у одной, а
 * бросать чужой замер — это терять чужую работу. Взводится он и на остановке
 * службы, но это частный случай, а не назначение.
 *
 * Измеритель, который отмену не умеет, просто не читает указатель — и тогда
 * join честно ждёт его столько, сколько тот идёт. Оба случая видны в коде, ни
 * один не притворяется другим. */
typedef d2k_vres (*d2k_sched_tcp_fn)(const char *ip, uint16_t port,
                                     d2k_hello trigger, d2k_hello control,
                                     uint32_t mark, int repeats,
                                     uint32_t gap_us, uint32_t wait_ms,
                                     const volatile sig_atomic_t *stop);
typedef d2k_vres (*d2k_sched_quic_fn)(const char *ip, uint16_t port, const char *sni,
                                      d2k_hello trigger, d2k_hello control,
                                      uint32_t mark, d2k_quic_arm *arm);
/* Проба на блокировку по объёму. Отдельным крючком по той же причине, что и
 * два оракула выше: тест обязан утверждать поведение планировщика, не выходя
 * в сеть. */
typedef d2k_vol_result (*d2k_sched_vol_fn)(const char *ip, uint16_t port,
                                           const char *sni, int plain, int tls12,
                                           size_t hello_wire, uint32_t mark);
extern d2k_sched_vol_fn  d2k_sched_vol_hook;
typedef d2k_vol_result (*d2k_sched_vol_path_fn)(const char *, uint16_t,
    const char *, int, int, size_t, uint32_t, const char *);
extern d2k_sched_vol_path_fn d2k_sched_vol_path_hook;

/* ЗАНЯТЬ ПОРТ ДЛЯ ОПЫТА. Крючок, а не прямой вызов, по той же причине, что и
 * у сетевых оракулов: отказ bind обязан быть ВОСПРОИЗВОДИМ в тесте. Именно на
 * этом отказе d2k раньше переходил к общему пробному плану и бил по чужим
 * соединениям (0010, R1).
 *
 * transport — 6 или 17: тип сокета задаётся при создании. 0 — занято,
 * отрицательное — локальный отказ. */
typedef int (*d2k_sched_bind_fn)(uint8_t transport, uint8_t family, int *out_fd, uint16_t *sport_be);
extern d2k_sched_bind_fn d2k_sched_bind_hook;

/* Separate from the global measurement mark hook: scheduler tests replace
 * only verifier-socket marking and must not alter unrelated measurement or
 * voice fixtures. */
typedef int (*d2k_sched_mark_fn)(int fd, uint32_t mark);
extern d2k_sched_mark_fn d2k_sched_mark_hook;

/* Зонд подтверждения (d2k_verify.h). Крючок нужен по той же причине, что и
 * три выше, и ещё по одной: этот зонд ведёт НАСТОЯЩЕЕ рукопожатие TLS 1.3 с
 * настоящим сервером, и модульный тест обязан утверждать, что планировщик
 * испытывает кандидата САМ, не выходя в сеть вовсе.
 *
 * transport (6 TCP, 17 UDP) передаётся зонду, потому что доказательство
 * принадлежит транспорту: подтвердить план QUIC обращением по TCP значило бы
 * записать успех ДРУГОГО транспорта. Умолчание (verify_default, sched.c) на
 * не-TCP честно отвечает «не измерено»: своего зонда для QUIC сегодня нет.
 *
 * hello_wire — длина приветствия, снятого С КЛИЕНТА этой цели: зонд добивает
 * своё до неё, иначе измерение идёт в другом контексте, чем работа человека
 * (седьмая находка лаборатории 13.09.2026). */
/* use_fd — УЖЕ ЗАНЯТЫЙ сокет зонда, под чей местный порт поставлен пробный
 * план (d2k_props_bind + d2k_link_set_name_probe). Меньше нуля — сокета нет,
 * зонд заводит свой; владение сокетом переходит вызываемому. */
/* client_shape — форма приветствия КЛИЕНТА, из-за которого идёт поиск
 * (d2k_shape). По ней выбирается протокол подтверждения: старому клиенту
 * (TLS 1.2) современное рукопожатие не годится — план записался бы под форму,
 * которой у него нет, и по ключу формы он его не получил бы вовсе
 * (MVP_CHECKLIST, пункт 3). */
typedef d2k_ver_result (*d2k_sched_ver_fn)(int use_fd, const char *ip, uint16_t port,
                                           uint8_t transport, const char *sni,
                                           int deadline_ms, size_t hello_wire,
                                           uint8_t client_shape);
extern d2k_sched_ver_fn  d2k_sched_ver_hook;
extern d2k_sched_ver_fn  d2k_sched_rx_ver_hook;
extern d2k_sched_ver_fn  d2k_sched_rx_gzip_ver_hook;
/* Зонд с ALPN КЛИЕНТА для не-HTTP протокола (задача 37, F3): по умолчанию
 * d2k_verify_probe_alpn_on. Зовётся вместо остальных TCP-зондов, когда снимок
 * клиента — TLS 1.3 с ЯВНЫМ не-HTTP ALPN, а замер доказал блок самого
 * рукопожатия без обрыва объёма (см. client_alpn_nonhttp в sched.c). */
typedef d2k_ver_result (*d2k_sched_alpn_ver_fn)(int use_fd, const char *ip, uint16_t port,
                                                const char *sni, int deadline_ms,
                                                size_t hello_wire,
                                                const uint8_t *alpn_list, size_t alpn_len);
extern d2k_sched_alpn_ver_fn d2k_sched_alpn_ver_hook;
typedef d2k_ver_result (*d2k_sched_path_ver_fn)(int, const char *, uint16_t,
    const char *, int, size_t, int, int, uint32_t, const char *);
extern d2k_sched_path_ver_fn d2k_sched_path_ver_hook;
/* QUIC-проверка плана по известному большому ресурсу (задача 39, раунд 1). */
typedef d2k_ver_result (*d2k_sched_quic_path_ver_fn)(int, const char *, uint16_t,
    const char *, int, size_t, const char *);
extern d2k_sched_quic_path_ver_fn d2k_sched_quic_path_ver_hook;

extern d2k_sched_tcp_fn  d2k_sched_tcp_hook;
extern d2k_sched_quic_fn d2k_sched_quic_hook;
/* БАЗОВЫЙ ВОПРОС ДОНОРА ОТДЕЛЬНО (задача 32): только первый вопрос «Поиска по
 * домену» — триггер целиком, одной записью, столько же повторов. Ответ —
 * d2k_vres.base_blocked. По нему планировщик решает, пробовать ли сначала
 * СВОИ подтверждённые планы той же формы (ТЗ §3.4), прежде чем продолжить
 * полный прогон, который затем идёт ровно как прежде. NULL (умолчание) — шага
 * нет: прежнее дерево (core/verdict.c) базового вопроса отдельно не умеет. */
extern d2k_sched_tcp_fn  d2k_sched_tcp_base_hook;
/* Полный прогон, берущий ответ уже заданного базового вопроса (seed — тот же
 * вход) вместо повторного опроса. NULL — прогон спрашивает базу сам. */
typedef d2k_vres (*d2k_sched_tcp_seeded_fn)(const char *ip, uint16_t port,
                                            d2k_hello trigger, d2k_hello control,
                                            uint32_t mark, int repeats,
                                            uint32_t gap_us, uint32_t wait_ms,
                                            const volatile sig_atomic_t *stop,
                                            const d2k_base_seed *seed);
extern d2k_sched_tcp_seeded_fn d2k_sched_tcp_seeded_hook;
/* ПОЛНЫЙ ПРОГОН С БЕЛЫМ ИМЕНЕМ СЕТИ ПРИМАНКОЙ (поле 10.10.2026). Тот же
 * прогон, что d2k_sched_tcp_hook, плюс белое имя сети (целый ClientHello) для
 * вопроса «приветствие под меткой времени»: имя — из каталога, не из контроля,
 * а сигнатуру основного крючка менять нельзя, поэтому отдельный крючок.
 * NULL — имя не известно, зовётся обычный крючок (вопрос не задаётся). */
typedef d2k_vres (*d2k_sched_tcp_white_fn)(const char *ip, uint16_t port,
                                           d2k_hello trigger, d2k_hello control,
                                           d2k_hello white, uint32_t mark, int repeats,
                                           uint32_t gap_us, uint32_t wait_ms,
                                           const volatile sig_atomic_t *stop);
extern d2k_sched_tcp_white_fn d2k_sched_tcp_white_hook;
/* ПОЛНЫЙ ПРОГОН С ОТВЕТОМ БАЗЫ И ECH-ПРИМАНКОЙ (поле 10.10.2026). У целей
 * семейства C профильный замер ловит ClientHello клиента и идёт SEEDED
 * (снятыми байтами), а seeded-крючок приманки не нёс — составной ECH-вопрос
 * не задавался. Этот крючок несёт И ответ базы (seed), И ECH-приманку, чтобы
 * вопрос задавался и на seeded-пути. NULL — зовётся обычный seeded-крючок. */
typedef d2k_vres (*d2k_sched_tcp_seeded_white_fn)(const char *ip, uint16_t port,
                                                  d2k_hello trigger, d2k_hello control,
                                                  d2k_hello white, uint32_t mark, int repeats,
                                                  uint32_t gap_us, uint32_t wait_ms,
                                                  const volatile sig_atomic_t *stop,
                                                  const d2k_base_seed *seed);
extern d2k_sched_tcp_seeded_white_fn d2k_sched_tcp_seeded_white_hook;
/* ПРИНИМАЕТ ЛИ АДРЕС ДАННЫЕ (задача 54, fix round 1 I2). Перепроверка
 * адреса, у которого есть вердикт address, начинается с этого вопроса ДО
 * любого зонда с триггером: один нейтральный байт, ожидание подтверждения TCP
 * сервера (d2k_probe_data_ack), до первого подтверждения из трёх.
 * Возврат: 1 — подтверждён; 0 — тишина на всех повторах; <0 — не измерено.
 * probes — сколько соединений стоил вопрос. NULL — вопроса нет, перепроверка
 * идёт обычным путём. */
typedef int (*d2k_sched_tcp_ack_fn)(const char *ip, uint16_t port, uint32_t mark,
                                    const volatile sig_atomic_t *stop, int *probes);
extern d2k_sched_tcp_ack_fn d2k_sched_tcp_ack_hook;
/* То же для QUIC: базовый вопрос — контроль живости и прямой зонд нашим
 * Initial (d2k_quic_base); полный прогон с ответом — d2k_quic_run_seeded.
 * NULL (умолчание) — шага своих планов для QUIC нет, прогон как прежде. */
typedef d2k_vres (*d2k_sched_quic_base_fn)(const char *ip, uint16_t port, const char *sni,
                                           d2k_hello trigger, d2k_hello control, uint32_t mark);
extern d2k_sched_quic_base_fn d2k_sched_quic_base_hook;
typedef d2k_vres (*d2k_sched_quic_seeded_fn)(const char *ip, uint16_t port, const char *sni,
                                             d2k_hello trigger, d2k_hello control, uint32_t mark,
                                             d2k_quic_arm *arm, const d2k_base_seed *seed);
extern d2k_sched_quic_seeded_fn d2k_sched_quic_seeded_hook;

/* ХОД ИЗМЕРИТЕЛЯ (задача 48). Полный прогон дерева идёт минутами, а
 * крючки выше возвращают только итог. Измеритель, работающий в рабочем
 * потоке планировщика, сообщает сюда каждый заданный вопрос: имя (как в
 * трассе: "split", "poison:seqovl-1") и сколько зондов он стоил. Планировщик
 * отдаёт это в live.json у поиска в фазе «распознаём поведение» — "probes" и
 * "question". Вне рабочего потока планировщика (CLI, тесты измерителя)
 * вызов ничего не делает. Не влияет ни на вердикт, ни на бюджет кандидатов. */
void d2k_sched_progress_note(const char *question, int pass, int fail);

/* Голосовой измеритель блокирует на сетевых ответах и запускается
 * асинхронно; крючок позволяет проверить scheduler без сети. */
typedef d2k_voice_res (*d2k_sched_voice_fn)(const d2k_voice_opt *opt);
extern d2k_sched_voice_fn d2k_sched_voice_hook;

/* HTTPS RR с ECHConfig (умолчание d2k_ech_resolve: один UDP-запрос, ответ
 * ждётся не дольше 1,5 с). По нему поиск с ECH offer отличает настоящий ECH
 * (внешнее имя — public_name конфигурации) от GREASE (задача 41). Крючок —
 * чтобы проверять это различение без сети. */
typedef int (*d2k_sched_ech_resolve_fn)(const char *origin, uint32_t mark,
                                        d2k_ech_config *config);
extern d2k_sched_ech_resolve_fn d2k_sched_ech_resolve_hook;

/* Повтор снятого ECH-приветствия клиента под пробным планом (умолчание
 * d2k_verify_replay_on). Им подтверждается кандидат настоящего ECH, когда
 * своего свидетеля-origin нет: доказательство — ServerHello, уровень
 * рукопожатия (replay_proof). Крючок — чтобы проверять это без сети. */
typedef d2k_ver_result (*d2k_sched_replay_ver_fn)(int use_fd, const char *ip, uint16_t port,
                                                  const uint8_t *hello, size_t hello_len,
                                                  int deadline_ms);
extern d2k_sched_replay_ver_fn d2k_sched_replay_ver_hook;
/* Повтор пачки QUIC клиента (QUIC с ECH); по умолчанию d2k_verify_quic_replay_on. */
extern d2k_sched_replay_ver_fn d2k_sched_quic_replay_ver_hook;

/* Запуск рабочего потока задачи. NULL (умолчание) — поток заводится как
 * обычно; ненулевой ответ крючка изображает отказ pthread_create. Нужен,
 * чтобы провал запуска замера был воспроизводим в тесте (задача 24): именно
 * на нём перезапуск поиска снимком оставлял задачу-зомби без имени. */
typedef int (*d2k_sched_spawn_fn)(void);
extern d2k_sched_spawn_fn d2k_sched_spawn_hook;

/* Источник занятости процессора (задача 29): накопленные с загрузки тики
 * «занято» и «всего» по всем ядрам и число ядер в строю (ядра — только для
 * панели: предел от них не считается, задача 38). 0 — данные есть.
 * По умолчанию читает /proc/stat и sysconf(_SC_NPROCESSORS_ONLN); где
 * /proc/stat нет (macOS), отвечает отказом — и предел замеров остаётся
 * прежним (2). Опрашивается тиком планировщика не чаще раза в секунду
 * модельных часов, поэтому тест подменяет его без настоящего процессора. */
typedef int (*d2k_sched_cpu_fn)(uint64_t *busy, uint64_t *total, unsigned *cores);
extern d2k_sched_cpu_fn d2k_sched_cpu_hook;
/* Разбор строки «cpu ...» из /proc/stat: занято = всё, кроме idle и iowait;
 * guest уже входит в user и второй раз не считается. 0 — строка разобрана. */
int d2k_sched_cpu_parse(const char *line, uint64_t *busy, uint64_t *total);

/* Память и conntrack (задача 38) — тем же снимком и тем же приёмом, что
 * процессор. Память: MemAvailable и MemTotal из /proc/meminfo в кБ; без
 * MemAvailable (ядро старше 3.14) — отказ, оценку не выдумываем. conntrack:
 * /proc/sys/net/netfilter/nf_conntrack_count и _max; нет таблицы — отказ, и
 * conntrack предел не ограничивает. Без данных о процессоре ИЛИ памяти
 * предел замеров — прежний (2). 0 — данные есть. */
typedef int (*d2k_sched_mem_fn)(uint64_t *avail_kb, uint64_t *total_kb);
extern d2k_sched_mem_fn d2k_sched_mem_hook;
typedef int (*d2k_sched_ct_fn)(uint64_t *count, uint64_t *max);
extern d2k_sched_ct_fn d2k_sched_ct_hook;
/* Разбор текста /proc/meminfo: нужны обе строки MemTotal и MemAvailable. */
int d2k_sched_meminfo_parse(const char *text, uint64_t *avail_kb, uint64_t *total_kb);

/* Заводит планировщик поверх уже открытого каталога и уже открытой связи с
 * датапатом. Владения ни тем, ни другим НЕ берёт: каталог переживает
 * планировщик (его пишет на диск вызывающий, он же решает когда — см.
 * d2k_catalog_save), связь закрывает тот, кто открыл. */
d2k_sched *d2k_sched_new(d2k_catalog *cat, int link_fd, uint32_t mark);

/* Ставит датапату планы ВСЕХ подтверждённых привязок каталога.
 *
 * Зовётся при запуске и после каждого подтверждения — по той же причине, что
 * и Sync на Go-стороне (controller.go, дословно): «датапат состояния между
 * запусками не хранит, знание живёт в каталоге». Без этого вызова каталог
 * лежит мёртвым грузом: каждая цель после перезапуска начинала бы поиск с
 * нуля, хотя её план найден и подтверждён.
 *
 * Возвращает число поставленных планов, -1 — отказ. Отдельные негодные записи
 * (план не переводится, привязка выключена) пропускаются с сообщением через
 * d2k_sched_set_say, а не роняют весь проход: одна битая запись не повод
 * оставить датапат пустым. */
int d2k_sched_sync(d2k_sched *s);

/* Отправляет ОЧЕРЕДНУЮ порцию проходa по каталогу. Возвращает 1, если работа
 * осталась, 0 — если проход закончен или его не начинали.
 *
 * Порциями, а не залпом, по измеренной причине. Датапат держит РОВНО ОДИН
 * исходящий кадр (datapath/ctl.c, d2k_ctl_event: «Хвост прошлого кадра ещё не
 * ушёл — это событие теряется»), и пока контроллер не читает, ВСЁ, что датапат
 * хочет сказать, пропадает — включая подозрения и обмены по живому трафику
 * пользователя, а не только подтверждения наших же команд. Залп из трёхсот
 * семидесяти команд создаёт ровно такое окно слепоты. Цикл между порциями
 * читает события, и окна нет.
 *
 * Зовётся из цикла, пока не вернёт 0. d2k_sched_tick начинает новый проход
 * сам, когда его попросили изнутри (подтверждение находки). */
int d2k_sched_sync_step(d2k_sched *s);

/* Предел длины посылки, объявленный датапатом (D2K_EV_PROTO). Ноль — не
 * объявлен; тогда сборка планов ведёт себя как раньше.
 *
 * Нужен планировщику затем, что планы собирает ОН: тело фальшивки обязано и
 * покрывать то, что должно покрыть, и помещаться в канал. Второе число знает
 * только датапат. */
void d2k_sched_set_send_cap(d2k_sched *s, uint32_t cap);
/* SO_MARK диагностических вопросов. По умолчанию равен mark из конструктора;
 * отдельное значение позволяет не возвращать собственное измерение в
 * NFQUEUE, оставив probe mark только verifier выбранного плана. */
void d2k_sched_set_measure_mark(d2k_sched *s, uint32_t mark);

/* Идёт ли проход по каталогу прямо сейчас. Цикл по этому признаку не засыпает:
 * порция обязана идти сразу за чтением событий, иначе смысл порций теряется. */
int d2k_sched_sync_pending(const d2k_sched *s);

/* Разбирает ОДНО событие датапата. Возвращает 1, если поиск начат или
 * продвинут, 0 — если событие к поискам отношения не имеет (или задача по этой
 * цели уже идёт и событие ничего не меняет), -1 — отказ.
 *
 * Блокировать этот вызов нельзя: всё, что требует сети, уезжает в рабочий
 * поток (см. шапку файла). */
int d2k_sched_event(d2k_sched *s, const d2k_ev *ev);

/* Двигает задачи, которым нужно время, а не событие: истёкшие сроки,
 * вернувшиеся из рабочих потоков вердикты, отдых после неудачи. Зовётся
 * циклом по часам — ровно та же причина, по которой Go-сторона завела тикер
 * рядом с событиями (controller.go: «Счётчики ядра опрашиваются по часам, а не
 * по событиям»). Возвращает число продвинутых задач. */
int d2k_sched_tick(d2k_sched *s, int64_t now_ms);

/* Дескриптор, который цикл обязан держать в poll() рядом с link_fd: рабочий
 * поток, закончив сетевой оракул, будит им цикл. Без этого вердикт лежал бы до
 * следующего события датапата или тика, а это секунды на ровном месте. */
int d2k_sched_wake_fd(const d2k_sched *s);

/* Куда планировщик говорит, что делает. По умолчанию — никуда: библиотека не
 * имеет права печатать в чужой поток вывода. d2kc ставит сюда свою печать.
 *
 * Заведено не для красоты: первый живой прогон d2kc на роутере не дал НИ ОДНОЙ
 * строки, и отличить «поисков не было, потому что датапат не подозревал» от
 * «поиск шёл и упал молча» было нечем. Go-сторона говорит о каждом шаге
 * (controller.go, sayf), и это единственное, чем её работа наблюдаема снаружи.
 * Строка приходит УЖЕ СОБРАННОЙ и живёт только на время вызова. */
typedef void (*d2k_sched_say_fn)(void *ctx, const char *line);
void d2k_sched_set_say(d2k_sched *s, d2k_sched_say_fn fn, void *ctx);

/* Сколько поисков идёт прямо сейчас — для d2kc и для тестов. */
size_t d2k_sched_active(const d2k_sched *s);

/* Пишет то, что панель показывает человеку, — в файл, атомарно.
 *
 * ПОЧЕМУ ЗДЕСЬ, А НЕ В GO. Панель (internal/web) берёт узнанное через интерфейс
 * KnowledgeSource и до 11.09 получала его от Go-контроллера — того самого,
 * который удалён. Собрать тот же вид в Go заново значило бы завести ВТОРОГО
 * читателя каталога и второе представление о том, что такое «идущий поиск»:
 * первый расходится со вторым в первый же день, и панель начинает показывать
 * не то, что делает движок. Здесь этот вид собирает тот, кто единственный
 * знает и каталог, и живые поиски, — сам планировщик; панель его только
 * читает.
 *
 * Формат — ровно структура status.Knowledge (internal/status/knowledge.go) в
 * JSON, поле в поле по её же тегам. Панель разбирает его как есть, без
 * переходников. Время — RFC 3339 с Z, как во всём каталоге.
 *
 * Пишется во временный файл рядом и переименовывается: панель читает этот файл
 * в произвольный момент, и увидеть половину записи она не должна. */
int d2k_sched_write_live(d2k_sched *s, const char *path, const char *catalog_path);

void d2k_sched_free(d2k_sched *s);

#endif /* D2K_SCHED_H */
