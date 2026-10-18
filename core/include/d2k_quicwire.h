/* d2k_quicwire.h — БАЙТОВЫЙ УРОВЕНЬ QUIC, ОДИН НА ВСЁ ЯДРО.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ МОДУЛЬ. Соль Initial, выбор меток по версии, снятие защиты
 * заголовка и разбор длинного заголовка к моменту появления этого файла жили
 * В ДВУХ КОПИЯХ — в core/quic.c (разбор клиентского Initial на пакетном пути)
 * и в core/quicprobe.c (проверка подлинности ответа сервера). Копии уже
 * начали расходиться: одна знает версию 2, другая нет; одна проверяет
 * резервные биты после снятия AEAD, другая не доходит до AEAD вовсе. Третьей
 * копии (зонд подтверждения) спецификация не позволяет по §2.5 — «второй
 * реализации быть не должно», — и поэтому байтовый уровень вынесен сюда, а
 * оба прежних места переведены на него.
 *
 * ЧТО ЗДЕСЬ ЕСТЬ И ЧЕГО ЗДЕСЬ НЕТ. Здесь только БАЙТЫ: числа переменной
 * длины, заголовки, номера пакетов, вывод ключей, защита и снятие защиты
 * пакета. Здесь НЕТ состояния соединения, кадров, потерь, подтверждений и
 * таймеров — это уровнем выше (core/quicconn.c). Граница проведена так
 * намеренно: всё, что ниже, проверяется векторами из RFC без единой строки
 * сетевого кода, и потому проверяется дёшево и до конца.
 *
 * ВЕРСИИ. Поддержаны v1 (RFC 9000/9001) и v2 (RFC 9369). Разница между ними
 * ровно в двух местах: соль извлечения начального секрета и метки защиты
 * (key/iv/hp). Метки извлечения СЕКРЕТА УРОВНЯ ("client in"/"server in") у
 * обеих одни и те же — RFC 9369 §3.3.2 меняет только защиту.
 *
 * Initial-ЗАЩИТА ОДНА: AES-128-GCM. Это не зависит от списка TLS cipher
 * suites внутри ClientHello: ChaCha20/AES-256 там относятся к будущему TLS
 * handshake, а не к QUIC Initial packet protection. Измерительный профиль
 * ClientHello поддерживает оба donor-порядка suites; wire-слой всё равно
 * использует RFC 9001 AES-128-GCM.
 */
#ifndef D2K_QUICWIRE_H
#define D2K_QUICWIRE_H

#include <stddef.h>
#include <stdint.h>

/* Версии протокола на проводе. */
#define D2K_QW_V1 0x00000001u /* RFC 9000 */
#define D2K_QW_V2 0x6b3343cfu /* RFC 9369 §3.1 */

/* Длина обеих солей — 20 байт (RFC 9001 §5.2, RFC 9369 §3.3.1). */
#define D2K_QW_SALT_LEN 20

/* RFC 9000 §17.2: «MUST NOT exceed 20 bytes… Endpoints that receive a value
 * larger than 20 MUST drop the packet». Это требование стандарта, а не
 * граница буфера: в однобайтовое поле помещается любое значение. */
#define D2K_QW_CID_MAX 20

/* Наибольшая датаграмма, с которой работает этот модуль. Нижняя граница
 * задана стандартом: клиентский Initial обязан быть не короче 1200 байт
 * (RFC 9000 §14.1). Верхняя взята кадром Ethernet: датаграмма крупнее не
 * проходит без фрагментации почти нигде, включая PPPoE (1492). */
#define D2K_QW_MAX_DGRAM 1500

/* Уровни ключей. Номера пакетов у каждого СВОИ (RFC 9000 §12.3): один
 * счётчик на три уровня — это провал расшифровки на ровном месте. */
typedef enum {
    D2K_QW_LEVEL_INITIAL = 0,
    D2K_QW_LEVEL_HANDSHAKE = 1,
    D2K_QW_LEVEL_APP = 2,
    D2K_QW_LEVEL_COUNT = 3
} d2k_qw_level;

/* Сторона, чьи ключи выводятся. Нужна обеим: клиент шифрует своим секретом и
 * расшифровывает серверным. */
typedef enum { D2K_QW_CLIENT = 0, D2K_QW_SERVER = 1 } d2k_qw_side;

/* Готовый набор ключей одного уровня одной стороны. */
typedef struct {
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t hp[16];
    int     have;   /* 0 — ключей этого уровня ещё нет */
} d2k_qw_keys;

/* Разобранный заголовок пакета. Один тип на длинный и короткий: вызывающий
 * различает их по полю long_hdr, а не по тому, какую функцию он позвал. */
typedef struct {
    int      long_hdr;      /* 1 — длинный заголовок, 0 — короткий */
    uint32_t version;       /* значим только при long_hdr */
    uint8_t  type;          /* тип длинного заголовка: 0 Initial, 1 0-RTT, 2 Handshake, 3 Retry */
    size_t   dcid_off, dcid_len;
    size_t   scid_off, scid_len;
    size_t   token_off, token_len; /* значимы только для Initial */
    size_t   pn_offset;     /* где начинается (ещё защищённый) номер пакета */
    size_t   length_claimed;/* поле Length: номер пакета + payload + тег; 0 у короткого */
    size_t   length_width;  /* ширина поля Length на проводе (1, 2, 4 или 8 байт) */
    size_t   packet_len;    /* сколько байт занимает ВЕСЬ пакет в датаграмме */
} d2k_qw_hdr;

/* Типы длинного заголовка v1 (RFC 9000 §17.2). В v2 они перенумерованы
 * (RFC 9369 §3.2), и d2k_qw_hdr_parse приводит их к номерам v1 — чтобы
 * вызывающий не разбирался в версии ради типа. */
#define D2K_QW_LT_INITIAL   0
#define D2K_QW_LT_0RTT      1
#define D2K_QW_LT_HANDSHAKE 2
#define D2K_QW_LT_RETRY     3

/* --- числа переменной длины (RFC 9000 §16) ------------------------------ */

/* 0 — прочитано, -1 — не хватило байт. val/width при отказе не трогаются. */
int  d2k_qw_varint_read(const uint8_t *p, size_t avail, uint64_t *val, size_t *width);
/* Сколько байт займёт значение: 1, 2, 4 или 8; 0 — значение не представимо. */
size_t d2k_qw_varint_len(uint64_t v);
/* Записывает значение минимальной шириной. Возвращает записанные байты или 0,
 * если не поместилось либо значение не представимо. */
size_t d2k_qw_varint_write(uint8_t *p, size_t cap, uint64_t v);
/* Записывает значение заданной шириной w (1, 2, 4 или 8; 0 — минимальной). */
size_t d2k_qw_varint_write_w(uint8_t *p, size_t cap, uint64_t v, size_t w);

/* --- заголовки ---------------------------------------------------------- */

/* Разбирает заголовок пакета, лежащего по p[0..n).
 *
 * dcid_len_short — длина DCID у КОРОТКОГО заголовка: на проводе она не
 * объявлена, её знает только тот, кто выдал этот идентификатор. Для чужих
 * пакетов, где она неизвестна, передаётся 0 и короткий заголовок honestly не
 * разбирается (вернётся -1) — гадать длину нельзя.
 *
 * 0 — разобрано, -1 — это не разбираемый заголовок. packet_len заполняется
 * всегда при успехе: по нему вызывающий переходит к следующему пакету
 * коалесцированной датаграммы (RFC 9000 §12.2). */
int d2k_qw_hdr_parse(const uint8_t *p, size_t n, size_t dcid_len_short,
                     d2k_qw_hdr *out);

/* Собирает НЕЗАЩИЩЁННЫЙ длинный заголовок вплоть до поля Length включительно
 * — ровно то, что принимает d2k_qw_seal. Номер пакета и тело допишет он.
 *
 * payload_len — длина тела ДО шифрования: поле Length обязано учесть номер
 * пакета, тело и тег AEAD (16 байт), иначе получатель отрежет пакет не там.
 *
 * out обязан вмещать 1+4+1+dcid_len+1+scid_len (+1 на пустой токен у Initial)
 * +8; на практике хватает 64 байт. Возвращает длину заголовка, 0 — отказ
 * (слишком длинный идентификатор либо непредставимая длина). */
size_t d2k_qw_long_hdr(uint8_t *out, size_t cap, uint32_t version, uint8_t type,
                       const uint8_t *dcid, size_t dcid_len,
                       const uint8_t *scid, size_t scid_len,
                       size_t pn_len, size_t payload_len);

size_t d2k_qw_long_hdr_w(uint8_t *out, size_t cap, uint32_t version, uint8_t type,
                         const uint8_t *dcid, size_t dcid_len,
                         const uint8_t *scid, size_t scid_len,
                         size_t pn_len, size_t payload_len,
                         size_t length_width);

/* То же для Initial с уже выданным сервером Retry-token. Token лежит между
 * полем длины SCID и полем Length; старый d2k_qw_long_hdr оставлен обёрткой
 * с пустым token, чтобы не менять все существующие вызовы. */
size_t d2k_qw_long_hdr_token(uint8_t *out, size_t cap, uint32_t version,
                             uint8_t type, const uint8_t *dcid, size_t dcid_len,
                             const uint8_t *scid, size_t scid_len,
                             const uint8_t *token, size_t token_len,
                             size_t pn_len, size_t payload_len);

size_t d2k_qw_long_hdr_token_w(uint8_t *out, size_t cap, uint32_t version,
                               uint8_t type, const uint8_t *dcid, size_t dcid_len,
                               const uint8_t *scid, size_t scid_len,
                               const uint8_t *token, size_t token_len,
                               size_t pn_len, size_t payload_len,
                               size_t length_width);

/* --- номера пакетов (RFC 9000 §17.1, A.2/A.3) --------------------------- */

/* Сколько байт нужно, чтобы закодировать pn при подтверждённом largest_acked
 * (-1, если не подтверждено ничего). Всегда 1..4. */
size_t d2k_qw_pn_len(uint64_t pn, int64_t largest_acked);
/* Восстанавливает полный номер по усечённому (алгоритм A.3). */
uint64_t d2k_qw_pn_decode(uint64_t largest_pn, uint64_t truncated, size_t pn_len);

/* --- ключи -------------------------------------------------------------- */

/* Начальный секрет уровня Initial для стороны side, выведенный из DCID
 * первого пакета клиента (RFC 9001 §5.2). 0 — успех. */
int d2k_qw_initial_secret(uint32_t version, const uint8_t *dcid, size_t dcid_len,
                          d2k_qw_side side, uint8_t out[32]);

/* Ключ, вектор и ключ защиты заголовка из секрета уровня (RFC 9001 §5.1).
 * 0 — успех. */
int d2k_qw_keys_from_secret(uint32_t version, const uint8_t secret[32],
                            d2k_qw_keys *out);

/* --- защита пакета ------------------------------------------------------ */

/* Собирает защищённый пакет ЦЕЛИКОМ: шифрует payload, считает тег, наводит
 * защиту заголовка.
 *
 * hdr — незащищённый заголовок вплоть до поля Length включительно (для
 * длинного) либо до DCID включительно (для короткого), БЕЗ номера пакета.
 * Номер пакета и payload модуль допишет сам.
 *
 * Возвращает длину готового пакета или 0 при отказе. */
size_t d2k_qw_seal(const d2k_qw_keys *k, int long_hdr,
                   const uint8_t *hdr, size_t hdr_len,
                   uint64_t pn, size_t pn_len,
                   const uint8_t *payload, size_t payload_len,
                   uint8_t *out, size_t out_cap);

/* Снимает защиту с пакета, разобранного d2k_qw_hdr_parse.
 *
 * largest_pn — наибольший ПОЛНЫЙ номер, уже принятый на этом уровне (0, если
 * не принято ничего): без него усечённый номер восстанавливается неверно, а
 * значит не сходится тег.
 *
 * plain должен вмещать не меньше packet_len байт. 0 — успех, и тогда
 * *plain_len — длина расшифрованного payload, *pn_out — полный номер. */
int d2k_qw_open(const d2k_qw_keys *k, const d2k_qw_hdr *h,
                const uint8_t *p, uint64_t largest_pn,
                uint8_t *plain, size_t *plain_len, uint64_t *pn_out);

/* --- Retry -------------------------------------------------------------- */

/* Проверяет метку целостности пакета Retry (RFC 9001 §5.8).
 * odcid — DCID, который клиент поставил в свой Initial.
 * 0 — метка сошлась, -1 — нет. */
int d2k_qw_retry_verify(uint32_t version, const uint8_t *odcid, size_t odcid_len,
                        const uint8_t *retry, size_t retry_len);

/* Собирает Retry с integrity tag RFC 9001 §5.8.
 * Пакет содержит DCID клиента, SCID сервера и непрозрачный token; ODCID
 * используется только при вычислении метки и в сам пакет не попадает.
 * Возвращает длину пакета либо 0 при переполнении/некорректном вводе. */
size_t d2k_qw_retry_build(uint8_t *out, size_t cap, uint32_t version,
                          const uint8_t *odcid, size_t odcid_len,
                          const uint8_t *dcid, size_t dcid_len,
                          const uint8_t *scid, size_t scid_len,
                          const uint8_t *token, size_t token_len);


/* --- принятые байты одного потока (задача 39, раунд 1) ------------------ */

/* Какие байты потока уже пришли: непересекающиеся отрезки [start, end),
 * упорядоченные и слитые. Ответ «целиком» — это FIN И все байты от нуля до
 * смещения FIN без дыр: наибольшее смещение этого не доказывает. Отрезков
 * больше D2K_QW_RANGES_MAX не храним — новый, не сливающийся ни с одним,
 * тогда не засчитывается (меньше, а не больше, чем пришло). */
#define D2K_QW_RANGES_MAX 64
typedef struct {
    uint64_t start[D2K_QW_RANGES_MAX], end[D2K_QW_RANGES_MAX];
    size_t   n;
    int      fin;       /* FIN принят */
    uint64_t fin_off;   /* окончательный размер потока */
} d2k_qw_ranges;

void     d2k_qw_ranges_reset(d2k_qw_ranges *r);
/* Записывает кадр STREAM: off, len, fin — флаг FIN кадра. */
void     d2k_qw_ranges_add(d2k_qw_ranges *r, uint64_t off, uint64_t len, int fin);
/* Сколько разных байт потока принято. */
uint64_t d2k_qw_ranges_bytes(const d2k_qw_ranges *r);
/* 1 — FIN принят, fin_off > 0 и все байты [0; fin_off) пришли. */
int      d2k_qw_ranges_complete(const d2k_qw_ranges *r);

#endif /* D2K_QUICWIRE_H */
