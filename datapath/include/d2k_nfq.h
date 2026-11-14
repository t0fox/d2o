/* d2k_nfq.h — сокет NFQUEUE.
 *
 * Тонкий слой над NETLINK_NETFILTER: открыть, привязаться к очереди, читать,
 * отвечать вердиктом. Разбор и сборка сообщений живут в d2k_nl.h и здесь не
 * повторяются — этот файл занимается только системными вызовами.
 *
 * Только Linux. На маке модуль не собирается намеренно: подделывать сокеты
 * ядра ради сборки значило бы проверять подделку. Переносимость ловится
 * кросс-компиляцией под aarch64 и mipsel (цель cross).
 */
#ifndef D2K_NFQ_H
#define D2K_NFQ_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <poll.h>

typedef struct d2k_nfq d2k_nfq;

typedef struct {
    uint16_t queue;
    /* Сколько байт пакета просить у ядра. Меньше — дешевле, но обрезанный
     * пакет мы всё равно откажемся трогать, так что экономия мнимая. */
    uint32_t copy_range;
    /* Глубина очереди в пакетах. */
    uint32_t maxlen;
    /* Переполнение очереди и смерть процесса ПРОПУСКАЮТ пакет, а не роняют.
     * Без этого падение датапата оставляет весь интернет в очереди — прямое
     * требование §10. Выключать только в лаборатории. */
    int      fail_open;
    /* Размер приёмного буфера сокета. 0 — не трогать. */
    int      rcvbuf;
} d2k_nfq_cfg;

/* NULL при неудаче, причина — в err. */
d2k_nfq *d2k_nfq_open(const d2k_nfq_cfg *cfg, char *err, size_t errcap);
void     d2k_nfq_close(d2k_nfq *q);
int      d2k_nfq_fd(const d2k_nfq *q);
uint32_t d2k_nfq_port(const d2k_nfq *q);

/* Netlink can signal ENOBUFS without unread packets (POLLERR only). */
static inline int d2k_nfq_read_event(short events) {
    return events & (POLLIN | POLLERR);
}

/* Читает один буфер сообщений.
 *  >0 — прочитано байт;
 *   0 — читать нечего (EAGAIN/EINTR);
 *  -1 — ошибка, причина в err;
 *  -2 — ENOBUFS: ядро сообщило, что сообщения ПОТЕРЯНЫ. Это не сбой сокета, а
 *       факт о наблюдении: часть пакетов мы не увидели. Считать отдельно и
 *       показывать — «неизвестное не показывается как исправное». */
ssize_t d2k_nfq_recv(d2k_nfq *q, uint8_t *buf, size_t cap, char *err, size_t errcap);

/* Вердикт по пакету. 0 — отправлено, -1 — ошибка. */
int d2k_nfq_verdict(d2k_nfq *q, uint32_t pkt_id, uint32_t verdict,
                    char *err, size_t errcap);

/* Вердикт, выпускающий вместо пакета payload (до 2048 байт). */
int d2k_nfq_verdict_payload(d2k_nfq *q, uint32_t pkt_id, uint32_t verdict,
                            const uint8_t *payload, size_t len, char *err, size_t errcap);

typedef struct {
    uint64_t drops, replacements, samples, max_us, no_timestamp;
    uint64_t userspace_samples, userspace_max_us;
} d2k_nfq_window;

/* Packet ID is retained only until verdict, in a fixed-size timing table.
 * NFQA_TIMESTAMP is kernel packet time, which can precede NFQUEUE enqueue. */
void d2k_nfq_timing(d2k_nfq *q, int enabled);
void d2k_nfq_note_packet(d2k_nfq *q, uint32_t id, uint64_t kernel_ns, uint64_t read_ns);
d2k_nfq_window d2k_nfq_take_window(d2k_nfq *q);

/* Сколько раз ядро сообщало о потерянных сообщениях. */
uint64_t d2k_nfq_lost(const d2k_nfq *q);

#endif /* D2K_NFQ_H */
