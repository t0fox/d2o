# dnsprobe — DoH/DoT/DoQ-измеритель

Отдельный C-инструмент для проверки шифрованных DNS-резолверов и подбора
способа предъявления имени. Не входит в `d2kc`; собирается сам, чтобы не менять
зависимости продуктовых бинарников.

## Что умеет

- `doh`: HTTP/1.1 POST `application/dns-message` поверх TLS 1.3/1.2.
- `dot`: DNS в TLS с двухбайтовой длиной (RFC 7858).
- `plain`: обычный UDP DNS (для резолверов, у которых TCP закрыт по IP).
- `doq`: пока не подключён в C; для проверки используется `dnsproxy`.
- Проверяет ответ: id, QR, отсутствие TC, RCODE, вопрос (имя/тип/класс),
  наличие A/AAAA; при `--name` с 0x20 требует точный регистр.
- `--expect IP` — ответ обязан содержать этот адрес; иначе статус
  `substituted` (защита от подмены `example.com` на `8.47.69.x`).
- Способы предъявления имени: `canon`, `dot` (`name.`), `none` (без SNI).
- `search <manifest>`: перебирает строки манифеста и внутри каждой строки —
  режимы SNI; первый проверенный ответ останавливает услугу. По умолчанию
  спрашивается `wikipedia.org`: `example.com` проверяемые Smart DNS
  переписывают на `8.47.69.x`, и такой ответ не доказывает настоящий резолв.
- `--repeats N` в `search` требует N успехов подряд (по умолчанию 1);
  `--timeout MS` задаёт потолок.

## Сборка

Linux (WSL):

```sh
make -C dnsprobe
make -C dnsprobe check
make -C dnsprobe lab    # лаб-цензор: canon reset, dot проходит; поиск выбирает dot
```

aarch64 для роутера (Zig):

```sh
zig cc -target aarch64-linux-musl -std=c99 -O2 \
  -Idnsprobe/include -Icore/include -Idatapath/include -Iruntime \
  -o builds/d2k-dnsprobe-arm64 \
  dnsprobe/src/dnsprobe.c dnsprobe/src/main.c \
  core/tls13.c core/tls12.c core/tls13core.c core/x25519.c \
  core/p256.c core/crypto.c core/diagnostics.c
```

## Примеры

```sh
# обычный DoH
./d2k-dnsprobe doh dns.comss.one --ip 141.133.183.77 --path /dns-query

# пословная блокировка имени: SNI с точкой на конце
./d2k-dnsprobe doh api.magicdns.ru --ip 109.120.177.170 --path /sync --sni dot

# DoT без SNI
./d2k-dnsprobe dot api.magicdns.ru --ip 109.120.177.170 --sni none

# подбор по манифесту
./d2k-dnsprobe search endpoints.example --repeats 2

# проверить, что ответ не подменён
./d2k-dnsprobe doh cloudflare-dns.com --ip 1.1.1.1 \
  --name example.com --expect 104.20.23.154
```

Манифест: `service|host|ip|proto|path`, по строке, `#` — комментарий.

## Что важно помнить

- `dot` в SNI — законная форма FQDN; сервер нормализует имя, а пословный
  фильтр видит другое имя. Проверка имени сертификата в ядре теперь тоже
  нормализует точку.
- `none` (без SNI) работает не у всех: DoT-сервер должен отдать сертификат по
  умолчанию. Для MagicDNS это работает на 853, для DoH на 443 — нет.
- Это измерение, а не транспорт: цепочка доверия не строится, проверяется
  только имя в листовом сертификате (как в `core/tls13.c`).
- Результат с одной машины/сети не переносится на роутер: у WSL и роутера
  разные публичные IP (проверено 2026-11-10).
