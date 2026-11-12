# DoH/DoT/DoQ: полевой замер с роутера, 2026-11-10

## Стенд

- Роутер: OpenWrt 25.12.6, aarch64 (MediaTek Filogic); адреса стенда опущены.
- WSL на рабочей машине использовал **другой egress**.
  Результаты из WSL не полевые: там MagicDNS DoH/DoT проходил, а с роутера
  тот же IP полностью закрыт.
- Инструменты: `dnsprobe` (C, этот репозиторий), `https-dns-proxy`
  2026.05.06-r1, `dnsproxy` 0.86.0-r1, `bind-dig`.

## Методика

`d2k-dnsprobe` собирает DNS-запрос A, шлёт его DoH/DoT/plain, проверяет id,
вопрос и наличие A/AAAA. DoH — HTTP/1.1 POST; серверы, требующие HTTP/2,
дают 505/400, для них отдельно проверялся `https-dns-proxy` (libcurl, HTTP/2).

**Контрольное имя — `wikipedia.org`, не `example.com`.** Выяснилось, что
Comss, Xbox, WebShift, Null's и dns-ai сами переписывают `example.com` на
`8.47.69.x`/`8.6.112.x`; `wikipedia.org` через них даёт настоящий
`185.15.59.224`. То же подтверждает `dig +https`/`dig +tls` (с проверкой
сертификата), то есть это не MITM, а правило самих Smart DNS. Поэтому
`example.com` для приёмки не годится, а `--expect` в `dnsprobe` позволяет
явно потребовать настоящий адрес.

## Матрица с роутера (запрос `wikipedia.org`)

| Сервис | Что ответило | Ответ | Что не ответило |
|---|---|---|---|
| Comss.one | DoH `141.133.183.77` | `185.15.59.224` | — |
| Xbox DNS | DoH `111.88.96.56` | `185.15.59.224` | — |
| WebShift | DoT `31.31.207.68:853` | `185.15.59.224` | DoH: HTTP 400 |
| Null's Proxy | DoT `185.175.46.137:853` | `185.15.59.224` | DoH: HTTP 505 |
| Bezmezhau | DoT `31.58.216.201:853` | `185.15.59.224` | `143.20.64.55` — timeout |
| dns-ai | DoT `194.87.196.13:853` | `185.15.59.224` | DoH HTTP/1.1 — 505; TCP 853 `45.151.102.219` молчит |
| GeoHide | DoQ `quic://geohide.ru` (dnsproxy) | `185.15.59.224` | DoH `37.230.192.51` — 200/503 нестабильно; DoT — EOF; `159.194.200.33` — timeout |
| MagicDNS | — | — | все три A: TCP 80/443/853 timeout, UDP 53 timeout; ICMP проходит |
| AstroCat | — | — | endpoint не обслуживается (см. ниже) |
| Mafioznik | — | — | `dns.mafioznik.xyz` — NXDOMAIN |
| XyZ | — | — | `dns.yo1nk.app` — NXDOMAIN |

DoQ отдельно: Comss, dns-ai и GeoHide ответили через `dnsproxy`
(`quic://...`) настоящим `185.15.59.224`. Это проверялось не C-клиентом, а
`dnsproxy`; C-клиент DoQ пока не подключён.

## Ключевые наблюдения

### 1. MagicDNS: блок по IP, локального обхода нет

```
ping 109.120.177.170                 -> 0% loss, ~49 ms
curl http://109.120.177.170          -> timeout
curl https://109.120.177.170/sync    -> timeout
dig wikipedia.org @45.88.163.92      -> timeout (3/3)
dig wikipedia.org @45.86.65.181      -> timeout (3/3)
```

С WSL (другой egress) тот же IP отвечал, а SNI `api.magicdns.ru.` (точка на
конце) проходил TLS и давал DoH 200. С роутера TCP 443/853 и UDP 53 к его
адресам не устанавливаются. ICMP проходит, значит адрес маршрутизируется, но
сервисные порты закрыты. Клиентский SNI-приём здесь не помогает; нужен
релей/туннель или другой адрес, которого у сервиса сейчас нет.

### 2. GeoHide: выбор IP, а не обход

`geohide.ru` имеет несколько A. `159.194.200.33` не отвечает;
`37.230.192.51` отвечает DoH 200 и DoQ. Это тот же сервис, просто мёртвый
первый адрес. D2K должен перебирать адреса, а не считать сервис заблокированным.

### 3. dns-ai: протокол решает

- DoT `194.87.196.13:853` — `185.15.59.224`.
- DoH с тем же IP по HTTP/1.1 — `HTTP 505`; через `https-dns-proxy`
  (libcurl, HTTP/2) — `185.15.59.224`.
- DoQ `45.151.102.219:853` — `185.15.59.224`, хотя TCP 853 на этом IP молчит.

### 4. AstroCat: не подмена DNS, а нерабочий endpoint

Авторитетные NS `ns1..ns4.turtleguard.cloud` отдают те же
`135.106.217.200` и `135.106.197.22`, что и Cloudflare/Google. Значит, это не
подмена ответа. По HTTP :80 отдаётся посторонний сайт автосервиса; TLS на :443
и :853 сбрасывается/молчит при любом SNI. Локального обхода нет: сервер не
обслуживает это имя.

### 5. Подмена `example.com` самими Smart DNS

С проверкой сертификата (`dig +https`/`dig +tls`) один и тот же ответ:

```
dns.comss.one      -> 8.47.69.0, 8.6.112.0
xbox-dns.ru        -> 8.6.112.0, 8.47.69.0
d.webshiftvpn.ru   -> 8.47.69.0, 8.6.112.0
dns.nullsproxy.com -> 8.6.112.5, 8.47.69.5
dns.dns-ai.ru      -> 8.6.112.0, 8.47.69.0
```

`wikipedia.org` через те же резолверы — настоящий `185.15.59.224`;
`dig +https example.com @cloudflare-dns.com` — настоящие `104.20.23.154`,
`172.66.147.243`. Значит, это не перехват TLS: сервисы сами переписывают
`example.com`. Вывод: проверять id/вопрос недостаточно, нужен контрольный
домен и/или `--expect` с доверенным адресом.

## Доказательство, что подбор идёт по коробке

### 1. Управляемый SNI-цензор (лаб)

`dnsprobe/test/lab_sni.sh` поднимает на 9443 цензор: ClientHello с SNI ровно
`api.magicdns.ru` получает RST, с `api.magicdns.ru.` — пересылается на
настоящий TLS/DoH-сервер 9444. Поиск обязан увидеть разницу и выбрать dot:

```
  try service=lab-doh proto=doh ip=127.0.0.1 sni=canon -> io ... Connection reset by peer
  try service=lab-doh proto=doh ip=127.0.0.1 sni=dot   -> ok rtt=52ms
service=lab-doh winner=doh host=api.magicdns.ru ip=127.0.0.1 sni=dot answers=1 1.2.3.4
```

Это не «всегда dot»: при живом canon поиск останавливается на canon (так и
вышло на Comss/Xbox/Bezmezhau). Режим выбирается по ответу коробки.

### 2. Поле: один сервис, разные IP

Один и тот же манифест, один прогон с роутера:

```
geo-bad  159.194.200.33  doh -> connect timeout (canon/dot/none)
geo-good 37.230.192.51   doh -> ok 185.15.59.224
dnsai-tcp      45.151.102.219  dot -> connect timeout (canon/none/dot)
dnsai-good-tcp 194.87.196.13   dot -> ok 185.15.59.224
```

Разница только в адресе; поиск не знает заранее, какой IP живой, и выбирает
его по замеру. То же для протокола: GeoHide DoH/DoT дают 503/EOF, а DoQ
`quic://geohide.ru` отвечает `185.15.59.224`; dns-ai DoQ работает на
`45.151.102.219`, где TCP 853 молчит.

### 3. Поле: подмена `example.com`

`d2k-dnsprobe doh cloudflare-dns.com --ip 1.1.1.1 --name example.com
--expect 104.20.23.154` возвращает `status=substituted` (пришли
`8.47.69.0/8.6.112.0`), а тот же запрос с `--expect 185.15.59.224` для
`wikipedia.org` — `ok`. Это проверка не «любого A», а ожидаемого адреса.

## Подбор и применение

`d2k-dns-search-apply.sh` запускает `d2k-dnsprobe search` по манифесту, при
неудаче C-поиска пробует DoQ через `dnsproxy` и применяет победителя
`d2k-dns-apply.sh --apply`.

Финальный прогон с роутера, `wikipedia.org`, `--repeats 2`:

```
magicdns  plain 45.88.163.92       -> UDP timeout (2/2 не дошли)
comss     doh   141.133.183.77     -> 185.15.59.224, rtt 274 ms
xbox      doh   111.88.96.56       -> 185.15.59.224, rtt 90 ms
webshift  dot   31.31.207.68       -> 185.15.59.224, rtt 94 ms
nulls     dot   185.175.46.137     -> 185.15.59.224, rtt 105 ms
geohide   doq   geohide.ru         -> 185.15.59.224 (DoQ fallback)
dnsai     dot   194.87.196.13      -> 185.15.59.224, rtt 244 ms
bezmezhau dot   31.58.216.201      -> 185.15.59.224, rtt 297 ms
```

GeoHide DoH в этом прогоне дал 503, DoT — EOF; DoQ через `dnsproxy` ответил.
Это и есть причина отдельного fallback: один протокол/адрес не должен
закрывать услугу.

## UCI/dnsmasq: сквозные проверки

Скрипт `scripts/d2k-dns-apply.sh` делает резерв, пишет UCI и перезапускает
службы; `--rollback` возвращает конфигурацию.

### Comss DoH через https-dns-proxy

```
uci set https-dns-proxy.@https-dns-proxy[0].resolver_url=https://dns.comss.one/dns-query
uci set https-dns-proxy.@https-dns-proxy[0].listen_port=5053
uci commit https-dns-proxy
uci set dhcp.@dnsmasq[0].noresolv=1
uci add_list dhcp.@dnsmasq[0].server=127.0.0.1#5053
uci commit dhcp
/etc/init.d/https-dns-proxy restart
/etc/init.d/dnsmasq restart
dig +short A wikipedia.org @127.0.0.1
dig +short A example.com @127.0.0.1
```

Результат: `wikipedia.org` → `185.15.59.224`; `example.com` →
`8.47.69.0/8.6.112.0` (подмена самим Comss). После `--rollback` —
прежний ответ, `wikipedia.org` снова `185.15.59.224`.

### Comss DoT через dnsproxy

```
uci set dnsproxy.global.enabled=1
uci add_list dnsproxy.global.listen_port=5353
uci add_list dnsproxy.servers.upstream=tls://dns.comss.one
uci add_list dnsproxy.servers.bootstrap=1.1.1.1
uci commit dnsproxy
/etc/init.d/dnsproxy restart
uci add_list dhcp.@dnsmasq[0].server=127.0.0.1#5353
```

Результат через `dig @127.0.0.1`: `wikipedia.org` → `185.15.59.224`.
После rollback — исходные ответы, `dnsproxy` остановлен.

### dns-ai DoH через https-dns-proxy

`resolver_url=https://dns.dns-ai.ru/dns-query`, `listen_port=5053`.
`wikipedia.org` → `185.15.59.224`; rollback вернул прежний ответ.

### MagicDNS plain

Проверялся `dhcp.@dnsmasq[0].server=45.88.163.92`, `noresolv=1`.
Один раз ответил `8.47.69.5/8.6.112.5`, затем три повтора подряд — timeout.
Стабильного ответа нет; как рабочий вариант не засчитан.

## Что осталось

- MagicDNS с этого ISP локально не поднимается: TCP 443/853 и UDP 53 к его
  адресам закрыты. Нужен релей/туннель или другой IP; клиентский обход не
  поможет.
- AstroCat: endpoint не обслуживается; клиентский обход не поможет.
- C-клиент DoH не умеет HTTP/2: dns-ai, Null's, WebShift DoH дают 505/400.
  Для применения используется `https-dns-proxy`; для измерения нужен HTTP/2
  в C или явная пометка «нужен HTTP/2».
- C-клиент DoQ пока не подключён; DoQ проверялся через `dnsproxy`.
- GeoHide нестабилен: DoH/DoT то 200, то 503/EOF; DoQ через `dnsproxy`
  отработал и дал `185.15.59.224`. Нужен повтор и выбор протокола/адреса;
  один 503/EOF не означает «заблокирован».
- `example.com` нельзя использовать как контроль: Smart DNS его переписывают.
  Для приёмки — `wikipedia.org` и/или `--expect` с доверенным адресом.
