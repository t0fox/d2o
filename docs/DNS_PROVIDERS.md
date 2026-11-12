# DoH/DoT-провайдеры

Снимок на **2026-11-10**. Справочный список адресов популярных DoH/DoT-сервисов
(в основном русскоязычные Smart DNS). Это не полевой замер D2K и не
доказательство обхода блокировок: Smart DNS меняет только резолвер, а не
маршрут трафика.

Полевой замер с роутера — `docs/field/2026-11-10-doh-dot-router.md`.
Коротко: Comss, Xbox, WebShift, Null's, Bezmezhau, GeoHide и dns-ai ответили
с роутера; MagicDNS закрыт по IP (TCP 443/853 и UDP 53), AstroCat не
обслуживает endpoint. `example.com` эти сервисы переписывают на `8.47.69.x`,
поэтому контроль — `wikipedia.org` (185.15.59.224).

## Как проверялось

- A-записи — через Cloudflare DoH (JSON API).
- DoH — GET `?dns=` (RFC 8484) по HTTP/2 с запросом `example.com A`.
  «DoH 200» ниже означает, что эндпоинт ответил DNS-ответом, а не просто
  отдал HTML. TLS-сертификаты при этой проверке не валидировались: это
  проверка доступности, а не пригодности для strict-режима.
- DoT отдельно не проверялся: на рабочей машине нет `openssl`, а `curl`
  собран без HTTP/2.
- `TLS reset` — с этой машины не прошло TLS-рукопожатие. Это может быть как
  фильтрация в сети, так и недоступность сервиса; не вывод о блокировке.
- `NXDOMAIN` — имя сейчас не резолвится.

## Русскоязычные Smart DNS / DoH-сервисы

| Сервис | DoH | DoT | IPv4 | Статус 2026-11-10 | Источник |
|---|---|---|---|---|---|
| Comss.one DNS | `https://dns.comss.one/dns-query` | `dns.comss.one` | `83.220.169.155`, `212.109.195.93`; DoH-сервер `195.133.25.16`; DoQ `quic://dns.comss.one` | DoH 200 OK | [comss.ru](https://www.comss.ru/page.php?id=7315) |
| Xbox DNS | `https://xbox-dns.ru/dns-query` | `xbox-dns.ru` | `111.88.96.56`, `111.88.96.57` | DoH 200 OK | [xbox-dns.ru](https://xbox-dns.ru/) |
| AstraCat | `https://dns.astracat.ru/dns-query` | `dns.astracat.ru` | `135.106.217.200` | TLS reset; A-запись есть | Zapret-Manager |
| MagicDNS | `https://api.magicdns.ru/sync` | `api.magicdns.ru` | `45.88.163.92`, `109.120.177.170`, `45.86.65.181` | TLS reset; A-записи есть | [magicdns.ru](https://magicdns.ru/) |
| WebShift DNS | `https://d.webshiftvpn.ru/dns-query` | `d.webshiftvpn.ru` | `31.31.207.68` | DoH 200 OK | mobileconfig и JS сайта WebShift |
| ImMALWARE (`dns.malw.link`) | `https://dns.malw.link/dns-query` | `dns.malw.link` | `164.5.224.81`, `179.254.166.171` | DoH 200 OK; требует HTTP/2 | Zapret-Manager |
| Зеркало dns.malw.link через Cloudflare Gateway | `https://5u35p8m9i7.cloudflare-gateway.com/dns-query` | — | — | не проверялся | Zapret-Manager |
| GeoHide DNS (RU) | `https://geohide.ru/dns-query` | `geohide.ru` | `159.194.200.33`, `37.230.192.51` | TLS reset; A-записи есть | Zapret-Manager, Техноварик |
| GeoHide EU | `https://eu.geohide.ru/dns-query` | `eu.geohide.ru` | см. A-запись | не проверялся | Zapret-Manager |
| GeoHide US | `https://us.geohide.ru/dns-query` | `us.geohide.ru` | см. A-запись | не проверялся | Zapret-Manager |
| Null's Proxy DNS | `https://dns.nullsproxy.com/dns-query` | `dns.nullsproxy.com` | `185.175.46.137`, `45.139.239.56`, `185.211.245.131`, `45.139.239.54`, `141.95.97.120` | DoH 200 OK | [nullsproxy.com](https://nullsproxy.com/) |
| Bezmezhau DNS | `https://dns.bezmezhau.com/dns-query` | `dns.bezmezhau.com` | `143.20.64.55`, `31.58.216.201` | DoH 200 OK | [bezmezhau.com/setup](https://bezmezhau.com/setup) |
| Mafioznik | `https://dns.mafioznik.xyz/dns-query` | `dns.mafioznik.xyz` | — | `NXDOMAIN`; зона `mafioznik.xyz` жива, хоста нет. `freedom.mafioznik.xyz` → `185.76.242.48`, TLS reset | Zapret-Manager; в RussiaFancyLists — «Unavailable» |
| XyZ DNS | `https://dns.yo1nk.app/dns-query` | `dns.yo1nk.app` | — | `NXDOMAIN` | Zapret-Manager |
| dns-ai | `https://dns.dns-ai.ru/dns-query` | `dns.dns-ai.ru` | `194.87.196.13`, `45.151.102.219` | DoH 200 OK, но в RussiaFancyLists — «Unavailable» | Zapret-Manager |

Примечания:

- `dns.webshiftvpn.ru` — это сайт WebShift, а не резолвер: на `/dns-query`
  он отдаёт HTML. Рабочий DoH — только `d.webshiftvpn.ru`.
- У `dns.malw.link` и `dns.nullsproxy.com` сервер требует HTTP/2 (RFC 8484);
  HTTP/1.1-клиент получит отказ.
- Для Comss.one DNS в разных инструкциях встречаются разные IPv4; актуальные
  адреса лучше сверять на странице сервиса.
- WL DNS в открытых источниках не нашёлся: публичного DoH/DoT-имени нет,
  в RussiaFancyLists есть только hosts. Если адрес есть в Telegram-канале
  проекта — его стоит добавить отдельно.
- Mafioznik и XyZ оставлены в списке для полноты, но на 2026-11-10 не
  работают. dns-ai отвечает по DoH, хотя в RussiaFancyLists помечен
  «Unavailable» — расхождение стоит перепроверить на нужных доменах.

## Обычные публичные резолверы

| Сервис | DoH | DoT | IPv4 |
|---|---|---|---|
| Cloudflare | `https://cloudflare-dns.com/dns-query` | `cloudflare-dns.com` | `1.1.1.1`, `1.0.0.1` |
| Google | `https://dns.google/dns-query` | `dns.google` | `8.8.8.8`, `8.8.4.4` |
| Quad9 | `https://dns.quad9.net/dns-query` | `dns.quad9.net` | `9.9.9.9`, `149.112.112.112` |
| AdGuard DNS | `https://dns.adguard-dns.com/dns-query` | `dns.adguard-dns.com` | `94.140.14.14`, `94.140.15.15` |
| Yandex DNS | `https://common.dot.dns.yandex.net/dns-query` | `common.dot.dns.yandex.net` | `77.88.8.8`, `77.88.8.1` |
| DNS.SB (Москва) | `https://ru-mow.doh.sb/dns-query` | `dns.sb` | `185.222.222.222`, `45.11.45.11` |

## Копируемый список

DoH:

```text
https://dns.comss.one/dns-query
https://xbox-dns.ru/dns-query
https://dns.astracat.ru/dns-query
https://api.magicdns.ru/sync
https://d.webshiftvpn.ru/dns-query
https://dns.malw.link/dns-query
https://5u35p8m9i7.cloudflare-gateway.com/dns-query
https://geohide.ru/dns-query
https://eu.geohide.ru/dns-query
https://us.geohide.ru/dns-query
https://dns.nullsproxy.com/dns-query
https://dns.bezmezhau.com/dns-query
https://dns.mafioznik.xyz/dns-query
https://dns.dns-ai.ru/dns-query
```

DoT (порт 853):

```text
dns.comss.one
xbox-dns.ru
dns.astracat.ru
api.magicdns.ru
d.webshiftvpn.ru
dns.malw.link
geohide.ru
eu.geohide.ru
us.geohide.ru
dns.nullsproxy.com
dns.bezmezhau.com
dns.mafioznik.xyz
dns.dns-ai.ru
```

## Источники

- `StressOzz/Zapret-Manager`, `Zapret-Manager.sh` — готовые URL DoH для AstraCat,
  Mafioznik, GeoHide, dns.malw.link, dns-ai, XyZ и зеркала Cloudflare Gateway.
- `Noktomezo/RussiaFancyLists` — статусы Smart DNS и отметки «Unavailable»
  для Mafioznik, XyZ и dns-ai.
- Страницы сервисов: Comss, Xbox DNS, MagicDNS, WebShift, Bezmezhau,
  Null's Proxy.
- [Техноварик: DNS для Gemini и нейросетей, 2026](https://trofimovsky.ru/article/dns-dlya-gemini-i-neirosetei-rossiya-2026-chatgpt-claude-grok-bez-vpn)
  — GeoHide RU, Comss.
- [Comss: о блокировках DoH/DoT, 2026-08-25](https://www.comss.ru/page.php?id=21721)
  — контекст доступности публичных DoH/DoT в РФ.
