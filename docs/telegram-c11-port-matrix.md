# Матрица порта Telegram proxy: Rust → C11

Аудит донора выполнен по `z2kOW` `d307c345ed7f7eedf02e52792d0a24bc832fe271`.
Состояние C-кода и интеграции зафиксировано на 2026-10-16. Таблица различает
реализованный код, локальные тесты и сценарии, которые ещё не проверены на
настоящей сети или маршрутизаторе.

| Возможность донора | Источник Rust | Реализация в d2o | Проверка и оставшийся предел |
|---|---|---|---|
| Obfuscated2, AES-256-CTR, DC ID, media flag, transport tags | `crypto.rs` | `mtproto_crypto.c`, `mtproto_auth.c`, `mtproto_auth_keys.inc`; используется локальным прокси | Векторы и тесты проходят. Нужна проверка с настоящим Telegram DC. |
| Abridged, intermediate и padded intermediate; разбиение пакетов | `splitter.rs` | `mtproto_splitter.c`; для direct WSS и CF proxy сохраняются MTProto-границы, Worker использует потоковый режим | Unit-векторы и тест локального WSS проходят. C/Rust сравнение на общем наборе входов отсутствует. |
| Исходное назначение, IPv4/IPv6, разрешение Telegram DC | `transparent.rs`, `transparent_proxy.rs` | `listener.c` читает IPv4/IPv6 `SO_ORIGINAL_DST`; `transparent.c` проверяет DC-карту, порт, CIDR и защиту от собственного dial | Парсер и политика покрыты тестами. Kernel REDIRECT для IPv6 и фактический трафик на роутере не проверялись. |
| TCP bridge, backpressure, закрытие и тайм-ауты | `transparent_proxy.rs`, `bridge.rs` | Linux `epoll` runtime, ограниченные очереди, неблокирующий TLS, WSS ping/pong/close, idle и handshake deadlines | Локальные тесты epoll, WSS и лимитов проходят. Стресс-тест на целевом роутере отсутствует. |
| DC discovery, проверка `req_pq_multi/resPQ`, auth и `help.getConfig` | `dc_discovery.rs` | `mtproto_probe.c`, `mtproto_auth.c`, `mtproto_config.c`; демон обновляет карту через IPv4/IPv6 seed DC1, сохраняет LKG и повторяет неудачу позже | Парсеры и криптография покрыты векторами. CLI проверяет один указанный IP; полной автоматической диагностики DC1–DC5 нет. 2026-10-16 пять отдельных TCP probes для DC1–DC5 дошли до `resPQ` с совпавшим nonce; это не проверка WSS-маршрутов и не `help.getConfig`. Полного автоматического запуска матрицы DC1–DC5 нет. |
| Прямой Telegram WSS `kwsN.web.telegram.org/apiws` | `ws_client.rs`, `routing.rs` | Direct WSS для DC1–DC5, TLS hostname/SNI и проверка сертификата; при сбое до WebSocket Upgrade маршрут меняется дальше по плану | Проверено локальным TLS/WSS сервером. Живые Telegram WSS endpoints не проверялись. |
| Cloudflare Worker на пользовательском домене | `routing.rs`, `bridge.rs` | `TG_CF_WORKER_DOMAIN`; проверенный TLS, настраиваемый Worker path, потоковый framing | План и transport mocks покрыты. Живой Worker/domain не проверен. |
| Резервный CF WebSocket proxy | `routing.rs`, `cf_proxy_doh.rs` | `TG_CF_DOMAIN`; WSS с MTProto packet framing и ограниченным пулом доменов | Локальные тесты плана, DNS и пула проходят. Живые CF proxy домены не проверялись. |
| TCP fallback | `transparent_proxy.rs`, `routing.rs` | Прямое соединение к валидированному исходному DC после неудачных WSS-маршрутов | Проверяется тестами выбора маршрута. Внешняя сеть и Telegram DC не проверялись. |
| Adaptive выбор, latency, cooldown, восстановление | `routing.rs` | `route_plan.c` и `epoll_proxy.c` хранят состояние по DC/media/исходному адресу, предпочитают успешный быстрый маршрут и учитывают cooldown | Синтетические сценарии проходят. Состояние процесса не сохраняется между перезапусками. Успех WSS-маршрута учитывается после полного структурно корректного MTProto transport packet в обратном Obfuscated2 направлении; quick ACK проходит без повышения health. Это не подтверждает конкретный RPC, например `help.getConfig`. |
| Ограниченная гонка WSS-кандидатов | `routing.rs` | Опциональный `TG_WS_ROUTING=hedged`, задержка и общий лимит параллельных гонок; кандидат становится основным после корректного MTProto transport packet | Локальный regression покрывает Abridged, Intermediate и Padded Intermediate, включая транспортное заполнение и quick ACK. Первый кандидат с HTTP 101 и запросом без MTProto-пакета не выигрывает; второй с корректным пакетом повышается. Реальная сеть не проверялась. |
| CF domain pool, встроенные fallback domains, last-known-good | `cf_domain_pool.rs`, `default_domains.rs` | `cf_domains.c`: ручной пул, встроенные domains, проверенный кэш и атомарное обновление списка | Парсер, объединение и кэш покрыты тестами. Обновление из внешнего источника в этой среде не проверялось. |
| DNS и DoH для CF-маршрутов | `cf_proxy_doh.rs` | `route_dns.c`: ограниченный кэш, системное разрешение, HTTPS DoH к Cloudflare и Google, проверка TLS hostname/SNI; DNS выполняет один вспомогательный worker | Формат ответа, кэш и адресные ограничения покрыты тестами. Живые DoH запросы не подтверждены. |
| Диагностика по фазам и машинный вывод | `diagnostics.rs` | `--check-telegram-dc` сообщает TCP/MTProto/resPQ; `--discover-telegram-dc` сообщает `help.getConfig`; панель читает Unix stats socket | JSON и парсеры тестируются локально. DNS/TLS/WS фазы, причина отказа CF-маршрута и DC1–DC5 матрица диагностики отсутствуют. |
| Runtime counters и панель | `stats.rs` | Unix socket с правами `0600`, счётчики соединений, байтов, WSS попыток/ошибок и CF ответов; C-панель читает и валидирует ответ | Тесты socket/API проходят. RSS, полное состояние каждого маршрута и настоящая доступность Telegram в статусе не показываются. |
| Пределы FD и RAM | `limits.rs` | `limits.c` рассчитывает лимит соединений по FD и памяти; daemon задаёт бюджет 32 MiB, предел 64 клиента и ограничивает WSS/hedge ресурсы | Unit-тесты и ASan/UBSan проходят. Реальный RSS и поведение на устройстве с 128 MiB не измерялись. |
| Конфигурация и удаление relay client | `config.rs`, `server.rs`, `runtime.rs` | `d2ktg` принимает только `TG_MODE=local`; старые relay URL/secret/enroll ключи не разбираются. Установщик переводит старый `relay` в `local`, сохраняя старые поля с правами `0600` | Тесты конфигурации, панели, release и runtime install проходят. Отдельный `relay-enroll` сервер оставлен для совместимости прежних установок и существующего Meta DNS resolver; новый `d2ktg` к нему не обращается. |
| Keenetic и OpenWrt lifecycle/firewall | OpenWrt integration | Установщик выбирает собственную таблицу nftables для fw4 или iptables для Keenetic/fw3; init, enable/disable и uninstall управляются штатно | Release/OpenWrt/runtime test scripts проходят. Docker lab, физический OpenWrt и Keenetic в этом прогоне недоступны. |
| Сборка, ABI, размер бинарника и регрессии | Makefile, CI, release scripts | `telegram/Makefile` и release cross-build используют явный локальный список исходников; client relay/session/stream/tunnel модули удалены | Native tests, ASan/UBSan и GCC `-fanalyzer` выполнены. Zig и Docker отсутствуют, поэтому 9-архитектурный static build, QEMU ABI и release sizes не проверены. |

## Результат

Локальный C11 runtime и интеграция больше не запускают прежний relay client.
Direct WSS, CF Worker, CF proxy, TCP fallback, discovery, DoH, пул доменов,
адаптивный выбор и opt-in hedge представлены в коде и имеют локальные тесты.
Успех WSS и hedge проверяется для трёх транспортных форматов.

Полный критерий завершения пока не выполнен. Подтверждён живой TCP `resPQ`
для DC1–DC5, но не WSS-доступ к Telegram, `help.getConfig` или реальные
Worker/CF маршруты. Также не завершены автоматическая диагностика DC1–DC5,
эквивалентность C/Rust, release-сборки архитектур, ABI/QEMU, ресурсные замеры
на 128 MiB устройстве и физические Keenetic/OpenWrt сценарии. WSS-health
проверяет структуру transport packet, а не конкретный RPC.

Во время установки старые `relay-enroll` endpoint и сервер оставлены: они не
используются новым локальным прокси и позволяют откатиться на прежний
установленный бинарник. Их удаление требует отдельного решения о сроке
совместимости с такими бинарниками.
