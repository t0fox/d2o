# Матрица порта Telegram proxy: Rust → C11

Аудит донора сверен с `z2kOW` `4ef79fb99c30c233488623c04ec13c8097a614e0`.
Дерево `platform/openwrt/tg-proxy` в этом HEAD совпадает с проверенной ревизией
`d307c345ed7f7eedf02e52792d0a24bc832fe271` (`git diff` по этому пути пуст).
Состояние C-кода и интеграции зафиксировано на 2026-10-16. Таблица различает
реализованный код, локальные тесты и сценарии, которые ещё не проверены на
настоящей сети или маршрутизаторе.

| Возможность донора | Источник Rust | Реализация в d2o | Проверка и оставшийся предел |
|---|---|---|---|
| Obfuscated2, AES-256-CTR, DC ID, media flag, transport tags | `crypto.rs` | `mtproto_crypto.c`, `mtproto_auth.c`, `mtproto_auth_keys.inc`; используется локальным прокси | Векторы и тесты проходят. 2026-10-16 прямые TCP и WSS probes подтвердили `resPQ` с совпавшим nonce на DC1–DC5. |
| Abridged, intermediate и padded intermediate; разбиение пакетов | `splitter.rs` | `mtproto_splitter.c`; для direct WSS и CF proxy сохраняются MTProto-границы, Worker использует потоковый режим | Unit-векторы и тест локального WSS проходят. Разовая FFI-сверка с Rust HEAD `4ef79fb` дала те же кадры для трёх транспортных форматов, фрагментированного потока, сырого режима и отказа на пакете выше лимита; повторяемого дифференциального теста нет. |
| Исходное назначение, IPv4/IPv6, разрешение Telegram DC | `transparent.rs`, `transparent_proxy.rs` | `listener.c` читает IPv4/IPv6 `SO_ORIGINAL_DST`; `transparent.c` проверяет DC-карту, порт, CIDR и защиту от собственного dial | Парсер и политика покрыты тестами. Kernel REDIRECT для IPv6 и фактический трафик на роутере не проверялись. |
| TCP bridge, backpressure, закрытие и тайм-ауты | `transparent_proxy.rs`, `bridge.rs` | Linux `epoll` runtime, ограниченные очереди, неблокирующий TLS, WSS ping/pong/close, idle и handshake deadlines | Локальные тесты epoll, WSS и лимитов проходят. Стресс-тест на целевом роутере отсутствует. |
| DC discovery, проверка `req_pq_multi/resPQ`, auth и `help.getConfig` | `dc_discovery.rs` | `mtproto_probe.c`, `mtproto_auth.c`, `mtproto_config.c`; демон обновляет карту через IPv4/IPv6 seed DC1, сохраняет LKG и повторяет неудачу позже | Парсеры и криптография покрыты векторами. Одиночный CLI проверяет указанный IP; `--check-telegram-dc-matrix` и `--discover-telegram-dc-matrix` проверяют DC1–DC5. 2026-10-16 все пять TCP probes дошли до `resPQ`, а `help.getConfig` вернул совпавший `this_dc` и 19 endpoints. |
| Прямой Telegram WSS `kwsN.web.telegram.org/apiws` | `ws_client.rs`, `routing.rs` | Direct WSS для DC1–DC5, TLS hostname/SNI и проверка сертификата; при сбое до WebSocket Upgrade маршрут меняется дальше по плану | Локальные тесты проходят. `--check-telegram-wss-matrix [CA_BUNDLE]` различает DNS/TCP/TLS/WS/MTProto и проверяет `resPQ` с nonce. 2026-10-16 все `kws1`–`kws5` вернули `resPQ`. В `files/tg-roots.pem` добавлен [официальный Go Daddy Root G2](https://certs.godaddy.com/repository/?lang=ENU) (SHA-256 `45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA`), потому что текущая цепочка Telegram WSS заканчивается на нём. |
| Cloudflare Worker на пользовательском домене | `routing.rs`, `bridge.rs` | `TG_CF_WORKER_DOMAIN`; проверенный TLS, настраиваемый Worker path, потоковый framing | План и transport mocks покрыты. Живой Worker/domain не проверен. |
| Резервный CF WebSocket proxy | `routing.rs`, `cf_proxy_doh.rs` | `TG_CF_DOMAIN`; WSS с MTProto packet framing и ограниченным пулом доменов | Локальные тесты плана, DNS и пула проходят. Живые CF proxy домены не проверялись. |
| TCP fallback | `transparent_proxy.rs`, `routing.rs` | Прямое соединение к валидированному исходному DC после неудачных WSS-маршрутов | Проверяется тестами выбора маршрута. Внешняя сеть и Telegram DC не проверялись. |
| Adaptive выбор, latency, cooldown, восстановление | `routing.rs` | `route_plan.c` и `epoll_proxy.c` хранят состояние по DC/media/исходному адресу, предпочитают успешный быстрый маршрут и учитывают cooldown | Синтетические сценарии проходят. Состояние процесса не сохраняется между перезапусками. Успех WSS-маршрута учитывается после полного структурно корректного MTProto transport packet в обратном Obfuscated2 направлении; quick ACK проходит без повышения health. Это не подтверждает конкретный RPC, например `help.getConfig`. |
| Ограниченная гонка WSS-кандидатов | `routing.rs` | Опциональный `TG_WS_ROUTING=hedged`, задержка и общий лимит параллельных гонок; кандидат становится основным после корректного MTProto transport packet | Локальный regression покрывает Abridged, Intermediate и Padded Intermediate, включая транспортное заполнение и quick ACK. Первый кандидат с HTTP 101 и запросом без MTProto-пакета не выигрывает; второй с корректным пакетом повышается. Реальная сеть не проверялась. |
| CF domain pool, встроенные fallback domains, last-known-good | `cf_domain_pool.rs`, `default_domains.rs` | `cf_domains.c`: ручной пул, встроенные domains, проверенный кэш и атомарное обновление списка | Парсер, объединение и кэш покрыты тестами. Обновление из внешнего источника в этой среде не проверялось. |
| DNS и DoH для CF-маршрутов | `cf_proxy_doh.rs` | `route_dns.c`: ограниченный кэш, системное разрешение, HTTPS DoH к Cloudflare и Google, проверка TLS hostname/SNI; DNS выполняет один вспомогательный worker | Формат ответа, кэш и адресные ограничения покрыты тестами. Живые DoH запросы не подтверждены. |
| Диагностика по фазам и машинный вывод | `diagnostics.rs` | `--check-telegram-dc-matrix`, `--discover-telegram-dc-matrix` и `--check-telegram-wss-matrix` последовательно проверяют DC1–DC5 и выдают JSON-строку на каждый; WSS probe включает DNS/TCP/TLS/WS/MTProto и проверяет `resPQ`, одиночные TCP режимы остаются доступны | Живые проверки 2026-10-16: TCP `resPQ`, WSS `resPQ` и `help.getConfig` прошли для всех пяти DC; `this_dc` совпал, `endpoint_count=19`. Диагностика DNS/TLS/WS для direct WSS доступна; детализация CF-маршрутов отсутствует. |
| Runtime counters и панель | `stats.rs` | Unix socket с правами `0600`, счётчики соединений, байтов, WSS попыток/ошибок и CF ответов; C-панель читает и валидирует ответ | Тесты socket/API проходят. RSS, полное состояние каждого маршрута и настоящая доступность Telegram в статусе не показываются. |
| Пределы FD и RAM | `limits.rs` | `limits.c` рассчитывает лимит соединений по FD и памяти; daemon задаёт бюджет 32 MiB, предел 64 клиента и ограничивает WSS/hedge ресурсы | Unit-тесты и ASan/UBSan проходят. RSS idle daemon после запуска со stats socket — 8 352 KiB в WSL, без клиентов; поведение под нагрузкой и на устройстве с 128 MiB не измерялось. |
| Конфигурация и удаление relay client | `config.rs`, `server.rs`, `runtime.rs` | `d2ktg` принимает только `TG_MODE=local`; старые relay URL/secret/enroll ключи не разбираются. Установщик переводит старый `relay` в `local`, сохраняя старые поля с правами `0600` | Тесты конфигурации, панели, release и runtime install проходят. Отдельный `relay-enroll` сервер оставлен для совместимости прежних установок и существующего Meta DNS resolver; новый `d2ktg` к нему не обращается. |
| Keenetic и OpenWrt lifecycle/firewall | OpenWrt integration | Установщик выбирает собственную таблицу nftables для fw4 или iptables для Keenetic/fw3; init, enable/disable и uninstall управляются штатно | Release/OpenWrt/runtime test scripts проходят. Docker lab, физический OpenWrt и Keenetic в этом прогоне недоступны. |
| Сборка, ABI, размер бинарника и регрессии | Makefile, CI, release scripts | `telegram/Makefile` и release cross-build используют явный локальный список исходников; client relay/session/stream/tunnel модули удалены | Native tests, ASan/UBSan и GCC `-fanalyzer` выполнены. Текущий x86_64 dynamic binary: 157 396 байт text+data+bss, ELF с debug symbols — 610 704 байта. Zig 0.16.0 и 0.14.1, проверенные по SHA-256, использованы для кросс-сборки статических релизных бинарников всех 9 архитектур; QEMU подтвердил отсутствие динамических зависимостей и успешный запуск. Под QEMU прошли проверки криптографии, QUIC wire, разбора планов, OpenSSL и MTProto. Размеры бинарника d2ktg после strip: arm64 2 803 240, arm 2 580 216, mipsel 3 917 140, mips 3 920 596, mips64el 4 042 448, amd64 3 950 152, x86 2 606 964, ppc64 3 406 392, riscv64 2 486 480 байт. |

## Результат

Локальный C11 runtime и интеграция больше не запускают прежний relay client.
Direct WSS, CF Worker, CF proxy, TCP fallback, discovery, DoH, пул доменов,
адаптивный выбор и opt-in hedge представлены в коде и имеют локальные тесты.
Успех WSS и hedge проверяется для трёх транспортных форматов.

Полный критерий завершения пока не выполнен. Живые TCP и WSS resPQ, а также
TCP help.getConfig подтверждены для DC1–DC5. Статические релизные бинарники собраны
для всех 9 архитектур и прошли под QEMU проверки ABI, запуска, криптографии,
QUIC wire, разбора планов, OpenSSL и MTProto (размеры приведены в таблице). Реальные Worker/CF маршруты и
DoH запросы, фазовая CF-диагностика и повторяемый дифференциальный тест C/Rust runtime
не проверены. Ресурсные замеры на 128 MiB устройстве и физические
Keenetic/OpenWrt сценарии остались за пределами этого прогона; на роутер
ничего не устанавливалось. WSS-health проверяет структуру transport packet,
а не конкретный RPC.

Для сверенного Rust HEAD выполнен `cargo test --locked --quiet` из временной
архивной копии: 139 unit и 55 integration тестов прошли. Рабочее дерево donor
не менялось. Дополнительно разовая FFI-сверка связала Rust-тесты с текущими
`mtproto_splitter.c` и `mtproto_crypto.c`: две проверки подтвердили совпадение
выходных кадров и отказа на слишком большом пакете. Тестовый стенд хранился
только во временной копии, поэтому повторяемого межъязыкового теста в
репозитории нет.

Для `help.getConfig` C-парсер пропускает корректный `msg_container` только с
управляющими сообщениями `new_session_created` и `msgs_ack`, затем принимает
следующий `rpc_result`.
Нативный набор `make -C telegram BUILD_DIR=build-gcc test d2ktg` прошёл. Живые
матрицы проверяет `python3 telegram/test_live_dc_matrix.py /путь/к/d2ktg`.

Во время установки старые `relay-enroll` endpoint и сервер оставлены: они не
используются новым локальным прокси и позволяют откатиться на прежний
установленный бинарник. Их удаление требует отдельного решения о сроке
совместимости с такими бинарниками.
