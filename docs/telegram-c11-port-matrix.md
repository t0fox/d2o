# Матрица порта Telegram proxy: Rust → C11

Аудит кода Telegram-донора выполнен на `z2kOW` `4ef79fb99c30c233488623c04ec13c8097a614e0`.
Текущий `z2kOW/main` — `9fc14bb67c3147b51d6d022575c9bba8f8f9ed2d`, на 10 коммитов
впереди аудита; сравнение подтверждает, что `platform/openwrt/tg-proxy` не менялся
и остаётся на проверенной ревизии `d307c345ed7f7eedf02e52792d0a24bc832fe271`.
Состояние C-кода и интеграции зафиксировано на 2026-10-16. Таблица различает
реализованный код, локальные тесты и сценарии, которые ещё не проверены на
настоящей сети или маршрутизаторе.

| Возможность донора | Источник Rust | Реализация в d2o | Проверка и оставшийся предел |
|---|---|---|---|
| Obfuscated2, AES-256-CTR, DC ID, media flag, transport tags | `crypto.rs` | `mtproto_crypto.c`, `mtproto_auth.c`, `mtproto_auth_keys.inc`; используется локальным прокси | Векторы и тесты проходят. Первый прогон 2026-10-16: прямые TCP и WSS-проверки подтвердили `resPQ` с совпавшим nonce на DC1–DC5. |
| Obfuscated2 handshake, secret и protocol tags | `crypto.rs` | `mtproto_crypto.c` | Differential runner проверяет direct init и secret handshake для normal/media DC1–DC5 во всех трёх transport tags, включая неверный secret; 90 C-парсерных сравнений проходят. Случайные handshake сравниваются по protocol invariants. |
| Abridged, intermediate и padded intermediate; разбиение пакетов | `splitter.rs` | `mtproto_splitter.c`; для direct WSS и CF proxy сохраняются MTProto-границы, Worker использует потоковый режим | `telegram/differential/run.py` на текущем Rust HEAD `9fc14bb` сравнивает несколько пакетов, произвольные границы чтений, CTR, raw mode, EOF flush и oversize на 144 воспроизводимых сценариях; расхождений нет. Это не сверяет полный runtime и выбор маршрутов. |
| WebSocket binary/text, управляющие кадры и фрагментация сообщений | `ws_client.rs`, `bridge.rs`, Tungstenite 0.24 | `tg_ws_reassembly_feed` собирает сообщения в событийном `tg_ws_pump`; ping/pong обрабатываются между фрагментами, соблюдаются лимит сообщения и UTF-8 для text/close | Сверка C/Rust охватывает 44 сценария: частичные чтения, длины 125/126/65535/65536, фрагменты, ping/pong, неверный порядок, UTF-8 и превышение 4 МиБ. TLS-регрессионный тест проверяет сборку фрагментированного binary-сообщения с ping между кадрами и отказ pump от text-сообщения. Живая WSS-сеть здесь не участвует. |
| Исходное назначение, IPv4/IPv6, разрешение Telegram DC | `transparent.rs`, `transparent_proxy.rs` | `listener.c` читает IPv4/IPv6 `SO_ORIGINAL_DST`; `transparent.c` проверяет DC-карту, порт, CIDR и защиту от собственного dial | Парсер и политика покрыты тестами. Kernel REDIRECT для IPv6 и фактический трафик на роутере не проверялись. |
| TCP bridge, backpressure, закрытие и тайм-ауты | `transparent_proxy.rs`, `bridge.rs` | Linux `epoll` runtime, ограниченные очереди, неблокирующий TLS, WSS ping/pong/close, idle и handshake deadlines | Локальные тесты epoll, WSS и лимитов проходят. Стресс-тест на целевом роутере отсутствует. |
| DC discovery, проверка `req_pq_multi/resPQ`, auth и `help.getConfig` | `dc_discovery.rs` | `mtproto_probe.c`, `mtproto_auth.c`, `mtproto_config.c`; демон обновляет карту через IPv4/IPv6 seed DC1, сохраняет LKG и повторяет неудачу позже | Парсеры и криптография покрыты векторами. Differential runner сверяет C/Rust выбор DC и причины отказа на 116 сценариях: все 33 встроенных IPv4 адреса, media/DC подсказки и синтетические официальные `dcOption` для TCP-only порта, CDN, IPv6, неоднозначности и неизвестных адресов. C дополнительно содержит пять встроенных IPv6 fallback адресов, отсутствующих в Rust `DEFAULT_DC_ROUTES`; официальный IPv6 путь сравнивается. Одиночный CLI проверяет указанный IP; `--check-telegram-dc-matrix` и `--discover-telegram-dc-matrix` проверяют DC1–DC5. Первый прогон 2026-10-16: все пять TCP-проверок дошли до `resPQ`, а `help.getConfig` вернул совпавший `this_dc` и 19 endpoints. |
| Прямой Telegram WSS `kwsN.web.telegram.org/apiws` | `ws_client.rs`, `routing.rs` | Direct WSS для DC1–DC5, TLS hostname/SNI и проверка сертификата; при сбое до WebSocket Upgrade маршрут меняется дальше по плану | Локальные тесты проходят. `--check-telegram-wss-matrix [CA_BUNDLE]` различает DNS/TCP/TLS/WS/MTProto и проверяет `resPQ` с nonce. 2026-10-16 все `kws1`–`kws5` вернули `resPQ`. В `files/tg-roots.pem` добавлен [официальный Go Daddy Root G2](https://certs.godaddy.com/repository/?lang=ENU) (SHA-256 `45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA`), потому что текущая цепочка Telegram WSS заканчивается на нём. |
| Cloudflare Worker на пользовательском домене | `routing.rs`, `bridge.rs` | `TG_CF_WORKER_DOMAIN`; проверенный TLS, настраиваемый Worker path, потоковый framing | План и transport mocks покрыты. Живой Worker/domain не проверен. |
| Резервный CF WebSocket proxy | `routing.rs`, `cf_proxy_doh.rs` | `TG_CF_DOMAIN`; WSS с MTProto packet framing и ограниченным пулом доменов | Локальные тесты плана, DNS и пула проходят. Встроенный пул и его обновление теперь включены по умолчанию; `TG_DEFAULT_DOMAINS=0` отключает их. На роутере ранее все 20 доменов списка вернули NXDOMAIN через Cloudflare DoH; актуальный список и живой CF-маршрут после обновления ещё не проверены. |
| TCP fallback | `transparent_proxy.rs`, `routing.rs` | Прямое соединение к валидированному исходному DC после неудачных WSS-маршрутов | Проверяется тестами выбора маршрута. Внешняя сеть и Telegram DC не проверялись. |
| Adaptive выбор, latency, cooldown, восстановление | `routing.rs` | `route_plan.c` и `epoll_proxy.c` хранят состояние по DC/media/исходному адресу, предпочитают успешный быстрый маршрут и учитывают cooldown | Локальные fake-route тесты проходят: WSS `101` без MTProto ответа и прерванный кадр помечают маршрут неуспешным; DNS и ошибка сертификата не дают ложного успеха; доступны TCP fallback и следующий WSS-кандидат; проверено восстановление после cooldown, отключение во время handshake, отказ всех маршрутов и 16 одновременных TCP-клиентов с возвратом числа FD к исходному уровню. Для ускоренного теста cooldown равен 1 секунде; runtime по умолчанию сохраняет 30 секунд. Состояние процесса не сохраняется между перезапусками. WSS health учитывает полный структурно корректный MTProto transport packet в обратном Obfuscated2 направлении; quick ACK не повышает health. Это не подтверждает конкретный RPC, например `help.getConfig`. |
| Ограниченная гонка WSS-кандидатов | `routing.rs` | Опциональный `TG_WS_ROUTING=hedged`, задержка и общий лимит параллельных гонок; кандидат становится основным после корректного MTProto transport packet | Локальный regression покрывает Abridged, Intermediate и Padded Intermediate, включая транспортное заполнение и quick ACK. Первый кандидат с HTTP 101 и запросом без MTProto-пакета не выигрывает; второй с корректным пакетом повышается. Реальная сеть не проверялась. |
| CF domain pool, встроенные fallback domains, last-known-good | `cf_domain_pool.rs`, `default_domains.rs` | `cf_domains.c`: ручной пул, встроенные domains, проверенный кэш и атомарное обновление списка; пул и автообновление включены по умолчанию, явный opt-out — `TG_DEFAULT_DOMAINS=0` | Парсер, объединение, кэш и выбор opt-out покрыты тестами. После включения на роутере требуется проверить, что обновлённый список содержит доступные домены. |
| DNS и DoH для CF-маршрутов | `cf_proxy_doh.rs` | `route_dns.c`: ограниченный кэш, системное разрешение, HTTPS DoH к Cloudflare и Google, проверка TLS hostname/SNI; DNS выполняет один вспомогательный worker | Живые DoH проверки 2026-10-16 вызвали production `tg_route_dns_https_request`: TLS-проверка имени, HTTPS POST и разбор DNS прошли для Cloudflare и Google; каждый вернул 2 публичных адреса. При принудительном отказе системного `getaddrinfo` production fallback вернул 4 адреса. Добавлены корни SSL.com ECC (SHA-256 `34:17:BB:06:CC:60:07:DA:1B:96:1C:92:0B:8A:B4:CE:3F:AD:82:0E:4A:A3:0B:9A:CB:C4:A7:4E:BD:CE:BC:65`) и GTS Root R4 (SHA-256 `34:9D:FA:40:58:C5:E2:63:12:3B:39:8A:E7:95:57:3C:4E:13:13:C8:3F:E6:8F:93:55:6C:D5:E8:03:1B:3C:7D`) сверены с официальными [SSL.com](https://www.ssl.com/repository/) и [Google Trust Services](https://pki.goog/repository/); обе TLS-цепочки проверены с `files/tg-roots.pem`. Проверено в WSL, не на роутере. |
| Диагностика по фазам и машинный вывод | `diagnostics.rs` | `--check-telegram-dc-matrix`, `--discover-telegram-dc-matrix` и `--check-telegram-wss-matrix` последовательно проверяют DC1–DC5 и выдают JSON-строку на каждый; WSS probe включает DNS/TCP/TLS/WS/MTProto и проверяет `resPQ`, одиночные TCP режимы остаются доступны | Первый живой прогон 2026-10-16: TCP `resPQ`, WSS `resPQ` и `help.getConfig` прошли для всех пяти DC; `this_dc` совпал, `endpoint_count=19`. Диагностика DNS/TLS/WS для direct WSS доступна; детализация CF-маршрутов отсутствует. |
| Runtime counters и панель | `stats.rs` | Unix socket с правами `0600`, счётчики соединений, байтов, WSS попыток/ошибок и CF ответов; C-панель читает и валидирует ответ | Тесты socket/API проходят. RSS, полное состояние каждого маршрута и настоящая доступность Telegram в статусе не показываются. |
| Пределы FD и RAM | `limits.rs` | `limits.c` рассчитывает лимит соединений по FD и памяти; daemon задаёт бюджет 32 MiB, предел 64 клиента и ограничивает WSS/hedge ресурсы; бюджет WSS учитывает дополнительный буфер reassembly до 4 МиБ | Unit-тесты и ASan/UBSan проходят. RSS idle daemon после запуска со stats socket — 8 352 KiB в WSL, без клиентов; поведение под нагрузкой и на устройстве с 128 MiB не измерялось. |
| Конфигурация и удаление relay client | `config.rs`, `server.rs`, `runtime.rs` | `d2ktg` принимает только `TG_MODE=local`; старые relay URL/secret/enroll ключи не разбираются. Установщик переводит старый `relay` в `local`, сохраняя старые поля с правами `0600` | Тесты конфигурации, панели, release и runtime install проходят. Отдельный `relay-enroll` сервер оставлен для совместимости прежних установок и существующего Meta DNS resolver; новый `d2ktg` к нему не обращается. |
| Keenetic и OpenWrt lifecycle/firewall | OpenWrt integration | Установщик выбирает собственную таблицу nftables для fw4 или iptables для Keenetic/fw3; init, enable/disable и uninstall управляются штатно. Watchdog проверяет локальный heartbeat `d2ktg`, не внешний HTTPS-сайт; для исправления правил перехватываются Telegram TCP/443 и TCP/5222 | Release/OpenWrt/runtime test scripts и отдельный тест heartbeat проходят. Docker lab не запускалась, так как Docker недоступен. На физическом Cudy WBR3000UAX v1 с OpenWrt 25.12.5 прочитана старая установка `d2o-20261016-1721-5a3a4ec`: watchdog обращался к `core.telegram.org` и перезапускал прокси примерно каждые 3 минуты; старые правила не включали TCP/5222. Исправленный код пока не установлен; роутер не изменялся. |
| Сборка, ABI, размер бинарника и регрессии | Makefile, CI, release scripts | `telegram/Makefile` и release cross-build используют явный локальный список исходников; client relay/session/stream/tunnel модули удалены | Native tests, ASan/UBSan и GCC `-fanalyzer` выполнены. Текущий x86_64 dynamic binary: 157 396 байт text+data+bss, ELF с debug symbols — 610 704 байта. Zig 0.16.0 и 0.14.1, проверенные по SHA-256, использованы для кросс-сборки статических релизных бинарников всех 9 архитектур; QEMU подтвердил отсутствие динамических зависимостей и успешный запуск. Под QEMU прошли проверки криптографии, QUIC wire, разбора планов, OpenSSL и MTProto. Размеры бинарника d2ktg после strip: arm64 2 803 240, arm 2 580 216, mipsel 3 917 140, mips 3 920 596, mips64el 4 042 448, amd64 3 950 152, x86 2 606 964, ppc64 3 406 392, riscv64 2 486 480 байт. Дополнительное native-сравнение на x86_64 WSL: чистый C HEAD `3623dfc` с `-O2 -DNDEBUG` после `strip` — 167 464 байта (text+data+bss 157 658; OpenSSL 3 и zlib подключены динамически); Rust donor `4ef79fb`, `cargo build --release --locked` — 4 942 048 байт (секции 4 942 013; Rustls/ring входят в бинарник, динамические зависимости — libc, libgcc и libm). Rust бинарник больше в 29,5 раза по размеру файла; профили оптимизации и связывания различаются, поэтому это только сравнение артефактов, не производительности или RSS. |

## Результат

Локальный C11 runtime и интеграция больше не запускают прежний relay client.
Direct WSS, CF Worker, CF proxy, TCP fallback, discovery, DoH, пул доменов,
адаптивный выбор и opt-in hedge представлены в коде и имеют локальные тесты.
Успех WSS и hedge проверяется для трёх транспортных форматов.

Полный критерий завершения пока не выполнен. Первый живой прогон подтвердил
прямые TCP и WSS `resPQ` на DC1–DC5; TCP `help.getConfig` вернул совпавший
`this_dc` и 19 endpoints. Живые DoH-запросы Cloudflare и Google прошли через
production C-код: проверка TLS-имени, HTTPS POST, разбор DNS-ответа и
fallback после отказа системного `getaddrinfo`.

Позднее на текущем роутере read-only проверка установленной старой версии
показала отсутствие подтверждённого Telegram-трафика: в одном снимке было
64/64 активных слота, около 15 КБ принятых клиентских данных и 0 байт от
upstream; WSS завершался ошибками до ответа Telegram. Старые диагностические
сокеты также не имели `SO_MARK=0x31` и могли попадать под локальный redirect.
В коде исправлены TCP/5222, маркировка диагностических сокетов и watchdog.
Это не проверяет реальный клиентский трафик с новым бинарником; роутер не
обновлялся.

Повторная проверка 16.10.2026: прямой WSS вернул корректный `resPQ` на
DC1–DC5 (938, 396, 889, 392 и 1110 мс). Повторный прямой TCP вернул `resPQ`
на DC2, DC4 и DC5; DC1 завершился `timeout` через 8 с на стадии `MTProto`,
DC3 — `io_error` через 5 с на той же стадии после успешного TCP-соединения.
CLI не показывает системный вызов для `io_error`, поэтому результаты не
доказывают блокировку провайдером.

Релизные бинарники собраны для всех 9 архитектур и прошли под QEMU проверки
ABI, запуска, криптографии, QUIC wire, разбора планов, OpenSSL и MTProto
(размеры приведены в таблице). Живые маршруты CF Worker/CF Proxy не
проверены: пользовательских тестовых доменов нет, а все 20 доменов штатного
списка CF Proxy через Cloudflare DoH вернули NXDOMAIN. Дифференциальные тесты
сравнивают MTProto framing, Obfuscated2, выбор DC и парсер WebSocket; полного
сравнения bridge, переключения маршрутов и TLS runtime между языками пока нет.

Полный набор `make test` для Telegram проходит после добавления
`src/ws_pump.c` к цели `test-ws`. Артефакты сборки создавались в `/tmp`;
`telegram/build-san/` не затрагивался. Нагрузка на устройстве с 128 MiB и
сценарии на физическом Keenetic/OpenWrt не проверялись; на роутер ничего не
устанавливалось. WSS-проверка подтверждает структуру transport-пакета
`MTProto`, но не доступность конкретного RPC.

Для сверенного Rust HEAD выполнен `cargo test --locked --quiet` из временной
архивной копии: 139 unit и 55 integration тестов прошли. Рабочее дерево donor
не менялось. Повторяемый `telegram/differential/run.py` закрепляет донорский
Rust SHA и собирает временный runner рядом с неизменённой копией донора. Он
сравнивает `splitter.rs`/`crypto.rs` с `mtproto_splitter.c`/`mtproto_crypto.c`
на 144 framing-сценариях и 90 проверках Obfuscated2, а `dc_map.rs`/C
`tg_dc_resolve` — на 116 сценариях карты DC; текущая проверка прошла без
расхождений. Сверка остальных перечисленных выше runtime-функций и выбора либо
переключения сетевых маршрутов ещё не реализована.

Для `help.getConfig` C-парсер пропускает корректный `msg_container` только с
управляющими сообщениями `new_session_created` и `msgs_ack`, затем принимает
следующий `rpc_result`.
Нативный набор `make -C telegram BUILD_DIR=build-gcc test d2ktg` прошёл. Живые
матрицы проверяет `python3 telegram/test_live_dc_matrix.py /путь/к/d2ktg`.

Во время установки старые `relay-enroll` endpoint и сервер оставлены: они не
используются новым локальным прокси и позволяют откатиться на прежний
установленный бинарник. Их удаление требует отдельного решения о сроке
совместимости с такими бинарниками.

Локальная панель показывает последний DC и маршрут с валидным MTProto-ответом,
задержку и возраст события, а также этап последней ошибки реальной WSS-попытки.
Один только WebSocket Upgrade не считается подтверждением доступности Telegram;
ошибки DNS до начала WSS-попытки в этой статистике не учитываются.
