# Дифференциальная проверка MTProto framing

Запусти из корня `d2o`:

```sh
python3 telegram/differential/run.py
```

Нужны Python 3.11+, `git`, C11-компилятор, OpenSSL headers/libraries, `cargo` и
`rustup`. Скрипт загружает `t0fox/z2kOW`, проверяет точный донорский commit
`4ef79fb99c30c233488623c04ec13c8097a614e0`, извлекает только
`platform/openwrt/tg-proxy` во временный каталог и добавляет туда временный
Rust runner. Исходники донора не изменяются. Для локального клона можно передать
`--donor-repo /путь/к/z2kOW`.

Оба runner получают один детерминированный corpus. Результаты сравниваются
побайтно. 144 сценария проверяют Abridged, Intermediate и Padded Intermediate,
несколько пакетов в потоке, произвольное разбиение входа на чтения, потоковый
AES-256-CTR, raw mode, неполный пакет на EOF и отклонение пакета больше 4 МиБ.
Seed генератора закреплён в `run.py`.

Дополнительно Rust создаёт 30 secret Obfuscated2 handshakes для normal/media
DC1–DC5 и трёх transport tags; C сверяет поля через `tg_mtproto_parse_secret`
и отклонение неверного secret. Ещё 30 Rust direct init проверяются через
`tg_mtproto_parse_obfuscated2`. Генерируемые handshake содержат случайные
байты; сравниваются проверяемые протоколом инварианты, а не сами случайные
пакеты. Всего C/Rust прогоняет 90 сравнений handshake.

Это повторяемая сверка handshake, framing и CTR. Она не утверждает
эквивалентность полного runtime, выбора маршрута, TCP/TLS/WebSocket или
жизненного цикла соединений.
