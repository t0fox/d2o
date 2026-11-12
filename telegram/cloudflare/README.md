# Cloudflare Worker для Telegram

В стандартном Worker Flowseal `/apiws?dst=<IP>` открывает TCP 443.
Существующий Worker подходит для обычного Telegram и медиа через D2O.
Расширенный Worker D2O обслуживает тот же API на 443 и добавляет
`/d2o/apiws/5222`. Он отвечает на запрос 5222 с подпротоколом
`d2o-tcp-5222-v1` только после успешного открытия TCP 5222 к указанному IP.
При отказе D2O показывает сбой маршрута в панели.

## Установка

1. В Cloudflare откройте **Workers & Pages → Create application** и создайте
   отдельный Worker. В **Edit code** вставьте целиком [worker.js](worker.js).
2. Нажмите **Deploy**. Для 5222 добавьте в **Settings → Variables and Secrets**
   текстовую переменную `D2O_TG_5222_TARGETS` и примените изменения.
   Значение — список точных IP разрешённых DC через запятую. Возьмите адреса
   из подтверждённой карты `/opt/d2k/state/telegram-dc-map.json` и сверяйте
   исходный порт 5222. IPv6 пишите без квадратных скобок.
   С пустым списком 5222 отключён.
3. Скопируйте hostname `<worker>.<account>.workers.dev` и добавьте его через
   **Telegram → Мои Workers → Добавить домен → Сохранить** в панели D2O.
   Существующие домены Flowseal можно оставить в списке.

На 443 Worker D2O разрешает IP из подсетей Telegram, известных D2O. Для
дополнительных адресов из подтверждённой карты можно задать точные IP в
`D2O_TG_443_TARGETS`. Обе переменные принимают IPv4 и IPv6. Допуск 5222
проверяется отдельно для каждого IP.

Для диагностики обычного маршрута и обновления карты DC на роутере запустите
`/opt/sbin/d2ktg --check-telegram-dc-map /opt/d2k/config`. Для проверки 5222
нужно воспроизвести соединение Telegram с исходным портом 5222 и сверить
маршрут и ответ MTProto в панели. Если Worker D2O не подтвердил TCP 5222,
проверьте IP в списке `D2O_TG_5222_TARGETS` и его доступность из Cloudflare.

## Проверка скачанного архива

Подпись Ed25519 над `latest.json` покрывает SHA-256
`d2k-telegram-worker.tar.gz` в поле `telegram_worker.sha256`. Используйте
публичный ключ из [репозитория D2O](https://github.com/t0fox/d2o/blob/main/docs/d2o-release-public.pem).

```sh
openssl pkeyutl -verify -pubin -inkey d2o-release-public.pem -rawin \
  -in latest.json -sigfile latest.json.sig
sha256sum d2k-telegram-worker.tar.gz
```

Сверьте выведенный SHA-256 с `telegram_worker.sha256` в проверенном манифесте.
