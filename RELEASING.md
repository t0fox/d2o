# Релизы D2O в t0fox/d2o

d2o использует схему CI/CD оригинального d2k: статические проверки,
unit-тесты, ASan/UBSan, интеграция, панель в Chrome и сборка на девяти
архитектурах. Дополнительный job сверяет Telegram C11 и Rust по тестовым
векторам. Общий gate: `CI passed`. Подписанный релиз запускается отдельно
вручную после успешного CI и публикуется только после проверки под QEMU.

## Первый выпуск: настроить подпись

Закрытый ключ d2o — отдельный от d2k. Публичный ключ закреплён
в [scripts/install.sh](scripts/install.sh),
[files/d2k-update.sh](files/d2k-update.sh) и
[docs/d2o-release-public.pem](docs/d2o-release-public.pem).

1. GitHub → **Settings → Environments** → **New environment**:
   `d2o-signing`. Разрешите ветку `main`, при необходимости настройте
   Required reviewers.
2. В этом environment добавьте **Secret**
   `D2O_ED25519_PRIVATE_KEY` — всё содержимое личного PEM-файла
   с приватным Ed25519 ключом d2o. **Никогда не коммитьте его**.
3. Проверьте **Settings → Actions → General**, что Actions разрешены.
   Workflow запрашивает `contents: write` только в job `publish`.

Workflow берёт публичный ключ из `docs/d2o-release-public.pem` и сверяет его
с ключами, закреплёнными в установщиках. Приватный ключ обязан ему
соответствовать: публикация откажет при любом рассогласовании. Секрет исходного
d2k для подписания d2o применять нельзя.

## Как запустить первый релиз

Откройте [Actions](https://github.com/t0fox/d2o/actions), запустите
**CI** → **Run workflow** → `main` и дождитесь успешного `CI passed`.
Затем откройте **D2O release** → **Run workflow** → `main`.
Текст notes можно оставить пустым: он формируется из коммитов после последней метки.

Каждый push запускает CI, но не сборку релиза. Когда выпуск готов, запустите
**D2O release** вручную на `main`; workflow проверит успешный `CI passed`
именно для текущего коммита. Повторно тот же commit SHA не выпускается.

`plan` создаёт тег `d2o-YYYYmmdd-HHMM-<sha>`.
Заголовок GitHub-релиза: `D2O DD.MM.YYYY (sha)`, например `D2O 15.10.2026 (1bd394e)`.
`build` запускает девять
независимых архитектур (arm64, arm, mipsel, mips, mips64el, amd64, x86,
ppc64, riscv64) с проверками QEMU. `publish` сверяет HEAD main,
проверяет ключ, упаковывает `latest.json` с SHA-256 и подписывает
его Ed25519 в `latest.json.sig`. Релиз сначала черновик, потом
публичный latest со всеми файлами. Устаревший build не публикуется.

Названия исполняемых файлов и архивов остаются `d2kd`, `d2kc`,
`d2kpanel`, `d2ktg`, `d2k-<arch>.tar.gz`: они нужны текущему
установщику. GitHub-теги имеют префикс `d2o-`, репозиторий — `t0fox/d2o`.

## Установка подписанного релиза

После публикации:

```sh
curl -fsSL https://raw.githubusercontent.com/t0fox/d2o/main/scripts/install.sh -o /tmp/d2o-install.sh
sh /tmp/d2o-install.sh
rm -f /tmp/d2o-install.sh
```

Установщик по умолчанию получает `latest.json` из `t0fox/d2o`,
проверяет подпись публичным ключом d2o, сравнивает SHA-256 архива и
устанавливает свою архитектуру. Обновлятор работает через ту же цепочку,
сохраняет конфигурацию и выполняет откат при ошибке health-check.

`D2K_SOURCE=ref` — режим разработки **без** подписанной цепочки: сборки
в `builds/` могут отличаться от исходников ветки. Для обычных
пользователей используйте только релизы.

## Проверки

```sh
sh scripts/check.sh
sh scripts/test-release-plan.sh
node scripts/test-update.cjs
sh scripts/test-install-manifest.sh
curl -fsSL https://github.com/t0fox/d2o/releases/latest/download/latest.json
```

Последняя команда сработает только после первой публикации. Тесты CI/QEMU
не равнозначны полевым тестам на физических Keenetic и OpenWrt.
Логи установки/обновлений на роутере: `/opt/d2k/log/update.log`.
