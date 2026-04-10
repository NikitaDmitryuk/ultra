# ultra

Один бинарник `ultra-relay` работает в одной из двух ролей из JSON-спецификации (`bridge` или `exit`): внешний узел и внутренний узел с согласованным TLS и HTTP-слоем между ними. Управление пользователями — PostgreSQL-база и HTTP API только на loopback. Маршрутизацию и транспорт обеспечивает встроенное ядро ([Xray-core](https://github.com/XTLS/Xray-core)).

Дополнительно — `ultra-bot`: Telegram-бот с веб-интерфейсом (Mini App) для управления пользователями и мониторинга прямо из мессенджера.

## Состав репозитория

| Пакет / каталог                                | Назначение                                                                                                  |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `internal/mimic`                               | Шаблоны HTTP для внутреннего транспорта (`apijson`, `steamlike`; `plusgaming` — псевдоним `apijson`).      |
| `internal/auth`                                | Управление пользователями: PostgreSQL-бэкенд с кешом, опциональный fallback на JSON-файл.                  |
| `internal/config`                              | Загрузка и валидация spec, сборка конфигурации для встроенного ядра.                                       |
| `internal/proxy`                               | Запуск ядра внутри процесса `ultra-relay`.                                                                  |
| `internal/adminapi`                            | HTTP API только на `admin_listen`: CRUD пользователей, экспорт конфигурации клиента, статистика трафика.   |
| `internal/bot`                                 | Telegram-бот (long polling) + Mini App HTTP-сервер с HMAC-валидацией initData.                             |
| `internal/db`                                  | PostgreSQL: подключение, миграции, репозитории (пользователи, трафик, Telegram-состояние, администраторы). |
| `internal/stats`                               | Сбор статистики трафика через gRPC API встроенного ядра.                                                   |
| `internal/install`, `internal/loglevel`, `internal/realitykey` | Установка по SSH, управление уровнями логов, ключевой материал.                          |
| `cmd/ultra-relay`, `cmd/ultra-install`, `cmd/ultra-bot` | Точки входа бинарников.                                                                          |

## Сборка

```bash
make build               # ./ultra-relay
make build-install       # ./ultra-install
make build-bot           # ./ultra-bot
make build-linux-amd64   # кросс-компиляция для Linux x86-64
make build-bot-linux-amd64
make test
make format
make lint
```

Требуется Go из `go.mod`.

## Установка двух узлов

С машины с **Go**, **ssh**, **scp** и ключом к обоим хостам:

```bash
make install
```

Скрипт собирает `ultra-relay-linux-amd64` для Linux-серверов и `ultra-install` для текущей ОС. На macOS не запускайте `ultra-install-linux-amd64` локально — будет `Exec format error`.

**Цель для внешнего TLS handshake на bridge (`-reality-dest`):** задайте `-reality-dest host:port` при установке, при необходимости — `-reality-sni`. В `install.config` это переменные `REALITY_DEST` / `REALITY_SNI`.

**Неинтерактивно:** скопируйте `install.config.sample` → `install.config` (файл в `.gitignore`), заполните и запустите `make install` или `ULTRA_INSTALL_CONFIG=/path/to/conf make install`.

**Вручную:**

```bash
make build-linux-amd64 build-install
./ultra-install -bridge FRONT -exit BACK -identity ~/.ssh/key \
  -reality-dest 'HOST:443' -reality-sni 'HOST'
```

Флаги: `./ultra-install -h` (включая `-public-host`, `-preset`, `-routing-mode`, `-geosite-block-tags`, `-warp`, `-disable-doh`, `-db-host` и другие).

- [deploy/systemd/ultra-relay.service](deploy/systemd/ultra-relay.service)
- [deploy/bootstrap-bridge.sh](deploy/bootstrap-bridge.sh) / [deploy/bootstrap-exit.sh](deploy/bootstrap-exit.sh)

## Telegram Mini App

`ultra-bot` запускается на bridge-узле и предоставляет веб-интерфейс администратора в Telegram.

**Минимальная конфигурация:**

1. Создать бота: [@BotFather](https://t.me/BotFather) → `/newbot` → скопировать токен.
2. Скопировать `.env.sample` → `.env`, вставить `TELEGRAM_BOT_TOKEN`.
3. Получить домен — см. раздел «[Домен для Mini App](#домен-для-mini-app)» ниже.
4. В `install.config` раскомментировать и заполнить:
   ```
   BOT_ENABLE=y
   BOT_DOMAIN=bot.example.com   # FQDN с DNS A-записью на bridge (обязательно)
   BOT_PORT=8444
   ```
5. Запустить `make install`. В конце будет выведена команда `/start <токен>` — отправить её боту для регистрации первого администратора.

Остальные секреты (`ULTRA_RELAY_ADMIN_TOKEN`, DB DSN) берутся автоматически из `/etc/ultra-relay/environment` и `spec.json` — вручную задавать не нужно.

**Mini App** открывается по кнопке от бота и предоставляет:
- Обзор: количество пользователей и трафик за текущий месяц.
- Список пользователей с трафиком; карточка пользователя с VLESS URI и QR-кодом.
- Добавление и удаление пользователей.
- Генерация инвайт-токенов для новых администраторов.

### Домен для Mini App

Telegram Mini App требует публичного HTTPS-адреса. Сертификат получается автоматически через Let's Encrypt — нужен только домен с DNS A-записью.

**Варианты получения домена:**

| Вариант | Стоимость | Как |
|---------|-----------|-----|
| Платный домен (reg.ru, namecheap и др.) | ~$10–15/год | Зарегистрировать любое доменное имя |
| Бесплатный поддомен [afraid.org](https://freedns.afraid.org/) | Бесплатно | Выбрать поддомен, добавить A-запись на IP bridge |
| Поддомен существующего домена | Бесплатно | Добавить A-запись в уже имеющийся домен |

**После получения домена:**

1. Добавить A-запись в DNS:
   ```
   bot.example.com.  A  <IP bridge-сервера>
   ```
   Проверить: `dig +short bot.example.com` должен вернуть IP bridge-а.

2. Убедиться, что порты открыты на bridge:
   - **80/tcp** — для HTTP-01 ACME challenge (нужен только при выдаче/обновлении сертификата)
   - **8444/tcp** — Mini App HTTPS (или другой `BOT_PORT`)

3. Прописать домен в `install.config` и запустить `make install`.

## SSH

Оркестратор использует `ssh -o BatchMode=yes`: без принятого ключа команды завершатся ошибкой.

По умолчанию — `StrictHostKeyChecking=accept-new`: при **первом** подключении ключ записывается в `known_hosts`. Для строгой модели доверия задайте `ULTRA_INSTALL_SSH_STRICT_HOST_KEY=yes` — хосты должны быть в `known_hosts` заранее.

**Сгенерировать ключ:**

```bash
ssh-keygen -t ed25519 -f ~/.ssh/ultra_relay_ed25519 -C "ultra-relay-deploy"
```

При passphrase: `eval "$(ssh-agent -s)"` и `ssh-add ~/.ssh/ultra_relay_ed25519`.

**Скопировать публичный ключ на серверы:**

```bash
ssh-copy-id -i ~/.ssh/ultra_relay_ed25519.pub root@BRIDGE_IP
ssh-copy-id -i ~/.ssh/ultra_relay_ed25519.pub root@EXIT_IP
```

**Опционально `~/.ssh/config`:**

```sshconfig
Host ultra-front
  HostName BRIDGE_IP
  User root
  IdentityFile ~/.ssh/ultra_relay_ed25519

Host ultra-back
  HostName EXIT_IP
  User root
  IdentityFile ~/.ssh/ultra_relay_ed25519
```

| Симптом                         | Проверка                                                                                             |
| ------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `Permission denied (publickey)` | Ключ в `authorized_keys`, пользователь, путь `-i`.                                                   |
| `Host key verification failed`  | Первый вход: `StrictHostKeyChecking=accept-new`; при смене ключа хоста — правка `known_hosts`.      |

## Spec (`schema_version`)

Конфигурация задаётся JSON-файлом (`-spec`). Поле `schema_version` — сейчас **1**. Поле `tunnel_tls_provision` описывает источник TLS-сертификата на exit для внутреннего канала — см. [deploy/TLS.md](deploy/TLS.md).

**Два независимых сегмента:**

- **Клиент → bridge:** публичный inbound; блок `reality` задаёт параметры TLS для внешних клиентов.
- **Bridge → exit:** межузловой канал; `mimic_preset`, `splithttp_host`, `splithttp_path` определяют HTTP-параметры транспорта.

**Маршрутизация на bridge** (при `split_routing: true`, `domainStrategy: IPIfNonMatch`):

- `routing_mode: blocklist` (по умолчанию) — трафик из `geosite_exit_tags` / `geoip_exit_tags` / `domain_exit` на exit, остальное прямо.
- `routing_mode: ru_direct` — русские домены (`.ru`, `.su`, `.рф`, VK, Яндекс и т.д.) напрямую, остальное на exit. Опционально `geosite_block_tags` → blackhole.

**Обход определения VPN на destination-сайтах:**

- `anti_censor.warp_proxy: true` — на exit использовать Cloudflare WARP в режиме прокси; destination-сайты видят Cloudflare IP вместо IP датацентра.
- `anti_censor.disable_doh: false` (по умолчанию) — DNS over HTTPS; bridge использует Yandex DoH для `.ru`-доменов и Cloudflare для остального.
- Фрагментация TLS ClientHello и паддинг splithttp-чанков включены по умолчанию.

**SOCKS5 на bridge:** блок `socks5` (`enabled`, `port`, `username`, `password`). По умолчанию слушает только `127.0.0.1`. Тот же routing, что у публичного inbound.

**Тонкая настройка:** опциональный объект `xray_wire` в spec задаёт теги, шифрование, sniffing и другие параметры; пустые поля не переопределяют встроенные значения (см. `internal/config/xray_wire_spec.go`).

**Обновление geo-файлов:** `scripts/update-geo-assets.sh <geo_assets_dir>`.

## Loopback API

Admin API на bridge слушает только loopback (`admin_listen` в spec, по умолчанию `127.0.0.1:8443`). Доступ с локальной машины — через SSH port forwarding:

```bash
ssh -L 8443:127.0.0.1:8443 user@BRIDGE_IP
```

**Веб-интерфейс:** [http://127.0.0.1:8443/admin/](http://127.0.0.1:8443/admin/) — вставить `ULTRA_RELAY_ADMIN_TOKEN` (выводится при `make install`, хранится в `/etc/ultra-relay/environment`).

**Локально в dev:** [http://127.0.0.1:18443/admin/](http://127.0.0.1:18443/admin/) (из `examples/spec.bridge.dev.json`).

**curl:**

```bash
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/users
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/users/UUID/client
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/traffic/monthly
```

Ответ `/client` содержит `vless_uri` и `full_xray_config_base64` для запуска Xray-клиента.

## Локальная отладка (`dev_mode`)

1. TLS-материалы для exit (не коммитить):
   ```bash
   cd examples
   openssl req -x509 -newkey rsa:2048 -keyout test-key.pem -out test-cert.pem -days 3650 -nodes \
     -subj "/CN=splithttp.invalid" -addext "subjectAltName=DNS:splithttp.invalid"
   ```
2. Пустой `users.json` (`[]`) и токен `ULTRA_RELAY_ADMIN_TOKEN`.
3. Терминал A — exit: `./ultra-relay -spec examples/spec.exit.dev.json`
4. Терминал B — bridge:
   ```bash
   export ULTRA_RELAY_ADMIN_TOKEN="$(openssl rand -hex 16)"
   ./ultra-relay -spec examples/spec.bridge.dev.json -admin-token "$ULTRA_RELAY_ADMIN_TOKEN"
   ```
5. Для `ultra-bot` в dev-режиме:
   ```bash
   # В .env: TELEGRAM_BOT_TOKEN=... и ULTRA_RELAY_ADMIN_TOKEN=...
   ./ultra-bot -spec examples/spec.bridge.dev.json -dev -port 8080
   ```

## Интеграционная проверка

```bash
VERIFY_IP_URL=https://YOUR_HOST/your-probe-path make verify-relay
# или с явными хостами:
VERIFY_IP_URL=https://api.ipify.org make verify-relay BRIDGE=… EXIT=… IDENTITY=…
```

Скрипт: `scripts/verify-relay.sh -h`. Быстрая проверка TLS-кандидатов: `scripts/probe-tls-sni-candidates.sh`.

## Производительность и перезагрузки

Любое изменение пользователей (через API или Mini App) приводит к **пересборке конфигурации и перезапуску ядра** — активные сессии могут прерваться. При частых правках имеет смысл батчить изменения. Режим `blocklist` с большим `geosite_exit_tags` увеличивает стоимость матчинга; при необходимости сузьте список тегов.

## Логи

```bash
make relay-logs BRIDGE=… EXIT=…
# или через install.config:
make relay-logs
```

Уровень логов: `ULTRA_RELAY_LOG_LEVEL` (в `/etc/ultra-relay/environment`) или флаг `-log-level`.

## Ограничения

- На паре узлов должен совпадать `mimic_preset` и параметры splithttp.
- Смена `splithttp_path` может разорвать существующие сессии между узлами.
- Для Telegram Mini App требуется FQDN с DNS A-записью на bridge и открытый порт 80 (ACME HTTP-01 challenge).
- Поведение зависит от среды; валидируйте spec и TLS на своих площадках.

## Лицензия

См. [LICENSE](LICENSE).
