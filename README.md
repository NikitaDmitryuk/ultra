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
| `internal/adminapi`                            | HTTP API только на `admin_listen`: CRUD пользователей и exit-нод, health/failover, экспорт клиента, статистика. |
| `internal/bot`                                 | Telegram-бот (long polling) + Mini App HTTP-сервер с HMAC-валидацией initData.                             |
| `internal/db`                                  | PostgreSQL: пользователи, **exit-ноды** (failover), трафик, Telegram-состояние, администраторы.            |
| `internal/exits`                               | Выбор active exit по priority и health, probe worker для failover.                                          |
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

Флаги: `./ultra-install -h` (включая `-public-host`, `-preset`, `-routing-mode`, `-exit-only`, `-tunnel-uuid`, `-warp`, `-disable-doh`, `-db-host` и другие).

- [deploy/systemd/ultra-relay.service](deploy/systemd/ultra-relay.service)
- [deploy/bootstrap-bridge.sh](deploy/bootstrap-bridge.sh) / [deploy/bootstrap-exit.sh](deploy/bootstrap-exit.sh)

## Несколько exit-нод (failover)

При `make install` можно сразу поставить **две exit VPS** (primary + backup): в `install.config` укажите `EXIT` и `EXIT2` (см. `install.config.sample`). Установщик развернёт доступные ноды, сгенерирует отдельный `tunnel_uuid` для каждой и положит на bridge `exit_nodes.bootstrap.json` — при первом старте строки импортируются в PostgreSQL. Exit, недоступные по SSH, попадают в bootstrap с **`enabled: false`** (не маршрутизируются, пока не задеployed и не включены в Mini App). Backup обычно с `EXIT2_PRIORITY=200`, primary — `100`. Недоступные exit **не блокируют** установку, если хотя бы одна exit задеployed; иначе `ultra-install` завершится с ошибкой.

| Где хранится | Что |
|--------------|-----|
| PostgreSQL `exit_nodes` | Список exit: address, port, `tunnel_uuid`, **priority** (меньше = primary), enabled |
| `exit_nodes.bootstrap.json` на bridge | Bootstrap при первом старте (импорт в БД; fallback — `spec.exit`) |
| Exit `spec.json` на каждом VPS | Свой `exit.tunnel_uuid`, общие `mimic_preset`, `splithttp_*`, transport |

**Failover:** bridge каждые ~30 с проверяет TCP-доступность enabled exit и выбирает active с минимальным `priority` среди reachable. При смене active — перезагрузка Xray на bridge (краткий разрыв сессий). Клиенты по-прежнему подключаются только к bridge; выбор exit прозрачен.

### Добавить или заменить exit VPS

1. Обновить bridge до версии с поддержкой multi-exit (`make install` или замена бинарника + restart).
2. **Mini App → Настройки → Exit-ноды** → «Добавить exit» (имя, адрес dial с bridge, порт, priority).
3. Скопировать **`tunnel_uuid`** и команду из блока Deploy в ответе API.
4. С локальной машины (Go, ssh, scp):
   ```bash
   make build-linux-amd64 build-install
   ./ultra-install -exit-only -bridge BRIDGE_IP -exit NEW_EXIT_IP \
     -identity ~/.ssh/key -tunnel-uuid 'UUID-ИЗ-API'
   ```
   Общие параметры туннеля (`splithttp_path`, `mimic_preset`, `TRANSPORT`, `TUNNEL_PORT`) читаются с bridge `spec.json`. Флаг `-dry-run` печатает exit spec без SSH.
5. Старую exit отключить или удалить в Mini App. Backup обычно с `priority=200`, primary — `100`.

**Admin API** (loopback, Bearer token): `GET/POST /v1/exits`, `PATCH/DELETE /v1/exits/{id}`, расширенный `GET /v1/health` (`exits[]`, `active_exit_id`). POST `/v1/exits` возвращает `deploy.install_example`.

Telegram-алерты: `exit_down` / `exit_up` (по active exit), `exit_failover` при переключении active.

## Telegram Mini App

`ultra-bot` запускается на bridge-узле и предоставляет веб-интерфейс администратора в Telegram.

**Минимальная конфигурация:**

1. Создать бота: [@BotFather](https://t.me/BotFather) → `/newbot` → скопировать токен.
2. **Обязательно:** скопировать `.env.sample` → `.env` и вставить `TELEGRAM_BOT_TOKEN` (без этого `make install` завершится ошибкой при `BOT_ENABLE=y`).
3. Получить домен — см. раздел «[Домен для Mini App](#домен-для-mini-app)» ниже.
4. В `install.config` раскомментировать и заполнить:
   ```
   BOT_ENABLE=y
   BOT_DOMAIN=bot.example.com   # FQDN; DNS A-запись на bridge
   BOT_PORT=8444
   ```
5. Запустить `make install`. В конце будет выведена команда `/start <токен>` — отправить её боту для регистрации первого администратора.

Остальные секреты (`ULTRA_RELAY_ADMIN_TOKEN`, DB DSN) берутся автоматически из `/etc/ultra-relay/environment` и `spec.json` — вручную задавать не нужно.

Long polling и алерты к `api.telegram.org` с bridge идут через локальный SOCKS5 (`127.0.0.1:10809`) в Xray и далее на **active exit** (с тем же failover, что и VPN-трафик).

**Mini App** открывается по кнопке от бота и предоставляет:
- Обзор: количество пользователей, трафик, состояние bridge и **active exit**.
- Список пользователей с трафиком; карточка пользователя с VLESS URI и QR-кодом.
- Добавление и удаление пользователей.
- **Exit-ноды:** список, добавление backup/новой exit, enable/disable, deploy-команда.
- Диагностика: health по узлам, последние алерты.
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

1. Добавить A-запись в DNS (**на IP bridge**, не на exit):

   ```
   bot.example.com.  A  <IP bridge-сервера>
   ```

   **Важно:** A-запись должна указывать на **bridge** (где крутится `ultra-bot`), а не на exit VPS. Если домен указывает на exit — Mini App в Telegram выдаст `ERR_TIMED_OUT`.

   Проверить: `dig +short bot.example.com` → IP bridge. Или `make verify-miniapp`.

2. Убедиться, что порты открыты на bridge:
   - **80/tcp** — для HTTP-01 ACME challenge (нужен только при выдаче/обновлении сертификата)
   - **8444/tcp** — Mini App HTTPS (или другой `BOT_PORT`)

3. Прописать домен в `install.config` и запустить `make install`.

4. В [@BotFather](https://t.me/BotFather): Bot Settings → Menu Button (или Web App URL) = `https://bot.example.com:8444/` — **точно** как в `BOT_DOMAIN` и `BOT_PORT`.

5. На мобильных сетях РФ надёжнее `BOT_PORT=443` (reverse proxy на bridge); по умолчанию 8444.

## SSH

Оркестратор использует `ssh -o BatchMode=yes`: без принятого ключа команды завершатся ошибкой.

Таймаут подключения SSH: `ULTRA_SSH_CONNECT_TIMEOUT` (секунды, по умолчанию **10**) — для `ultra-install`, `make install` и `make relay-logs`. Недоступные exit пропускаются с WARNING; bridge обязателен.

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
- **Bridge → exit:** межузловой канал; `tunnel_transport: splithttp` (XHTTP stream-up H2, по умолчанию) или устаревший `grpc`. Параметры HTTP: `mimic_preset`, `splithttp_host`, `splithttp_path`. На bridge блок `exit` в spec — **legacy/bootstrap**; рабочий список upstream — таблица `exit_nodes` в PostgreSQL (см. [несколько exit-нод](#несколько-exit-нод-failover)). На каждой exit VPS свой `exit.tunnel_uuid`.
- **Клиент → bridge (REALITY):** по умолчанию `vless_flow: xtls-rprx-vision` (Xray 26). После смены flow пользователи должны **переимпортировать** подписку из Mini App. Отключение: `DISABLE_VLESS_FLOW=y` в `install.config`. Внутренний туннель bridge→exit по-прежнему без flow (ограничение Xray; предупреждения в логах exit допустимы).

**Маршрутизация на bridge** (при `split_routing: true`, `domainStrategy: IPIfNonMatch`):

- `routing_mode: blocklist` (по умолчанию) — трафик из `geosite_exit_tags` / `geoip_exit_tags` / `domain_exit` на exit, остальное прямо.
- `routing_mode: ru_direct` — русские домены (`.ru`, `.su`, `.рф`, VK, Яндекс и т.д.) напрямую, остальное на exit. Опционально `geosite_block_tags` → blackhole.

**Параметры протокола:**

- `anti_censor.warp_proxy: true` — на exit использовать Cloudflare WARP в режиме прокси; destination-сайты видят Cloudflare IP вместо IP датацентра.
- `anti_censor.disable_doh: false` (по умолчанию) — DNS over HTTPS; bridge использует Yandex DoH для `.ru`-доменов и Cloudflare для остального.
- Фрагментация TLS ClientHello и паддинг splithttp-чанков включены по умолчанию.

**SOCKS5 на bridge:** два режима — (1) общий inbound в spec (`socks5.enabled`, по умолчанию `127.0.0.1`); (2) **per-user** `kind=socks5` в Admin API / Mini App — отдельный порт из диапазона **10810–10899**, логин = UUID, пароль в карточке пользователя (`socks5://…` в UI). Оба используют тот же routing, что VLESS. Per-user порты слушают `0.0.0.0`; откройте нужный TCP в security group. На мобильных сетях нестандартные порты (108xx, 8444) могут блокироваться — для Telegram in-app proxy или Mini App надёжнее `:443` или системный VPN (HAPP).

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
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/exits
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/health
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
make verify-miniapp   # DNS A → bridge и HTTPS Mini App (нужны BOT_DOMAIN, BOT_ENABLE в install.config)
```

Скрипты: `scripts/verify-relay.sh -h`, `scripts/verify-miniapp.sh`. Быстрая проверка TLS-кандидатов: `scripts/probe-tls-sni-candidates.sh`.

## Производительность и перезагрузки

Любое изменение **пользователей** или **exit-нод** (через API или Mini App), а также **failover** на другую exit приводит к пересборке конфигурации и перезапуску ядра на bridge — активные сессии могут прерваться. При частых правках имеет смысл батчить изменения. Режим `blocklist` с большим `geosite_exit_tags` увеличивает стоимость матчинга; при необходимости сузьте список тегов.

## Логи

```bash
make relay-logs
# или явно: make relay-logs BRIDGE=… EXIT=… EXIT2=…
# make relay-logs SINCE_RESTART=1   # журнал с последнего restart ultra-relay
```

Скрипт читает `EXIT` и `EXIT2` из `install.config`. Если exit-нода недоступна по SSH, выводится WARNING и сбор продолжается (код выхода 1 только при недоступном bridge).

Уровень логов: `ULTRA_RELAY_LOG_LEVEL` (в `/etc/ultra-relay/environment`) или флаг `-log-level`.

## Ограничения

- На каждой exit VPS должны совпадать `mimic_preset`, `splithttp_host`, `splithttp_path` и transport с bridge (при `-exit-only` они подтягиваются с bridge spec).
- У каждой exit свой `tunnel_uuid`; на bridge UUID хранятся в `exit_nodes`.
- Нельзя отключить или удалить последнюю enabled exit.
- Failover v1 — **primary/backup**, не балансировка нагрузки между exit.
- Смена `splithttp_path` может разорвать существующие сессии между узлами.
- Для Telegram Mini App требуется FQDN с DNS A-записью на bridge и открытый порт 80 (ACME HTTP-01 challenge).
- Поведение зависит от среды; валидируйте spec и TLS на своих площадках.

## Лицензия

См. [LICENSE](LICENSE).
