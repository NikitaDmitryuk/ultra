# ultra

Один бинарник `ultra-relay` работает в одной из двух ролей из JSON-спецификации (`bridge` или `exit`): внешний слушатель и внутренний узел с согласованным TLS и HTTP-слоем между ними. Управление записями идентификаторов — файл `users.json` и loopback HTTP API. Маршрутизация выполняется встроенным ядром [Xray-core](https://github.com/XTLS/Xray-core) (зависимость в `go.mod`).

## Состав репозитория

| Пакет / каталог | Назначение |
|-----------------|------------|
| `internal/mimic` | Шаблон HTTP для сегмента bridge→exit (host, path, заголовки). Пресет `apijson` (идентификатор `plusgaming` в старых spec остаётся псевдонимом). |
| `internal/auth` | Хранение UUID в `users.json`, перечитывание, атомарная запись при изменениях через API. |
| `internal/config` | Загрузка и валидация spec, сборка JSON для Xray. |
| `internal/proxy` | Запуск Xray в процессе `ultra-relay`. |
| `internal/adminapi` | HTTP только на `admin_listen`: CRUD записей и выдача outbound-фрагментов. |
| `internal/install`, `internal/loglevel`, `internal/realitykey` | Установка по SSH, уровни логов, ключи REALITY. |
| `cmd/ultra-relay`, `cmd/ultra-install` | Точки входа бинарников. |

## Сборка

```bash
make build                    # ./ultra-relay
make build-linux-amd64
make build-install            # ./ultra-install
make build-install-linux-amd64
make test
make format
make lint
```

Нужен Go из `go.mod`.

## Установка двух узлов

С машины с **Go**, **ssh**, **scp** и ключом к обоим хостам:

```bash
make install
```

Скрипт собирает `ultra-relay-linux-amd64` для Linux-целей и нативный `./ultra-install` для текущей ОС. На macOS не запускайте `ultra-install-linux-amd64` на месте установки — будет `Exec format error`.

**Параметры REALITY:** для новой установки обязательны `-reality-dest host:port` и при необходимости `-reality-sni` (если пусто — берётся host из dest). В `install.config` — `REALITY_DEST` / `REALITY_SNI`, либо `REUSE_BRIDGE_SPEC=y` без смены зеркала.

**Неинтерактивно:** `install.config.sample` → `install.config` (файл в `.gitignore`), затем `make install` или `ULTRA_INSTALL_CONFIG=/path/to/conf make install`.

**Вручную:**

```bash
make build-linux-amd64 build-install
./ultra-install -bridge FRONT -exit BACK -identity ~/.ssh/key \
  -reality-dest 'HOST:443' -reality-sni 'HOST'
```

Флаги: `./ultra-install -h` (`-public-host`, `-preset`, `-reality-dest`, `-reality-sni`, `-generate-exit-tls`, `-dry-run`, `-write-local`, `-log-level`, `-reuse-bridge-spec`, …).

- [deploy/systemd/ultra-relay.service](deploy/systemd/ultra-relay.service)
- [deploy/bootstrap-bridge.sh](deploy/bootstrap-bridge.sh) / [deploy/bootstrap-exit.sh](deploy/bootstrap-exit.sh)

## SSH (ключ к обоим хостам)

Оркестратор использует `ssh -o BatchMode=yes`: без принятого ключа команды завершатся ошибкой.

**Сгенерировать ключ:**

```bash
ssh-keygen -t ed25519 -f ~/.ssh/ultra_relay_ed25519 -C "ultra-relay-deploy"
```

При passphrase перед установкой: `eval "$(ssh-agent -s)"` и `ssh-add ~/.ssh/ultra_relay_ed25519`. Путь к ключу в `make install` можно оставить пустым, если ключ уже в агенте.

**Публичный ключ на оба сервера** (front = bridge, back = exit), подставив пользователя и адрес:

```bash
ssh-copy-id -i ~/.ssh/ultra_relay_ed25519.pub root@FRONT_IP
ssh-copy-id -i ~/.ssh/ultra_relay_ed25519.pub root@BACK_IP
```

**Проверка без пароля:**

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i ~/.ssh/ultra_relay_ed25519 root@FRONT_IP 'echo ok'
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i ~/.ssh/ultra_relay_ed25519 root@BACK_IP 'echo ok'
```

**Опционально `~/.ssh/config`:**

```sshconfig
Host ultra-front
  HostName FRONT_IP
  User root
  IdentityFile ~/.ssh/ultra_relay_ed25519

Host ultra-back
  HostName BACK_IP
  User root
  IdentityFile ~/.ssh/ultra_relay_ed25519
```

Нестандартный порт SSH скрипты не задают — используйте `Port` в `~/.ssh/config` или обёртки вручную.

| Симптом | Проверка |
|--------|----------|
| `Permission denied (publickey)` | Ключ в `authorized_keys`, пользователь, путь `-i`. |
| `Host key verification failed` | Первый вход: `StrictHostKeyChecking=accept-new`; при смене ключа хоста — правка `known_hosts`. |

## Spec (`schema_version`)

В JSON задаётся `schema_version` (сейчас **1**). Поле `tunnel_tls_provision` описывает происхождение сертификата на `exit` для канала bridge→exit — см. [deploy/TLS.md](deploy/TLS.md).

Плейсхолдер `splithttp.invalid` в примерах соответствует зарезервированному TLD (RFC 6761); в продакшене задайте согласованные `splithttp_host` и TLS (SAN/CN).

**SOCKS5 на bridge:** блок `socks5` в spec (`enabled`, `port`, `username`, `password`, опционально `listen_address`, `udp`). Порт должен отличаться от `vless_port`. Тот же глобальный `routing`, что и для VLESS (split / direct vs exit). Подключайте с него, например, домашний сервер: `curl --socks5-hostname user:pass@bridge:port …`.

**Имена и литералы Xray:** опциональный объект `xray_wire` в spec задаёт теги inbounds/outbounds, `vless_encryption`, `sniffing_dest_override`, `domain_matcher_split`, `splithttp_mode`, параметры локального SOCKS в выдаче `full_xray_config` и т.д. Пустые поля не переопределяют встроенные значения по умолчанию (см. `internal/config/xray_wire_spec.go`).

## Локальная отладка (`dev_mode`)

1. TLS-материалы для `exit` (не коммитить):

   ```bash
   cd examples
   openssl req -x509 -newkey rsa:2048 -keyout test-key.pem -out test-cert.pem -days 3650 -nodes \
     -subj "/CN=splithttp.invalid" -addext "subjectAltName=DNS:splithttp.invalid"
   ```

2. `users.json` по образцу `users.json.sample` или `[]` и токен `ULTRA_RELAY_ADMIN_TOKEN` + `/admin/` или `POST /v1/users`.

3. Терминал A — exit: `./ultra-relay -spec examples/spec.exit.dev.json`

4. Терминал B — bridge:

   ```bash
   export ULTRA_RELAY_ADMIN_TOKEN="$(openssl rand -hex 16)"
   ./ultra-relay -spec examples/spec.bridge.dev.json -admin-token "$ULTRA_RELAY_ADMIN_TOKEN"
   ```

5. API на `admin_listen`: `GET/POST/PATCH/DELETE /v1/users`, `GET /v1/users/{uuid}/client`. Веб: `http://127.0.0.1:8443/admin/`.

Согласуйте `mimic_preset`, `splithttp_path`, UUID туннеля и `splithttp_tls` между процессами.

## Loopback API с административной машины

```bash
ssh -L 8443:127.0.0.1:8443 user@EDGE_HOST
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/users
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/users/UUID/client
```

Ответ `client` содержит поля вроде `vless_uri`, `xray_client_json`, `full_xray_config_base64` — это данные для внешнего совместимого с Xray потребителя; репозиторий их не интерпретирует.

## Интеграционная проверка

На машине оператора: `ssh`, `curl`, `xray`, `jq` или `python3`. Задайте **обязательно** `VERIFY_IP_URL` (HTTPS URL для GET через локальный SOCKS после поднятия конфигурации из Admin API).

```bash
VERIFY_IP_URL=https://YOUR_HOST/your-probe-path make verify-relay
# или с явными хостами:
VERIFY_IP_URL=https://YOUR_HOST/your-probe-path make verify-relay BRIDGE=… EXIT=… IDENTITY=…
```

Скрипт: `scripts/verify-relay.sh -h`. Быстрый TLS-отсев кандидатов для `reality.dest`: `scripts/probe-reality-dest.sh`.

## Логи

`make relay-logs` с `install.config` или `BRIDGE=… EXIT=…`. См. `scripts/collect-relay-logs.sh -h`. Уровень логов: `ULTRA_RELAY_LOG_LEVEL` / флаг `-log-level` у `ultra-relay` и установщика.

Повторный `make install` копирует unit и выполняет `systemctl restart ultra-relay` на обоих узлах.

## Ограничения

- Один активный `mimic_preset` на релизную ветку (см. `-preset` / справку установщика).
- Смена `splithttp_path` может разорвать существующие сессии между узлами.
- Поведение зависит от среды; валидируйте spec и TLS на своих площадках.

## Лицензия

См. [LICENSE](LICENSE).
