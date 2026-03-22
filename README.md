# ultra

**Репозиторий:** [github.com/NikitaDmitryuk/ultra](https://github.com/NikitaDmitryuk/ultra)

```bash
git clone https://github.com/NikitaDmitryuk/ultra.git
```

**ultra** — двухуровневый сетевой релей на Go: один процесс `ultra-relay` работает либо как **внешний узел** (`bridge` в конфиге), либо как **внутренний** (`exit`). Конфигурация задаётся JSON (`spec`), поддерживается горячая перезагрузка списка участников и локальный **loopback**-API для выдачи клиентских артефактов. Транспорт и параметры TLS между сегментами описаны в спецификации и передаются во встроенный движок пакетной обработки.

## Назначение

Проект рассчитан на сценарии, где трафик проходит **два последовательных сетевых узла** с согласованными TLS- и HTTP-параметрами между ними. Публичная документация описывает только механику развёртывания и конфигурации; детали протоколов на проводе определяются полями `spec.json`.

## Схема

```mermaid
flowchart LR
  Client[Client]
  Front[EdgeNode]
  Back[CoreNode]
  Up[Upstream]
  Client -->|TLS| Front
  Front -->|TLS| Back
  Back --> Up
```

В `spec.json` роли называются `bridge` и `exit`.

## Состав репозитория

- **`mimic`** — шаблоны HTTP-слоя для межузлового сегмента (host, path, заголовки). Сейчас доступен один встроенный шаблон `plusgaming`; описание полей — [docs/http-profiles.md](docs/http-profiles.md).
- **`auth`** — хранение идентификаторов в `users.json`, перечитывание файла, атомарная запись при изменениях через API.
- **`config`** — загрузка и проверка `spec`, генерация JSON для движка маршрутизации.
- **`proxy`** — запуск движка в процессе `ultra-relay`.
- **`adminapi`** — HTTP только на loopback: создание записей и выдача клиентских фрагментов.

## Зависимости

Сборка тянет модуль маршрутизации из экосистемы [Xray-core](https://github.com/XTLS/Xray-core) (лицензия и исходники — в `go.mod` / vendor graph).

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

Требуется Go из `go.mod`.

## Установка двух узлов

С машины с **Go**, **ssh**, **scp** и ключом к обоим хостам:

```bash
make install
```

Скрипт собирает **`ultra-relay-linux-amd64`** для VPS и **нативный** `./ultra-install` для текущей ОС (на macOS нельзя запускать `ultra-install-linux-amd64` — будет `Exec format error`). SSH: [docs/SSH.md](docs/SSH.md).

## Spec (`schema_version`)

В JSON задаётся `schema_version` (сейчас **1**). Поле `tunnel_tls_provision` фиксирует способ выдачи сертификата на узле `exit` для канала между узлами — [deploy/TLS.md](deploy/TLS.md).

## Локальная отладка (`dev_mode`)

1. TLS-материалы для `exit` (не коммитить):

   ```bash
   cd examples
   openssl req -x509 -newkey rsa:2048 -keyout test-key.pem -out test-cert.pem -days 3650 -nodes -subj "/CN=gw.cg.yandex.ru"
   ```

2. Пользователи: `users.json` по образцу `users.json.sample` или пустой массив `[]` и токен `ULTRA_RELAY_ADMIN_TOKEN` + веб-админка `/admin/` или `POST /v1/users`.

3. Терминал A — `exit`: `./ultra-relay -spec examples/spec.exit.dev.json`

4. Терминал B — `bridge`:

   ```bash
   export ULTRA_RELAY_ADMIN_TOKEN="$(openssl rand -hex 16)"
   ./ultra-relay -spec examples/spec.bridge.dev.json -admin-token "$ULTRA_RELAY_ADMIN_TOKEN"
   ```

5. Loopback API на `admin_listen`: `GET /v1/users` (список), `POST /v1/users`, `PATCH /v1/users/{uuid}` (переименовать), `DELETE /v1/users/{uuid}`, `GET /v1/users/{uuid}/client` (конфиг клиента). Веб-UI: [http://127.0.0.1:8443/admin/](http://127.0.0.1:8443/admin/) (страница без Bearer; токен вводится в форме и хранится в sessionStorage вкладки).

Согласуйте между процессами `mimic_preset`, `splithttp_path`, UUID туннеля и блок `splithttp_tls` (см. `deploy/spec.*.example.json`).

## Loopback API с административной машины

```bash
ssh -L 8443:127.0.0.1:8443 user@EDGE_HOST
# Браузер: http://127.0.0.1:8443/admin/
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/users
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/users/UUID/client
```

Токен: `-admin-token` или `ULTRA_RELAY_ADMIN_TOKEN`. Без токена API не поднимается; при пустом `users.json` на `bridge` токен нужен, чтобы создать первую запись через API или админку.

### Выдача конфигурации конечным узлам

- Подключение в **AmneziaVPN** (ссылка `vless://` или импорт JSON из `full_xray_config_base64`): [docs/amnezia-client.md](docs/amnezia-client.md).

### Отладка и уровень логов

- Интерактивный `make install` спрашивает **log-level** (пишется в `/etc/ultra-relay/environment` на **bridge и exit**); вручную: флаг `ultra-install -log-level …`.
- `journalctl`, правка `ULTRA_RELAY_LOG_LEVEL`, проверки: [docs/debug.md](docs/debug.md).
- Сбор логов: при наличии **`install.config`** достаточно **`make relay-logs`** (хосты и ключ из файла). Иначе: `make relay-logs BRIDGE=… EXIT=… IDENTITY=…`. См. [docs/debug.md](docs/debug.md) и `scripts/collect-relay-logs.sh -h`.

### Переустановка и systemd

Повторный `make install` / `ultra-install` снова копирует unit и выполняет `systemctl daemon-reload`, `enable` и **`restart` `ultra-relay`** на bridge и exit — сервис поднимается с новым бинарником и конфигом (кратковременный обрыв сессий возможен). Ранее только `enable --now` не перезапускал уже активный юнит; сейчас после деплоя всегда делается `restart`.

## Деплой

**Неинтерактивно:** скопируйте [install.config.sample](install.config.sample) → `install.config` в корне репозитория (шаблон в git, ваш файл — в `.gitignore`). Укажите `BRIDGE`, `EXIT`, `IDENTITY`. Затем:

```bash
make install
```

Другой путь к конфигу: `ULTRA_INSTALL_CONFIG=/path/to/conf make install`.

**Вручную:**

```bash
make build-linux-amd64 build-install
./ultra-install -bridge FRONT_IP -exit BACK_IP -identity ~/.ssh/id_ed25519
```

Флаги: `./ultra-install -h` (`-public-host`, `-preset`, `-reality-dest`, `-reality-sni`, `-generate-exit-tls`, `-dry-run`, `-write-local`, `-log-level`).

- [deploy/systemd/ultra-relay.service](deploy/systemd/ultra-relay.service)
- [deploy/bootstrap-bridge.sh](deploy/bootstrap-bridge.sh) / [deploy/bootstrap-exit.sh](deploy/bootstrap-exit.sh)

## Ограничения

- Поддерживается один идентификатор пресета в `mimic_preset` для текущей ветки релиза (см. справку установщика).
- Смена `splithttp_path` при пересборке может кратковременно разрывать существующие сессии между узлами.
- Поведение в разных сетевых средах не унифицировано; проверяйте конфигурацию на своих площадках.

## Лицензия

См. [LICENSE](LICENSE).
