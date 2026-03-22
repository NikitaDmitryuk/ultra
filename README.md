# ultra

Один бинарник `ultra-relay` работает в одной из двух ролей из JSON-спецификации (`bridge` или `exit`): внешний узел и внутренний узел с согласованным TLS и HTTP-слоем между ними. Управление записями клиентов — файл `users.json` и HTTP API только на loopback. Маршрутизацию выполняет встроенное ядро из зависимостей `go.mod` ([Xray-core](https://github.com/XTLS/Xray-core)).

## Состав репозитория


| Пакет / каталог                                                | Назначение                                                                                                                                      |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/mimic`                                               | Шаблоны HTTP для splithttp bridge→exit (`Host`, path, заголовки). Идентификаторы `apijson`, `steamlike`; `plusgaming` — псевдоним `apijson`. |
| `internal/auth`                                                | Хранение UUID в `users.json`, перечитывание, атомарная запись при изменениях через API.                                                         |
| `internal/config`                                              | Загрузка и валидация spec, сборка JSON конфигурации для встроенного ядра.                                                                       |
| `internal/proxy`                                               | Запуск ядра в процессе `ultra-relay`.                                                                                                           |
| `internal/adminapi`                                            | HTTP только на `admin_listen`: CRUD записей и выдача outbound-фрагментов для клиентов.                                                          |
| `internal/install`, `internal/loglevel`, `internal/realitykey` | Установка по SSH, уровни логов, ключевой материал для публичного inbound.                                                                       |
| `cmd/ultra-relay`, `cmd/ultra-install`                         | Точки входа бинарников.                                                                                                                         |


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

**Цель для внешнего TLS handshape на bridge (`-reality-dest`):** для новой установки задайте `-reality-dest host:port` и при необходимости `-reality-sni` (если пусто — берётся host из dest). В `install.config` — переменные `REALITY_DEST` / `REALITY_SNI`, либо `REUSE_BRIDGE_SPEC=y` без смены параметров существующего spec.

**Неинтерактивно:** `install.config.sample` → `install.config` (файл в `.gitignore`), затем `make install` или `ULTRA_INSTALL_CONFIG=/path/to/conf make install`. В `install.config` задаются `PRESET` (шаблон HTTP для splithttp), при необходимости `SPLITHTTP_HOST` и `SPLITHTTP_PATH` — см. комментарии в образце.

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

По умолчанию для `ultra-install`, `make install` и bootstrap-скриптов задаётся `StrictHostKeyChecking=accept-new`: при **первом** подключении к хосту ключ записывается в `known_hosts` (trust-on-first-use). Для жёсткой модели доверия задайте `**ULTRA_INSTALL_SSH_STRICT_HOST_KEY=yes`** (или `1` / `true` / `strict`): тогда используется `StrictHostKeyChecking=yes`, и хосты должны быть заранее в `known_hosts` оператора.

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


| Симптом                         | Проверка                                                                                       |
| ------------------------------- | ---------------------------------------------------------------------------------------------- |
| `Permission denied (publickey)` | Ключ в `authorized_keys`, пользователь, путь `-i`.                                             |
| `Host key verification failed`  | Первый вход: `StrictHostKeyChecking=accept-new`; при смене ключа хоста — правка `known_hosts`. |


## Spec (`schema_version`)

В JSON задаётся `schema_version` (сейчас **1**). Поле `tunnel_tls_provision` описывает происхождение сертификата на `exit` для канала bridge→exit — см. [deploy/TLS.md](deploy/TLS.md).

**Два независимых сегмента (разные поля spec):**

- **Клиент → bridge:** публичный inbound: блок `reality` задаёт `dest` и `server_names` для TLS на стороне клиента относительно listener bridge (см. документацию Xray по REALITY).
- **Bridge → exit:** межузловой outbound: VLESS поверх TLS и `splithttp`; `mimic_preset`, `splithttp_host`, `splithttp_path` и заголовки из пресета задают параметры HTTP для этого транспорта. Публичный сертификат CA на FQDN, для которого у вас нет полномочий в DNS, выпустить нельзя; для проверки имени хоста доверенным CA укажите контролируемый FQDN в `splithttp_host` и `splithttp_tls.server_name` и согласуйте материал ключа на exit — см. [deploy/TLS.md](deploy/TLS.md). Пресет `steamlike` подставляет типовые пути и заголовки, сходные с HTTP-клиентом игровой платформы; он не задаёт идентичность TLS удалённого сервиса третьей стороны.

Плейсхолдер `splithttp.invalid` в примерах соответствует зарезервированному TLD (RFC 6761); в продакшене задайте согласованные `splithttp_host` и TLS (SAN/CN).

**SOCKS5 на bridge:** блок `socks5` в spec (`enabled`, `port`, `username`, `password`, опционально `listen_address`, `udp`). Порт должен отличаться от `vless_port`. Если `listen_address` не задан, inbound SOCKS слушает **только `127.0.0.1`**, даже когда публичный inbound на `0.0.0.0` — чтобы не открывать второй парольный сервис в интернет по умолчанию. Для привязки ко всем интерфейсам задайте, например, `"listen_address": "0.0.0.0"` и ограничьте доступ firewall. Тот же глобальный `routing`, что и для публичного inbound (split / direct vs exit).

**Тонкая настройка inbounds/outbounds:** опциональный объект `xray_wire` в spec задаёт теги, шифрование, sniffing, `domain_matcher_split`, `splithttp_mode`, параметры локального SOCKS в выдаче `full_xray_config` и т.д. Пустые поля не переопределяют встроенные значения по умолчанию (см. `internal/config/xray_wire_spec.go`).

**Обновление geo-файлов на bridge:** `scripts/update-geo-assets.sh` (аргумент — каталог `geo_assets_dir`). Старые cron-задачи с прежним именем скрипта нужно перепривязать на этот путь.

### Локальный прокси через Xray и конфиг из Admin API

**SOCKS5 на bridge по умолчанию слушает только `127.0.0.1` на самом bridge** — с другой машины в сеть к этому порту не подключиться. Для клиентского хоста (ноутбук, сервер и т.д.) обычный путь — **запустить Xray локально** с конфигом, выданным Admin API: он подключается к **публичному** inbound bridge (`public_host` и порт из spec), а на `127.0.0.1` поднимает SOCKS для приложений.

1. Получите JSON клиента: Admin API на bridge (доступ через SSH `-L` на `admin_listen`, см. раздел ниже) → `GET /v1/users/{uuid}/client`.
2. Декодируйте `full_xray_config_base64` в файл конфигурации, например `config.json`. Ограничьте права на файл (`chmod 600`).
3. Установите [Xray-core](https://github.com/XTLS/Xray-core/releases) той же ветки версий, что и в `go.mod` репозитория (дистрибутивный пакет или бинарник — как удобнее на вашей ОС).
4. Запуск: `xray run -c /path/to/config.json`.
5. В конфиге уже задан inbound SOCKS на loopback (адрес и порт смотрите в JSON, часто `127.0.0.1:10808`). Для приложений: `ALL_PROXY=socks5h://127.0.0.1:10808` или отдельная настройка прокси в сервисе.

**Без локального Xray:** SSH с клиентского хоста на bridge с пробросом порта на loopback SOCKS bridge, например `ssh -N -L 1080:127.0.0.1:1080 user@bridge` (порт возьмите из `socks5.port` в spec). Локальный SOCKS на клиенте: `127.0.0.1:1080`. Нужны SSH-доступ к bridge и учётные данные SOCKS из spec.

**SOCKS на bridge, видимый из сети без SSH:** в spec задайте `"listen_address": "0.0.0.0"` (или адрес интерфейса), ограничьте доступ **firewall** и используйте **сильный пароль**; учитывайте риск сканирования и перебора.

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
5. API на `admin_listen`: `GET/POST/PATCH/DELETE /v1/users`, `GET /v1/users/{uuid}/client`. Веб-интерфейс на том же адресе — пошагово в разделе «Loopback API с административной машины» ниже.

Согласуйте `mimic_preset`, `splithttp_path`, UUID туннеля и `splithttp_tls` между процессами.

## Loopback API с административной машины

На **bridge** Admin API и веб-админка слушают только **loopback** (`admin_listen` в spec, по умолчанию `127.0.0.1:8443`). С интернета к ним не подключиться — нужен **SSH port forwarding** с вашей машины на хост bridge.

Файл `/etc/ultra-relay/environment` с `ULTRA_RELAY_ADMIN_TOKEN` на сервере должен быть доступен только привилегированным пользователям (**режим 600**); шаблон в [deploy/bootstrap-bridge.sh](deploy/bootstrap-bridge.sh) задаёт это при установке.

### Веб-админка

1. Запустите туннель и оставьте сессию открытой (`EDGE_HOST` — DNS или IP **bridge**, пользователь — как при `make install`, часто `root`). При необходимости добавьте `-i ~/.ssh/ваш_ключ`.
  ```bash
   ssh -L 8443:127.0.0.1:8443 user@EDGE_HOST
  ```
   Если локальный порт **8443** уже занят, пробросьте другой и откройте админку на нём, например:
   тогда в браузере используйте порт **18443** вместо 8443.
2. В браузере откройте **[http://127.0.0.1:8443/admin/](http://127.0.0.1:8443/admin/)**.
3. В поле **Admin token (Bearer)** вставьте значение `**ULTRA_RELAY_ADMIN_TOKEN`**: его выводит `ultra-install` при установке. На bridge значение хранится в `/etc/ultra-relay/environment` (не коммитьте и не копируйте токен в открытые каналы). Нажмите **Сохранить в sessionStorage** — после этого страница ходит в API от вашего имени.

Локально в dev (без SSH): URL из `admin_listen` в spec, для `examples/spec.bridge.dev.json` это **[http://127.0.0.1:18443/admin/](http://127.0.0.1:18443/admin/)**.

### Примеры curl

```bash
ssh -L 8443:127.0.0.1:8443 user@EDGE_HOST
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/users
curl -H "Authorization: Bearer …" http://127.0.0.1:8443/v1/users/UUID/client
```

Ответ `client` содержит поля для подключения внешнего клиента, совместимого с тем же стеком, что и встроенное ядро; репозиторий их не интерпретирует.

## Интеграционная проверка

На машине оператора: `ssh`, `curl`, бинарник ядра из `go.mod`, `jq` или `python3`. Нужен **обязательно** `VERIFY_IP_URL` (первый GET через локальный SOCKS после выдачи конфига из Admin API). Далее по умолчанию идёт проверка **двумя** HTTPS-зондами (`scripts/verify-split-routing.sh`): один запрос обычно идёт в сторону «direct» на bridge, второй — в сторону, маршрутизируемую на exit по вашим `geosite_exit_tags`, пока не удастся отличить IPv4 исхода. Отключить второй этап: `VERIFY_SPLIT_ROUTING=n`; свой URL для второго зонда: `VERIFY_PROBE_EXIT_URL` (должен попадать под ваши правила geosite, ответ с IPv4 или путь `…/cdn-cgi/trace`); ослабить строгость: `VERIFY_SPLIT_STRICT=0`.

```bash
VERIFY_IP_URL=https://YOUR_HOST/your-probe-path make verify-relay
# или с явными хостами:
VERIFY_IP_URL=https://YOUR_HOST/your-probe-path make verify-relay BRIDGE=… EXIT=… IDENTITY=…
```

Скрипт: `scripts/verify-relay.sh -h`. Быстрая проверка TLS-кандидатов для `-reality-dest`: `scripts/probe-tls-sni-candidates.sh`.

## Производительность и перезагрузки

Любое изменение `users.json` (в т.ч. через Admin API) приводит к **полной пересборке конфигурации и перезапуску** встроенного ядра в процессе `ultra-relay`: активные клиентские сессии могут обрываться, нагрузка на CPU кратковременно растёт. При частых правках учёток имеет смысл батчить изменения на стороне оператора. Режим split с большим набором `geosite_exit_tags` увеличивает стоимость матчинга на запрос — при узком сценарии можно сузить список тегов в spec.

## Логи

`make relay-logs` с `install.config` или `BRIDGE=… EXIT=…`. См. `scripts/collect-relay-logs.sh -h`. Уровень логов: `ULTRA_RELAY_LOG_LEVEL` / флаг `-log-level` у `ultra-relay` и установщика.

Повторный `make install` копирует unit и выполняет `systemctl restart ultra-relay` на обоих узлах.

## Ограничения

- На паре узлов должен совпадать один и тот же `mimic_preset` и параметры splithttp; установщик: `-preset` (`apijson`, `steamlike`), опционально `-splithttp-host` / `-splithttp-path`.
- Смена `splithttp_path` может разорвать существующие сессии между узлами.
- Поведение зависит от среды; валидируйте spec и TLS на своих площадках.

## Лицензия

См. [LICENSE](LICENSE).