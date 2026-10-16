# TLS между узлами bridge и exit (splithttp)

Сегмент **bridge** → **exit** использует VLESS/XHTTP/TLS. Для новой установки
задайте `MAIN_EXIT_DOMAIN=tunnel.example.com`: DNS A этого имени указывает на
`MAIN_EXIT_IP`, bridge подключается к явному IP exit, передавая это имя в TLS SNI
и HTTP Host. Используется проверка публичного CA и имени, без `allowInsecure`
и без pin leaf-сертификата. Публичные варианты Happ VLESS/XHTTP/TLS и
VLESS/TCP/REALITY на bridge от этой настройки не меняются.

Канонический `install.config` больше не принимает `PRESET`. В управляемом
режиме не добавляются придуманные Steam/API заголовки; XHTTP использует
детерминированный путь `/ultra-xhttp` или явно заданный `SPLITHTTP_PATH`.
Padding и остальные настройки XHTTP сохраняются.

## Управляемый сертификат отдельного exit

Первый поддержанный сценарий — чистый schema 2 bootstrap с одним exit,
`REUSE_BRIDGE_SPEC=false`, прямым ingress и управляемым Vultr DNS. Имя exit
должно быть отдельной меткой `DNS_ZONE`, отличной от имён bridge и бота.
Перед настройкой exit Ansible на bridge создаёт принадлежащую ему A-запись
с ролью `tunnel`; DNS credentials остаются на bridge.

На exit Ansible устанавливает nginx/certbot, открывает TCP/80 в уже включённом
UFW, выпускает отдельный HTTP-01 сертификат и настраивает `certbot.timer`.
`TUNNEL_PORT=80` отклоняется: этот порт занят nginx для HTTP-01.
В компонентном bootstrap DNS применяется в `bootstrap-postgres` до
`bootstrap-exit`; последний выдаёт подтверждение CA/hostname без leaf pin.
`bootstrap-bridge` и проверка возобновления используют этот режим из frozen
inventory; сравнение pin сохраняется только для прежних режимов аутентификации.
Внешний firewall провайдера должен пропускать TCP/80; автоматического изменения
такого firewall этот сценарий не выполняет. У домена не должно быть посторонней
AAAA-записи, направляющей ACME на другой сервер. Ошибка DNS/ACME прерывает
установку до активации relay; самоподписанного fallback нет.

Certbot hook проверяет цепочку CA, имя, срок и соответствие ключа сертификату,
затем копирует только локальную пару в `/etc/ultra-relay` с правами 0600 и
перезапускает relay после продления. Приватный ключ между серверами не передаётся.
Клиенты проверяют CA/hostname, поэтому продление не требует распространения pin.

`upgrade` и runtime adoption пока явно отклоняются, если указан
`MAIN_EXIT_DOMAIN`, в том числе при сохранении прежнего домена. Upgrade
отказывает до создания каталога операции или запуска исполнителя; retry и
forward-only эту границу не обходят. Не используйте bootstrap для обхода
этой границы на действующей установке.

Проверка прежней идентичности runtime не связывает режим TLS, Host/SNI и пути
сертификата с доменом из плана. Локальная проекция runtime использует
`REUSE_BRIDGE_SPEC=true`, который этот режим запрещает, и пока выбирает только
`user_provided`/`self_signed`; исполнитель TLS-переходов также не принимает
`acme_letsencrypt`. Поэтому одного сравнения `MAIN_EXIT_DOMAIN` недостаточно
для безопасного обновления бинарников. Нужны согласованная проверка и сохранение
прежней CA/hostname-аутентификации, локальной пары и renewal-настройки exit,
а также проверка его восстановления после переустановки.

Ниже описаны низкоуровневые форматы ранее созданных specs; они не выбираются
параметром `PRESET` в канонической конфигурации.

## Поле `tunnel_tls_provision`

В spec можно задать `tunnel_tls_provision`, чтобы зафиксировать способ получения сертификата на back-узле (удобно для эксплуатации и аудита конфигурации):

| Значение | Смысл |
|----------|--------|
| `acme_letsencrypt` | Публичный сертификат (часто Let’s Encrypt) на **домен**, совпадающий с ожидаемым SNI/host в канале. |
| `user_provided` | Файлы `fullchain.pem` / `privkey.pem` подготовлены вручную (коммерческий CA, свой PKI и т.д.). |
| `self_signed` | Самоподписанный сертификат (например `openssl` или флаг `ultra-install -generate-exit-tls`). Проще в развёртывании; цепочка доверия не совпадает с публичным CDN — учитывайте при планировании окружения. |

Пустое значение допускается для старых конфигов.

## Согласование SNI, сертификата и Host

- В сгенерированной конфигурации ядра для splithttp задаются **`serverName` / uTLS fingerprint** и HTTP **`host`** (из пресета mimic).
- Сторона front проверяет сертификат сервера в соответствии с `splithttp_tls.server_name` (если пусто — подставляется host пресета).
- **Рекомендация:** имя в сертификате back (SAN/CN) и `splithttp_tls.server_name` должны быть согласованы: либо **свой домен** на back с валидным публичным сертификатом, либо режим `self_signed` с пониманием ограничений.

## ACME и только IP

Let’s Encrypt **как правило не выдаёт** сертификаты на «голый» IP без отдельного сценария. Практичный путь — **домен**, указывающий на back, и HTTP-01 или DNS-01 challenge (настройка вне `ultra-relay`).

## Пример self-signed на back

CN/SNI должны совпасть с тем, что ожидает front (обычно это `Host()` пресета):

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout /etc/ultra-relay/privkey.pem \
  -out /etc/ultra-relay/fullchain.pem \
  -days 3650 -nodes -subj "/CN=splithttp.invalid" \
  -addext "subjectAltName=DNS:splithttp.invalid"
```

Нужен **SAN** (не только CN): иначе при проверке имени хоста Go 1.23+ выдаёт `certificate relies on legacy Common Name field, use SANs instead`.

При `tunnel_tls_provision: self_signed` bridge→exit outbound использует **`pinnedPeerCertSha256`** (SHA-256 leaf-сертификата exit) вместо удалённого в Xray 26 `allowInsecure`. Pin записывается в `exit_nodes.bootstrap.json` / PostgreSQL при `make install`.

В `spec` для роли `exit` укажите `exit_cert.cert_file` / `key_file` на эти пути и при необходимости `tunnel_tls_provision`: `self_signed`.

## Несколько exit VPS

Каждая exit-нода — отдельный VPS со своим `spec.json` и **своим** `exit.tunnel_uuid` (регистрация на bridge через Admin API / Mini App). TLS-сертификат (`exit_cert`) выпускается **на каждом** exit-хосте (например `ultra-install -generate-exit-tls` или `-exit-only`). SAN/CN сертификата должны соответствовать `splithttp_host` / `splithttp_tls.server_name`, общим для всех exit в паре с bridge. Bridge хранит dial-адреса и UUID в PostgreSQL (`exit_nodes`), не в `spec.exit`.

## Публичный XHTTP/TLS

Основной HTTPS-вход обслуживает Nginx; продление сертификата выполняет graceful reload без перезапуска relay. Отдельный эксперимент загружает сертификат при старте и имеет собственный deploy-hook. Воспроизводимые команды и сохранение прежнего HTTP-01 бота — в [инструкции входа](../docs/xhttp-ingress.md).

## Отдельное имя сертификата backend бота

Имя TLS listener бота (`BOT_DOMAIN`) может отличаться от публичных
`SUBSCRIPTION_DOMAIN` и `VPN_DOMAIN`. Для существующего управляемого ingress
используйте узкую операцию `ultra-install backend-domain`: она получает webroot
сертификат, согласованно меняет окружение бота и `proxy_ssl_name` Nginx и добавляет
renewal hook с перезапуском только бота при продлении нового backend-сертификата.
Прежние публичные сертификаты и vhost сохраняются. После проверки применяется
отдельный `--action accept`, который обновляет канонический `BOT_DOMAIN`.
Условия владения, команды и откат — в [инструкции подписок](../docs/subscription-ingress.md#смена-имени-tls-backend-бота).
