# TLS между узлами bridge и exit (splithttp)

Сегмент **bridge** → **exit** использует **TLS** с параметрами из `splithttp_tls` в spec и HTTP host/path из `mimic_preset`.

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

При `tunnel_tls_provision: self_signed` фрагмент bridge→exit, который собирает `ultra-relay`, включает **`allowInsecure: true`** на исходящем splithttp (сертификат не из публичного CA — иначе `x509: certificate signed by unknown authority`).

В `spec` для роли `exit` укажите `exit_cert.cert_file` / `key_file` на эти пути и при необходимости `tunnel_tls_provision`: `self_signed`.
