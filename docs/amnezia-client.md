# Подключение клиента AmneziaVPN к ultra-relay

Сервер выдаёт три артефакта на пользователя (админка **«Клиент»** или `GET /v1/users/{uuid}/client`):

| Поле | Назначение |
|------|------------|
| `vless_uri` | Текстовая ссылка `vless://…` |
| `xray_client_json` | Фрагмент outbound (для справки) |
| `full_xray_config_base64` | Полный минимальный JSON конфигурации Xray (SOCKS 127.0.0.1:10808 + ваш outbound) в Base64 |

Официально Amnezia описывает импорт [по текстовому ключу](https://docs.amnezia.org/documentation/instructions/connect-via-text-key) и [из файла `.json`](https://docs.amnezia.org/documentation/instructions/connect-via-config). Версии приложения различаются; если один способ не сработал, используйте другой.

## Способ A: ссылка `vless://`

1. Скопируйте значение `vless_uri` из админки или из ответа API.
2. В AmneziaVPN: добавить подключение → ввод ключа / текстового ключа (в документации — строки вида `vpn://`, `vless://`, `ss://`).
3. Вставьте всю строку `vless://…` и сохраните подключение.

Подходит, если ваша сборка Amnezia корректно разбирает VLESS + REALITY из URI.

## Способ B: файл `*.json` (полный конфиг Xray)

1. Скопируйте `full_xray_config_base64` и декодируйте в файл, например:

   ```bash
   pbpaste | base64 -d > ultra-client.json   # macOS: буфер = base64
   ```

   Либо в админке скопируйте base64 в любой декодер и сохраните результат как `ultra-client.json`.

2. Убедитесь, что файл — валидный JSON с полями вроде `inbounds`, `outbounds`, `routing` (так выдаёт `FullClientXRayJSON` в репозитории).

3. В AmneziaVPN: **плюс** → **файл с настройками подключения** (Connection settings file) → выберите `ultra-client.json` → **Continue** → подключение.

Интерфейс на телефоне/ПК может отличаться; смысл тот же: импорт готового Xray JSON.

## Если импорт не принимается

- Обновите AmneziaVPN до последней версии (поддержка Xray / Reality расширялась в новых релизах).
- Проверьте, что в URI/конфиге верные `public-host`, порт VLESS и параметры REALITY (они должны совпадать с `spec.json` на bridge).
- Временно можно использовать другой Xray-совместимый клиент с тем же `vless_uri` или JSON.

## Напоминание по админке

Admin API слушает только loopback на bridge. С машины администратора:

```bash
ssh -i ~/.ssh/ваш_ключ -L 8443:127.0.0.1:8443 root@BRIDGE_IP
```

Далее браузер: `http://127.0.0.1:8443/admin/` — токен из `/etc/ultra-relay/environment` на сервере (`ULTRA_RELAY_ADMIN_TOKEN`).
