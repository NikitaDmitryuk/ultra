# HTTPS-вход подписок

По умолчанию подписки и Mini App обслуживаются непосредственно на bridge.
Nginx разделяет HTTPS на 443 по имени: один vhost передаёт запросы TLS listener
бота на loopback с проверкой сертификата и SNI, другой обслуживает XHTTP.
БД остаётся на bridge. Отдельный ingress-узел не является копией приложения или БД.

## Настройка

Канонические параметры находятся в `install.config`, секреты — в `.env`.
План схемы 2 задаёт `SUBSCRIPTION_DOMAIN`, `VPN_DOMAIN`, `ACME_EMAIL`,
`PUBLIC_XHTTP_PATH` и принадлежащие ultra DNS-записи; полный контракт описан
в [автоматизации](automation.md). DNS-зону создают и делегируют заранее.

`ultra-install ingress --config install.config --action activate` применяет
[роль ingress](../deploy/ansible/roles/ingress/tasks/main.yml).
`bash scripts/setup-subscription-ingress.sh` — совместимый вызов того же CLI.
Он не запускает отдельный SSH-установщик и требует явной ingress-политики.
`--action status` проверяет состояние без применения конфигурации.
Опубликованный основной endpoint нельзя менять обычным применением:
используется отдельная операция `domain-cutover`.

Файлы Nginx, Certbot webroot и renewal hooks записываются транзакционно через
[контракт владения](../deploy/ansible/library/ultra_owned_file.py).
Неизвестные или изменённые файлы и символьные ссылки блокируют перезапись.
Проверка конфигурации, listener и TLS предшествует успеху; при ошибке применения
восстанавливаются прежние файлы. Неизменный повтор не вызывает reload без причины.
HTTP access logs подписок отключены: URL содержит токен доступа.

## Сохранённый отдельный вход

`automation.ingress.forward_host`, формируемый из `BOT_INGRESS_IP`, сохраняет
вход через отдельный узел. [Роль forward_ingress](../deploy/ansible/roles/forward_ingress/tasks/main.yml)
настраивает Nginx stream для передачи TLS на bridge и HTTP-путь ACME.
TLS завершается на bridge; ключи бота на forwarding-узел не переносятся.
Роль принимает только известные прежние конфигурации либо сохранённые
управляющие хеши. При включённом гостевом firewall разрешаются управляемые
TCP-listener; выключенный firewall автоматически не включается.
Управление DNS и API-ключи не передаются forwarding-узлу.

Старые вручную настроенные прокси сохраняют до проверки нового пути.
Наличие сохранённого шаблона HAProxy не означает, что новый исполнитель
автоматически принимает неизвестную работающую конфигурацию: владение
ресурсом должно быть подтверждено до изменения.

## Проверка и переключение

Перед изменением DNS проверить сертификат, `/healthz`, `/happ`, Mini App и
подписку тестового пользователя через заданный IP с правильными hostname и SNI.
Секретный URL передавать только внутри защищённого проверяющего процесса;
не показывать URL или содержимое подписки в выводе.

`ULTRA_BOT_PUBLIC_URL` задаёт публичный HTTPS origin независимо от порта
внутреннего listener. Допустим origin без учётных данных, пути, query и fragment.
Изменение origin не меняет UUID и токены, но существующие ссылки и старый вход
сохраняют до проверки DNS и истечения прежнего TTL. Успешный ответ нескольких
резолверов не подтверждает обновление кеша каждого устройства.

Domain cutover и перенос bridge выполняются через общие операции Ansible,
с проверкой DNS ownership и сохранением прежнего входа для отката.
После перехода проверяют обычное DNS-разрешение, импорт и обновление подписки,
сертификат и renew-hook. Staging-сертификат не заменяет рабочий сертификат.
Условия переноса описаны в [инструкции bridge](bridge-migration.md).

При сохранённом forwarding-узле он и bridge обязательны для подписок.
Успех TCP health-check сам по себе не подтверждает TLS, HTTP или работу приложения.

## Смена имени TLS backend бота

`BOT_DOMAIN` — имя сертификата внутреннего listener бота, а
`SUBSCRIPTION_DOMAIN` и `VPN_DOMAIN` — публичные имена. Когда backend использует
прежний публичный hostname, его можно перенести на отдельное имя, например
`core.example.com`, не меняя подписки, Mini App, UUID или VPN endpoint:

```bash
ultra-install backend-domain --config install.config \
  --domain core.example.com --zone example.com \
  --known-hosts /absolute/path/known_hosts --action apply
```

Операция требует уже работающие управляемые Nginx и DNS: на bridge должны
существовать `dns.json` и `dns-receipt.json` в `/etc/ultra-recovery`, а изменяемые
прокси должны принадлежать `/var/lib/ultra-ingress/managed.json`.
API-ключ используется из существующей приватной DNS-конфигурации bridge.
ACME email берётся из `ACME_EMAIL` либо `--acme-email`. Bootstrap, обновление
бинарников и изменение firewall эта операция не выполняет.

[Отдельная роль](../deploy/ansible/roles/backend_domain/tasks/main.yml) добавляет
управляемую A-запись `backend`, проверяет DNS и выдаёт сертификат HTTP-01 через
постоянный webroot. Затем [журнал перехода](../deploy/ansible/library/ultra_backend_domain.py)
сохраняет приватные before images и согласованно меняет `ULTRA_BOT_DOMAIN`,
`proxy_ssl_name` во всех принадлежащих ultra vhost и отдельный renewal hook.
`ULTRA_BOT_PUBLIC_URL` сохраняет origin публичной подписки.
Проверяются Nginx, backend TLS с `/healthz`, публичные `/healthz`, `/happ` и Mini App, VPN TLS
и Certbot dry-run. Это не проверка импорта подписки на пользовательском устройстве.

После успешной проверки оператор отдельно принимает результат:

```bash
ultra-install backend-domain --config install.config \
  --domain core.example.com --zone example.com \
  --known-hosts /absolute/path/known_hosts --action accept
```

`accept` заново проверяет работающий вход и журнал, затем атомарно обновляет только
`BOT_DOMAIN` в каноническом `install.config` с правами 0600. Резервная копия
создаётся общим механизмом `writeCutoverConfig`; автоматического изменения
параметров после `apply` нет. До принятия не запускайте другие операции,
которые заново формируют окружение из прежнего `BOT_DOMAIN`.

При ошибке активации роль восстанавливает прежние environment, SNI и hook и
проверяет прежний backend; итог операции остаётся ошибкой. Прежний публичный
vhost и сертификаты сохраняются. Дополнительные DNS-запись, сертификат и
HTTP-01 listener остаются управляемыми для повторной попытки и продления.
Повтор `apply` использует тот же журнал; неизвестное изменение файла блокирует
автоматическую перезапись, включая откат.

Явный `--action rollback` восстанавливает сохранённый backend. Если `accept` уже
изменил канонический файл, добавьте `--previous-domain old.example.com`, чтобы
выбрать прежний журнал. После проверенного отката оператор отдельно вызывает
ту же команду с `--action accept-rollback --previous-domain old.example.com`:
она требует подтверждённый журнал отката, проверяет сохранённые файлы и работающий
вход, затем атомарно возвращает канонический `BOT_DOMAIN` с правами 0600. DNS-ownership
нового имени не удаляется и не передаётся чужой записи. Последующая DNS-сверка
по прежней публичной паре сохраняет и проверяет уже управляемую backend-запись.
Инвентарь следующего recovery capture включает новую lineage и её ACME account;
сама операция не запускает внеочередной capture.
