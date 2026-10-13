# Полная установка и обновление

План `schema_version: 2` включает обязательную автоматизацию. Версия 1 и планы,
сгенерированные из прежнего `install.config`, сохраняют прежнюю установку VPN;
они не подтверждают настройку независимых копий и монитора.
Исходный пример: [install-plan-v2.example.json](../deploy/install-plan-v2.example.json).

## Входные данные

Канонические входы — `install.config` с параметрами развёртывания и `.env` с
секретами. [Пример v2](../deploy/install.config.v2.example) включает явный
`INSTALL_SCHEMA_VERSION=2`; без него прежние конфиги продолжают создавать v1.
JSON-план остаётся совместимым интерфейсом и может генерироваться командой `plan`,
но не требует отдельного ручного сопровождения.

Оператор задаёт выделенные VM, SSH identity и проверенный `known_hosts`, публичный
age recipient, Telegram ID, провайдеры/бюджеты статических узлов и домены в
`install.config`. `ULTRA_AUTOMATION_STATIC_NODES` — JSON-массив несекретной политики
узлов. Приватный age identity остаётся у оператора; `recovery-key init/verify`
управляют им отдельно. Монитор получает отдельный ограниченный service access.

`.env` содержит `TELEGRAM_BOT_TOKEN`, `ULTRA_VULTR_API_KEY` для compute и отдельный
`ULTRA_VULTR_DNS_API_KEY` для DNS. `SECRETS_ENV_FILE` переопределяет путь; прежний
`BOT_ENV_FILE` поддерживается. Известные секретные ключи в `install.config`
отклоняются без вывода значений. Installer создаёт временные проекции 0600;
бот получает только разрешённые bot-переменные, без provider credentials.
Runtime `ULTRA_VULTR_KEY_FILE` сохраняется: это производный файл, не дополнительный
канонический источник. Для прежних JSON-планов `automation.cloud_key_file`
поддерживается; явно заданный compute key в `.env` имеет приоритет.

```sh
ultra-install doctor --config install.config
ultra-install apply --config install.config
ultra-install status --config install.config
ultra-install upgrade --config install.config
```

`--config` и `--plan` взаимоисключающие. Относительные пути разрешаются от рабочего
каталога оператора. `DNS_PROVIDER=vultr`, `DNS_ZONE`, `DNS_TTL` и относительные
`DNS_SUBSCRIPTION_NAME`/`DNS_VPN_NAME` описывают DNS-политику. Defaults ролей —
`sync`/`edge`, TTL — 300 секунд; ultra ограничивает TTL диапазоном 120–86400 секунд.
Имена должны совпадать с `SUBSCRIPTION_DOMAIN` (по умолчанию `BOT_DOMAIN`) и `VPN_DOMAIN`. Это не разрешение автоматически
переименовывать уже опубликованные endpoints: миграция существующих ссылок отдельна.

Для нового прямого входа `sync.<zone>` и `edge.<zone>` указывают на bridge;
`automation.ingress.forward_host` не задаётся. Nginx разделяет HTTPS на 443 по имени:
subscription vhost направляет запросы в TLS listener бота на loopback с проверкой
сертификата/SNI, VPN vhost обслуживает XHTTP. Раздельные webroot-сертификаты и
renewal hooks обслуживаются установщиком. Access logs subscription vhost выключены.
Старые конфигурации с `forward_host` сохраняют NL forwarding; installer их не удаляет.
Изменение уже опубликованного primary endpoint отклоняется с требованием явного
cutover, а не молча пропускается.

DNS apply работает только с уже созданной зоной Vultr: регистрацию/делегирование
выполняют заранее. Он управляет двумя A-записями из policy, не изменяет apex,
не удаляет записи и не принимает чужие существующие записи без receipt.
Перед POST/PATCH сохраняется журнал; после ответа проверяется фактическое состояние.
Потерянный ответ POST восстанавливается по точному совпадению цели; если запись не
видна, автоматический повтор создания блокируется. Явный отказ HTTP 4xx очищает
pending без автоматического повтора. Drift и дубликаты останавливают установку.
До ACME проверяются recursive A-ответы и оба authoritative NS Vultr через `dig`
с общим deadline. Runtime policy/key/receipt лежат в `/etc/ultra-recovery` и
попадают в зашифрованный backup inventory. API-ответы и credentials не выводятся.

`static_nodes` задаёт реальные провайдеры начальных узлов, а не признак независимости
по стране. UUID узлов установщик получает из БД. Узел того же провайдера допустим
для начала установки, но полная готовность остаётся ложной до появления пригодной
независимой копии. Создание платного exit остаётся явным действием администратора
через Telegram; контроллер автоматически включает готовую машину в резервирование.

## Release и команды

`make release-dist` собирает relay, installer, bot и client для amd64/arm64, recovery
bundle и `release-manifest.json`. Manifest содержит SHA-256/размер каждого артефакта,
версию, capability `service-access-v1` и границы схемы БД. Скопируйте **весь** результат
в `automation.release_dir`; `automation.version` должна точно совпадать с manifest.
`latest` не допускается. SHA проверяется до изменений на узлах и после доставки;
доверие к происхождению самого manifest обеспечивает выбранный канал доставки.

```sh
ultra-install doctor --plan /secure/install-plan.json
ultra-install apply --plan /secure/install-plan.json
ultra-install status --plan /secure/install-plan.json
ultra-install bootstrap --plan /secure/install-plan.json
ultra-install upgrade --plan /secure/install-plan-next.json
```

`bootstrap` завершает эксплуатационную настройку уже установленного VPN.
`apply` выполняет её сам после установки. Повторный v2 apply сохраняет существующий
spec, UUID и pins; нечитаемый существующий spec блокирует замену. Новые планы должны
указывать точные пути к секретам; значения секретов не входят в JSON-план и вывод.

Установка размещает конфиги в `/etc/ultra-recovery`, активные инструменты в
`/opt/ultra-recovery`, версии инструментов в `releases/<version>`, состояние установки
в `/var/lib/ultra-automation`. Временный upload-каталог удаляется; работа timers от
него не зависит. `deployment.json` сохраняет публичную топологию и постоянные пути
для восстановления. Полный набор state/artifact paths строится из установленных
служб, ingress receipt, выбранных сертификатов/ACME account, geo-assets и стабильных
ключей; дополнительные прикладные пути задаются в плане явно.

Успех требует свежего `streaming` всех enabled replica, готового независимого
контроллера, свежей копии и активных timers. `streaming` worker подтверждает проверкой
replay lag и heartbeat прикладной БД. `status` возвращает только готовность и коды
причин, без секретов. Последняя ошибка bootstrap/upgrade сохраняется в
`/var/lib/ultra-automation/last-error.json` и поле `last_error` статуса: только
действие, этап, код и время. Успешное завершение удаляет эту запись. При незавершённой сходимости bootstrap возвращает ненулевой код,
но сохраняет установленный контроллер, чтобы готовность восстановилась после
появления нового exit. Такой результат нельзя называть полной установкой.
Если настройка прервалась после активации кода, совместимый аварийный бинарник
и инструменты также сохраняются: служебная запись мониторинга уже могла попасть
в БД. После исправления причины повторяют `bootstrap`; готовность до успеха не объявляется.

Для каждого нового статического exit план требует `static_nodes[].budget`:
`monthly_bytes` — согласованный месячный лимит провайдера в байтах,
`is_fallback` — признак единственного резервного бюджета. Числа в примере плана
иллюстративны: их заменяют лимитами своих серверов. Квота сама удерживает 20% резерва;
вводить уже уменьшенное значение не нужно. Поле `provider` описывает независимость
реплик и само по себе не включает сбор статистики Vultr для статического сервера.

Bootstrap вызывает `ultra-relay -ensure-static-budgets -spec PATH -static-budgets-file PATH`
до создания мониторингового доступа. Команда принимает JSON-массив статических узлов,
создаёт только отсутствующие бюджеты и не меняет накопленный расход. При повторе
явный бюджет обязан совпадать с существующим; для `reuse_spec` его можно опустить,
только если запись уже есть в БД. Несоответствие или отсутствие бюджета — ошибка,
а не повод назначать неявный лимит. Cloud-managed exit получает бюджет штатно из
выбранного тарифа и наблюдений API провайдера.

## Обновление и откат

`upgrade` принимает полный комплект явно выбранной версии. Перед изменениями нужна
свежая независимая копия. Таймеры и выполняющиеся backup/reconcile останавливаются
на период активации. Каждый exit обновляется по очереди через pinned SSH; следующий
начинается после свежей проверки передачи через туннель предыдущего. Затем меняются
relay и bot на bridge: bot запускается только после готовности relay/Xray.

Обратное переключение допускается только на предыдущие бинарники с подтверждёнными
SHA, `service-access-v1` и совместимыми границами схемы. Автоматически не откатываются
SQL, credentials и топология. Неизвестный предыдущий manifest или несовместимый
бинарник блокирует upgrade; наличие старого accounting-aware бинарника недостаточно.
Комплект сохраняет совместимый emergency relay вместе с его manifest и включает
их в зашифрованные артефакты. Журнал `/var/lib/ultra-automation/upgrade.json` связывает этапы узлов и bridge с
точным manifest и топологией. Повтор той же версии после остановки процесса
проверяет установленный SHA и сохранённый fallback, затем продолжает этапы;
другую версию или изменённую топологию незавершённый журнал не принимает.
Snapshot файлов bundle позволяет восстановить предыдущие инструменты после
перезапуска процесса. Неудачный rollback возвращает ошибку,
а не успешную готовность.

Проверки реализации: Go-тесты `internal/installplan` и `cmd/ultra-install`,
`python3 internal/install/scripts/test_automation.py`, существующие проверки ingress
в `make test-ui`. Они проверяют контракты, целостность, порядок и ошибки обновления;
готовность конкретной инфраструктуры подтверждается её `status`, а восстановление —
отдельным [изолированным учением](../deploy/recovery/README.md).

## Явная смена домена с сохранением старых входов

`domain-cutover` принимает и legacy v1 `install.config`. Он не запускает полную
переустановку: использует текущие primary backend/path и существующий service probe,
создаёт новые vhost aliases, проверяет старую и новую подписки и изолированный VPN
payload, затем меняет только согласованную publication metadata. Старые Nginx sites,
NL forwarding, REALITY, UUID и subscription tokens сохраняются. Неизвестные TLS
publication descriptors требуют отдельного рассмотрения вместо массовой замены.

```sh
ultra-install domain-cutover --config install.config \
  --subscription-domain sync.example.com --vpn-domain edge.example.com \
  --zone example.com --dns-receipt /secure/example.com.receipt.json \
  --known-hosts /secure/ultra-known-hosts --acme-email operator@example.com
```

Зона/записи уже должны иметь owned DNS receipt. В canonical `.env` нужны
`ULTRA_VULTR_DNS_API_KEY` и `ULTRA_CUTOVER_SUBSCRIPTION_URL` — ранее выданная рабочая
HTTPS-ссылка `/sub/...`; команда не выпускает и не ротирует токены. Probe URL не
попадает в argv, журнал или bot.env. Перед операцией выполняется fresh backup capture.
Прогресс и приватные before-images сохраняются в `/var/lib/ultra-domain-cutover/current`;
повтор с теми же целями продолжает операцию, а изменение целей отклоняется.

`SUBSCRIPTION_DOMAIN` задаёт публичный subscription hostname, по умолчанию совпадает
с `BOT_DOMAIN`. Последний остаётся именем TLS-сертификата backend бота на 8444.
Public URL переключается через отдельный последний systemd EnvironmentFile, сохраняя
прежние token/DSN files. После успешных проверок CLI атомарно обновляет только domain
параметры `install.config` и сохраняет `.before-domain-cutover`. Он не меняет
`INSTALL_SCHEMA_VERSION`, `BOT_DOMAIN` или прежний `BOT_INGRESS_IP`;
`SUBSCRIPTION_INGRESS_MODE=direct` выбирает новый прямой вход при последующем v2 apply.
При неуспехе публикации или её проверки восстанавливаются прежние spec/public-origin settings;
созданные aliases сохраняются, старый вход остаётся доступен. Повтор проверяет drift
перед восстановлением. Уже импортированная ссылка пользователя сама не переименуется.

После проверки публикации cutover расширяет inventory резервной копии новыми
управляемыми vhost, сертификатами и DNS policy, обновляет адрес monitor и сохраняет
новую резервную копию. Прежние пути и сертификаты остаются в inventory.

После успешной проверки публикации журнал переходит в `finalizing`. Ошибка обновления
recovery metadata или финального capture оставляет новую публикацию работающей,
но команда не сообщает завершение и не обновляет локальный `install.config`.
Повтор той же команды проверяет публикацию и завершает backup/canonical state.
Откат только spec на этой стадии запрещён: recovery metadata уже могла сохраниться.

После bootstrap/upgrade readiness требует controller receipt и backup snapshot
со временем строго новее активации. Предыдущий свежий статус не подтверждает
готовность новой версии, даже если timers и реплики продолжают работать.

Изменение owned ingress-файла предваряется приватным transaction receipt
`managed.json.pending`. После остановки процесса повтор завершает ownership receipt
только при совпадении сохранённых before/target hashes; посторонняя правка остаётся
ошибкой. Записи и удаление журнала синхронизируются на диск.
