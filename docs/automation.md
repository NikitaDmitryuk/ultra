# Установка и эксплуатационная автоматизация

Переход поставляется поэтапно. Границы первого PR и отложенная сквозная
приёмка перечислены в [Ansible TODO](../TODO.md). Реализация команды не означает
подтверждённую production-приёмку.

[Наглядное объяснение Ansible](ansible-explained.html) показывает путь задания,
границы ответственности, обновление и откат.

Ansible управляет подготовкой серверов, службами, PostgreSQL и репликами,
DNS/TLS, установкой копий и мониторинга, обновлением и восстановлением.
Прикладной код сохраняет учёт, маршрутизацию, операции покупки VM, проверку
поколений и готовности данных. Docker используется только в отдельных тестах;
он не является способом развёртывания сервиса.

Новые управляемые runtime контроллера размещаются в
`/opt/ultra-ansible/releases/managed-<version>`. Прежний каталог версии без
квитанции владения не перезаписывается и не принимается по одному совпадению
хеша бинарника. Старые пути остаются читаемыми при adoption и восстановлении;
фактический путь сохраняется в deployment metadata и backup inventory.

Новые записи recovery `deployment.json` сохраняют полный ingress-план, включая порты backend,
gateway, staging, status и экспериментального профиля. Finalizer и transition
отклоняют неполный или типизированный не как integer набор портов, прежде чем
зафиксировать cutover. Для исторической metadata без status/experimental-портов
upgrade сверяет их только с receipt-управляемым публичным profile-файлом,
который указан в relay spec; gateway-порт сверяется с активным relay spec.
Отсутствующий staging-порт отдельно отмечается как не записанный, поскольку он
действует только на временном этапе staging. Желаемая конфигурация не используется
как доказательство прежнего runtime. Уже начатый legacy cutover можно продолжить
только с тем же private journal и fingerprint исходного плана; новые cutover
остаются строгими и требуют полный набор портов.

При обновлении и совместимом откате путь активного контроллера одновременно
обновляется в службе, `deployment.controller_directory` и `backup.artifact_paths`.
Следующее поколение копий содержит runtime активной версии; чужая идентичность
блокирует изменение. Источник: [контракт восстановления контроллера](../deploy/ansible/roles/release/tasks/backup-identity.yml).

## Канонические входы

`install.config` содержит параметры развёртывания, `.env` — секреты.
[Подробный пример](../install.config.example) использует единственную поддерживаемую
схему установки 2. Параметр `INSTALL_SCHEMA_VERSION` в конфигурации не нужен;
явное значение 1 или любая иная версия отклоняются. JSON-план обязан явно
указывать `"schema_version": 2`.
JSON-план остаётся совместимым интерфейсом `plan`; второй вручную поддерживаемый
inventory не нужен. Его генерирует общий Go-парсер, а действующие динамические
exit берутся из управляющей БД.

Схема 1 не поддерживается ни для `doctor`, `plan`, `render`, ни для применения.
Первоначальное применение и `bootstrap` требуют полной политики схемы 2 и
проверенного release-комплекта. Первоначальная установка через старые CLI-флаги без automation-политики
отклоняется: используйте `apply --config`.
Версии relay spec, журналов, release manifest и host-local runtime request
независимы от схемы установки; их значения 1 не являются совместимостью
с install-plan v1. Внутренняя локальная runtime-проекция сохраняет прежний
минимальный формат без automation-политики, но не используется для установки.

Оператор задаёт адреса VM, выделенный SSH identity, проверенный `known_hosts`,
public age recipient, Telegram ID, домены и несекретную политику статических
узлов. `ULTRA_AUTOMATION_STATIC_NODES` — JSON-массив. Приватный age identity
остаётся у оператора; `recovery-key init/verify` управляют им отдельно.
Монитор использует отдельный ограниченный служебный доступ.

`BRIDGE_IP` задаёт адрес bridge для SSH, сервисов, DNS и проверок.
`MAIN_EXIT_IP` и `DATABASE_IP` задают отдельные роли. Операторские ключи:
`BRIDGE_SSH_KEY`, `MAIN_EXIT_SSH_KEY`, `DATABASE_SSH_KEY`.
Подключения используют `-F /dev/null`; неявные настройки SSH не применяются.
Неизвестный или изменённый pin блокирует операцию. Конфигурация узлов не должна
исполнять Jinja-выражения: входные контейнеры передаются с `!unsafe`.

`.env` содержит `TELEGRAM_BOT_TOKEN`, `ULTRA_VULTR_API_KEY` для compute и
отдельный `ULTRA_VULTR_DNS_API_KEY` для DNS. `SECRETS_ENV_FILE` переопределяет путь;
`BOT_ENV_FILE` поддерживается для совместимости. Секретные ключи в
`install.config` отклоняются. Приватные производные файлы имеют права 0600;
бот не получает ключи управления провайдером. Поддерживаемый
`automation.cloud_key_file` не заменяет канонический compute key из `.env`.

`ULTRA_RELEASE_MINISIGN_PUBLIC_KEY` — доверенный открытый ключ, которым локальный
оператор проверяет подписи `release-manifest.json` и `checksums.txt` перед
обновлением. Это публичная политика, не секрет: значение остаётся в каноническом
`install.config`, не попадает в JSON-план, Ansible inventory и recovery config.
Значение — base64-строка из `minisign.pub` (строка после комментария), а не
приватный `minisign.key`; приватная часть остаётся только в секретах release
workflow. Перед доверием проверьте, что открытый ключ соответствует ключу,
которым подписывает workflow. Для проверки на машине оператора нужен `minisign`
в `PATH`.

После успешного upgrade локальный кеш `~/.cache/ultra/releases` очищается от
устаревших комплектов только при подтверждённой подписи, неизменном составе и
отсутствии активного bundle lease или ссылки из незавершённой операции. Текущий
и предыдущий релизы сохраняются для отката; неизвестные и изменённые каталоги
очистка оставляет на месте. Ссылка на релиз незавершённой операции хранится рядом
с кешем и защищает комплект независимо от того, где расположен заданный `--job-dir`;
после успешного завершения ссылка удаляется.

`ULTRA_AUTOMATION_STATE_PATHS` и `ULTRA_AUTOMATION_ARTIFACT_PATHS` дополняют
backup inventory. Это JSON-массивы абсолютных путей: отсутствие, пустая строка
и `[]` не добавляют путей; `null` и неверные типы отклоняются.
При `upgrade` указанные пути добавляются в recovery inventory перед финальным
capture после применения релиза. Инвентаризация накопительная: старые пути остаются,
даже если config-путь убран, поскольку автоматическое удаление могло бы исключить
пользовательские данные из recovery.
`adopt --prepare-config /secure/candidate.config --release-dir /secure/releases/vX.Y.Z`
создаёт новый schema 2 файл с правами 0600 из согласованной recovery-политики;
только этот режим допускает исходные параметры ролей без полной automation policy.
Исходные параметры имеют schema 2 (явная schema 1 отклоняется), проходят проверку
ролей и SSH-доступа, но не проходят обычный `ValidatePlan` и не пригодны для `apply`.
Полный кандидат проходит обычную проверку schema 2 после согласования metadata.
существующий файл не перезаписывается. Дополнительные пути из старого backup inventory
сохраняются, включая пользовательские hooks и units внутри каталогов Ultra.
Исключаются только точные штатные пути, которые создаются заново, и каталог контроллера,
явно указанный в `deployment.json` для той же версии. Неоднозначное указание контроллера
блокирует подготовку. Исходный config и состояние узлов не меняются; затем кандидат
проверяют через `adopt --config /secure/candidate.config --release-dir /secure/releases/vX.Y.Z --adopt-runtime --check`.
Если legacy config использовал локальный SSH-алиас, при подготовке можно явно
указать `--bridge-ssh-host 192.0.2.1`. Это меняет адрес только в новом кандидате;
совпадающий с прежним алиасом endpoint primary также переносится. Identity, pins
и остальные параметры сохраняются. Алиасы и `ProxyCommand` не импортируются,
проверка SSH-ключа остаётся обязательной.
Опубликованные `subscription_domain` и `ingress_mode` из deployment metadata
переносятся в канонические параметры. Режим допускает только `direct`/`forward`;
для `forward` требуется подтверждённый endpoint ingress.
Конфликт с уже заданной политикой блокирует подготовку. Неизвестные поля metadata
по-прежнему отклоняются.
При явном `direct` неиспользуемый legacy `BOT_INGRESS_IP` сохраняется как параметр,
но не создаёт forwarding-узел. Ошибка подготовки указывает фиксированную стадию
или имя проверяемого параметра без его значения и содержимого приватных файлов.
Источник: [подготовка политики принятия](../cmd/ultra-install/ansible_adopt_policy.go).

## CLI и независимый исполнитель

```sh
ultra-install doctor --config install.config
ultra-install plan --config install.config
ultra-install adopt --config install.config --release-dir /secure/releases/vX.Y.Z --check
ultra-install apply --config install.config
ultra-install status --config install.config
ultra-install upgrade
ultra-install upgrade --release vX.Y.Z
ultra-install upgrade --config install.config --release latest
```

`--config` и `--plan` взаимоисключающие. Относительные пути разрешаются от
рабочего каталога оператора. CLI проверяет входы, создаёт приватное неизменяемое
задание и запускает фиксированную операцию Ansible. Обычное обновление
не повторяет полную подготовку ОС. `upgrade` без selector выбирает stable
`latest`; `--release vX.Y.Z` закрепляет конкретный релиз. Для upgrade без
`--config` используется локальный `install.config`. Явный config выбирает цели
и deployment policy, а также задаёт желаемые управляемые runtime-настройки.
Они сверяются с фактической конфигурацией узлов и применяются в составе upgrade;
удалённые необязательные параметры сбрасываются к валидированным default или
отключённому состоянию. Сгенерированные identity и секреты сохраняются. Изменения
состава/адресов узлов и identity базы требуют отдельной миграции и блокируются до
первой мутации. Параметр без безопасного default должен быть задан явно. Локальный
`--release-dir` поддержан для уже скачанного подписанного комплекта.

Изменение доменов проходит отдельные DNS, backend и ingress-фазы: старые адреса
сохраняются до проверки нового TLS, subscription identity/payload и полного tunnel
через каждый frozen exit. Переход не гарантирует работу клиентов на прежнем домене
или URI: поддерживаемым считается только endpoint из canonical `install.config`.
После приёмки старые alias и DNS записи удаляются; до неё они могут оставаться как
rollback-материал. Автоматически удаляются только alias и DNS records, закреплённые
ownership receipts текущего cutover. Исторические alias и DNS records из предыдущих
операций требуют отдельной инвентаризации и очистки; обычный upgrade их не сканирует.
Смена DNS zone и других неподдерживаемых внешних identity требует отдельной миграции.

Перед активацией релиза `upgrade` сверяет DNS TTL и сохранённую ingress policy с
`install.config`. Изменения ACME email, DNS TTL, режима/узла forwarding, staging,
status, experimental, backend или gateway port пока требуют отдельной миграции:
команда останавливается до мутаций вместо того, чтобы считать новое значение
применённым. В режиме `direct` неиспользуемый `BOT_INGRESS_IP` не меняет эффективную
конфигурацию. Upgrade также блокирует замену recovery age recipient, bridge provider,
static-node policy и admin Telegram ID: ключ требует отдельной ротации, а остальные
значения входят в recovery/topology state. Изменение bridge IPv4 требует отдельной
миграции. Новые backup paths применяются перед финальным recovery capture.
`READINESS_TIMEOUT_SEC` задаёт
длительность локального ожидания проверки после активации.

Runtime-переходы, затрагивающие firewall, WARP или TLS, сначала сохраняют точные
host-local before-images и request-bound journal. Tunnel peers обновляются по одному
exit при остановленном bridge; после применения проверяется новый payload на всех
узлах. Rollback восстанавливает только journalled-owned файлы и состояния, а drift
останавливает операцию. WARP включается или выключается только при уже установленной
регистрации; выпуск или ротация TLS-ключей и сертификатов в upgrade не выполняется.
Сбой финальной фиксации сохраняет lifecycle gate для retry той же generation.
Legacy retry определяет commit до recovery preflight: после commit проверяет точную
цепочку runtime/domain candidate по приватным journals и продолжает только
retirement/finalize и фиксацию effects. До commit preflight допускает только
journal-bound before/candidate images и их известные сочетания, включая точные
mode/owner; постороннее изменение блокирует компенсацию. Работающий candidate
relay проверяется по frozen release SHA и сохранённому compatible fallback;
producers останавливаются в принадлежащей операции maintenance-границе перед
новой независимой recovery capture. Исходный checkpoint остаётся неизменным.

Upgrade сначала отдельно подтверждает reservation своего UUID; отказ drain не
включает legacy fallback. Legacy режим выбирается по проверенному manifest прежнего
relay без `lifecycle-gate-v1`, затем сверяет SHA работающего процесса с этим
manifest. Приватный maintenance checkpoint сохраняет состояния bot и recovery
таймеров, а также хеши конфигурации. Перед изменением exit требуются idle recovery,
свежая доставка независимому primary, остановленный bridge с нулевыми MainPID и
ControlPID и повторная проверка замороженной topology. Exit обновляются последовательно;
их payload проверяется через новый bridge для каждого frozen exit до запуска bot.
Совместимый rollback запускает и проверяет прежний bridge даже при неизменных байтах,
затем возвращает сохранённые состояния bot и таймеров до освобождения reservation.
При запуске принятого кандидата legacy resume проверяет цепочку точных приватных
образов runtime, ingress и backend той же generation и domain attempt, binding
runtime/effects и неизменность relay unit. Bot запускается по желаемому `BOT_ENABLE`,
а таймеры возвращаются в прежнее состояние. Ошибка до активации и rollback по-прежнему
требуют исходные хеши конфигурации и возвращают исходное состояние bot.
Для принятой разнородной установки можно явно задать приватный
`ULTRA_UPGRADE_BASELINE_FILE`: exit остаются на сохранённом операторском комплекте,
а bridge работает на emergency relay после подтверждённого adoption rollback.
Это одноразовый адаптер прежнего состояния. Обычное обновление использует прежний
общий manifest; проверка подписи целевого релиза остаётся обязательной.

Descriptor содержит `schema: 1`, абсолютные пути `journal` и `manifest`, их
`journal_sha256` и `manifest_sha256`, объект `bridge` и карту `exits` по UUID
замороженной topology. Каждый exit указывает `stage`, `request_sha256` и старый
bootstrap selector `alias` (`exit_0`, `exit_1`, …). Bridge указывает `stage` и
`request_sha256` успешного `rollback-adoption`, а также `checkpoint` и
`checkpoint_sha256`. Локальные descriptor, journal и manifest должны принадлежать
оператору, иметь приватные права и не проходить через symlink. Рядом с manifest
требуется весь прежний release-комплект. Journal связывает source commit, version,
SHA manifest и remote attempt и должен подтверждать отправку mutator.

На bridge адаптер отдельно проверяет root-владение доказательств, успешные
request/job/receipt одного attempt, selector и адрес exit, роль `exit`, прежние
SSH host keys и relay SHA из frozen inventory. Полный сохранённый операторский
комплект проверяется по manifest в исходном `operator-inputs/manual-…/release`.
Для bridge UUID rollback-request задаёт единственный checkpoint adoption;
проверяются его закреплённый SHA и сохранённый emergency relay. Прочитанный SHA
работающего бинарника не заменяет эти доказательства. Несовпадение останавливает
обновление до maintenance и активации.

Проверенные входы и нормализованные fallback manifest сохраняются приватно в
каталоге операции (`baseline.*.json`); при повторе они не могут измениться или
исчезнуть. Activation, rollback и retention используют прежний manifest каждого
exit и отдельный emergency manifest только для relay на bridge; bot, client и
recovery manifest bridge сохраняют свой прежний контракт. При переносе команды
на другой controller заранее перенеси приватные локальные доказательства и
перепиши только их локальные пути, сохраняя SHA и исходный remote attempt.
Источники: [адаптер входов](../cmd/ultra-install/upgrade_baseline.go),
[проверка root-доказательств](../deploy/ansible/library/ultra_upgrade_baseline.py),
[синтетические проверки](../scripts/test-ansible-upgrade-baseline.py).

Если legacy activation завершилась до записи maintenance checkpoint, rollback
сначала доказывает владение lifecycle gate, точный работающий legacy executable
и активные recovery timers, а также исходные runtime images и prepared/rolled-back
journals той же generation. Проверка выполняется до runtime/domain rollback;
DNS-подготовка компенсируется отдельно. Только этот проверенный случай пропускает release
компенсацию и readiness probe: остановки producers и изменения relay/config ещё
не начинались. Неоднозначное состояние сохраняет закрытый gate для восстановления.
Первый и повторный синхронный capture используют отдельный collector из проверенного
подписанного release; активные tools и их rollback inventory обновляются позже.
Это применяет исключения временного subscription probe URL уже к первому архиву.

Источники: [upgrade](../deploy/ansible/playbooks/upgrade.yml),
[maintenance barrier](../deploy/ansible/library/ultra_upgrade_maintenance.py),
[rollback](../deploy/ansible/playbooks/rollback.yml).

Перед lifecycle reservation и установкой cleanup обычный upgrade отдельным свежим
read-only заданием проверяет на bridge отсутствие `lifecycle-retired.json`.
Файл означает, что прежний controller мог не соблюдать выведенные из эксплуатации
операции; текущий контракт не доказывает безопасный rollback через такой controller.
При наличии файла upgrade прекращается до maintenance и активации, не запуская
cleanup, который мог бы возобновить уже остановленные службы. Проверка выполняется
заново при каждом запуске и повторе; результат прошлой попытки не кэшируется.
Защита перед rollback остаётся отдельной проверкой.
Источники: [upgrade preflight](../cmd/ultra-install/ansible_upgrade.go),
[read-only playbook](../deploy/ansible/playbooks/inspect-upgrade.yml),
[rollback floor](../deploy/ansible/roles/release/tasks/controller-rollback-preflight.yml).

Служба `ultra-ansible-controller` работает на bridge независимо от relay и бота.
Она принимает ограниченный набор заданий через Unix-сокет. Root-peer управляет
резервированием lifecycle; relay может подавать только типизированные задания
настройки exit и реплик. Произвольные команды, inventory и playbook-пути
через сокет relay не принимаются.

Идентификатор операции отличается от имени её playbook: смена домена использует
общую реализацию ingress, а операторская и служебная настройка exit — общую роль
выхода. Фиксированная таблица исполнителя сохраняет разные задания и полномочия;
общая реализация не разрешает relay выбирать произвольный playbook.

Клиент открывает бинарник, SSH identity и pins со своими правами и передаёт
дескрипторы через SCM_RIGHTS. Worker фиксирует приватные копии и SHA, сохраняет
UUID операции и квитанцию попытки. Изменённые входы не подменяют сохранённое
задание. При отключении клиента работа остаётся в очереди; после перезапуска
worker продолжает незавершённые задания. Неуспешная попытка не становится
успешной из-за старой квитанции.

Явный повтор подготовки exit сохраняет новую генерацию задания в облачной
операции. Купленная VM, UUID и SSH pins остаются прежними; автоматический цикл
не снимает блокировку завершившегося ошибкой задания.

Локальный CLI публикует каталог задания атомарно после записи входов и полного
встроенного комплекта Ansible. Ошибка записи при подготовке не оставляет
полузаписанную операцию, мешающую повтору; опубликованные входы и комплект
при повторном запуске не заменяются. Источник: [подготовка задания](../internal/deployansible/local_prepare.go).

Операторский `ansible-retry-bootstrap --state-dir <original-stage>` продолжает
исходный bootstrap-комплект под блокировкой из frozen request и удерживает
дескриптор действующей lifecycle reservation bridge до завершения этапа.
Удалённый режим и старые попытки без `execution-mode.json` отклоняются до
блокировок и исполнения с `retry_remote_lifecycle_attachment_unsupported`:
этот интерфейс не умеет удерживать удалённый дескриптор bridge во время этапа.
Ошибка архивируется и синхронизируется до смены номера попытки; успешные этапы
остаются кешированными.
Этот интерфейс также очищает оставшуюся с прежних установок блокировку
failed-версии автоматического канала.
Таймаут исполнителя прекращает локальную группу Ansible/SSH до записи terminal
receipt. Отмена оператора прекращает ту же группу, но оставляет задание
незавершённым для безопасного продолжения.

Новые установки фиксируют компонентный движок до применения: PostgreSQL,
каждый exit по очереди и bridge выполняются отдельными сохраняемыми заданиями.
Общий снимок и блокировка не меняются; bridge получает TLS pins только из
проверенных квитанций exit. Ограничение времени относится к каждому этапу,
а не суммарной подготовке всех серверов.
Старые monolithic jobs сохраняют прежний комплект. Явный
`ansible-bootstrap-components --state-dir <original-stage>` допускается только
при действующей исходной reservation без rollback: он сохраняет исходные роли,
добавляет фиксированный компонентный протокол и связывает результаты с родительским
журналом. Продолжение всей операции проверяет эту цепочку перед пропуском старого
base-этапа; исходная failed receipt не подменяется успешной.

Одна блокировка сериализует изменяющие операции; persistent lifecycle
резервирует топологию на всё применение. Проверки БД и управляющих API
дополнительно дожидаются уже начавшихся облачных и административных операций.
Стадия пассивной проверки разрешает нужную эксплуатационную работу, но
не публикует новые exit посреди обновления. Входы и очереди не являются
родительскими процессами Ansible. Вывод Ansible подавляется; публичная ошибка
содержит безопасные действие, этап, роль узла и код причины.

Для явного отказа от зависшей попытки в `applying` root-оператор на bridge
может выполнить `ultra-install ansible-lease --retire --id <uuid>`. Нужен точный
канонический UUID попытки; `--phase`, `--resume-frozen` и позиционные аргументы
с этой командой несовместимы. Broker сначала сохраняет постоянный retirement
fence для этого UUID, затем освобождает reservation. Старую попытку после этого
нельзя продолжить, повторно зарезервировать или присоединить к её lock. Команда
не выполняет rollback и не подтверждает исправность инфраструктуры: перед новой
операцией оператор должен сверить фактическое состояние узлов.

Ошибка `infrastructure_busy` после retirement означает, что fence уже записан,
но внешний процесс ещё удерживает infrastructure lock. Заверши старый операторский
процесс штатно и повтори retirement с тем же UUID. Не удаляй lock-файл или
`lifecycle-retired.json` вручную: fence должен сохраняться после перезапуска broker.
Неподдерживающий retirement broker и любой неподтверждённый ответ завершают команду
ошибкой; успешный ответ должен явно подтвердить состояние `released`.

Источники: [исполнитель](../internal/deployansible/service.go),
[lifecycle](../internal/deployansible/lifecycle.go),
[локальный адаптер](../internal/deployansible/local.go).

## Первоначальная установка и принятие

### Ручная выкладка через bridge

`make deploy` запускает `scripts/manual-deploy.py` для точного committed `HEAD`;
tracked-дерево должно быть чистым. Главный сервер установки всегда `bridge`:
на нём работают VPN-вход и управляющий исполнитель. Статические `exit` — отдельные
узлы выхода трафика. Канонический `install.config` задаёт bridge и статические узлы.
Операторский SSH подключается напрямую к bridge, а bridge-контроллер открывает Ansible
SSH-соединения к exit. Exit не используется как jump host для входа оператора на
bridge. Для helper передайте локальные пути к bridge-ключу и файлу pins:

```sh
ULTRA_OPERATOR_IDENTITY=/secure/operator/ssh-key \
ULTRA_OPERATOR_KNOWN_HOSTS=/secure/operator/known_hosts make deploy
```

Для незавершённого upgrade-журнала, созданного до перехода на прямое SSH к bridge,
явное восстановление сначала сверяет прежнюю transport-привязку и выполняет новую
read-only аттестацию bridge по его текущему pin. Если в прежней привязке использовались
exit-identity (`ULTRA_OPERATOR_IDENTITY` или `MAIN_EXIT_SSH_KEY`) и его host-key pin,
их локальные метаданные и pin должны оставаться доступными и неизменными до завершения
recovery; соединение через exit при этом не открывается. Новые журналы привязываются
только к прямому SSH на bridge.

При запуске из отдельного worktree путь к каноническому файлу можно передать через
`INSTALL_CONFIG=/absolute/path/to/install.config make deploy`. Для конфигурации
используйте режим 0600; обновление сохраняет исходный режим.

Для upgrades, меняющих subscription/domain/runtime параметры, добавьте
`ULTRA_SUBSCRIPTION_PROBE_URL=https://current.example.com/sub/<token>` в приватный
локальный `.env` рядом с canonical `install.config` (обычный файл владельца,
0600, без symlink/hardlink). Скрипт
читает только этот literal key, без sourcing, interpolation или process env.
Hostname URL должен совпадать с текущим публичным subscription endpoint из
наблюдаемого состояния; при cutover тот же token проверяется на новом endpoint
из `SUBSCRIPTION_DOMAIN`.
Из отдельного worktree источник можно указать через
`SUBSCRIPTION_PROBE_ENV_FILE=/secure/operator/.env make deploy` либо
`scripts/manual-deploy.py --subscription-probe-env-file /secure/operator/.env`.
URL не добавляется в `install.config`, аргументы команд или журналы. Его отдельная
копия 0600 передаётся по pinned SSH для acceptance; весь `.env` не передаётся.
При отсутствии default `.env`/key обычный upgrade продолжает работу без probe;
upgrade, требующий acceptance, отклоняется installer до изменения runtime.
Явно указанный отсутствующий файл/key или небезопасный файл отклоняется до
изменения canonical config.

Журнал и удалённый staged input связывают probe digest с точными candidate/config
inputs. Failed retry использует frozen копию; явно переданный новый источник
должен содержать тот же URL. После успешных upgrade и status копии с URL удаляются,
а digest остаётся для проверки replay. Interrupted cleanup повторяет только
очистку completed operation. После завершения повтор того же candidate требует
тот же allowlisted URL; изменение credential не создаёт новую попытку. До dispatch
ошибки удаляют локальную копию и пытаются очистить удалённую; если SSH cleanup
не подтверждён, скрипт сообщает фиксированное предупреждение для reconciliation.

Ключ должен быть выделенным файлом с правами 0600, а host keys — проверенными
заранее. SSH использует `-F /dev/null`, `StrictHostKeyChecking=yes` и только эти
локальные path refs; пользовательский `~/.ssh/config` не читается. `.env`, SSH
private key и known_hosts не копируются на сервер.

`ULTRA_OPERATOR_INVENTORY` остаётся необязательным compatibility route для
продолжения существующего failed adoption artifact из `adopt-*/compare/`. В этом
случае скрипт проверяет provenance артефакта. Для обычной ручной выкладки отдельный
inventory не нужен и вручную его создавать не следует.

После локальной сборки и проверки release скрипт передаёт на bridge полный комплект
и точный canonical `install.config` в
`/var/lib/ultra-ansible/operator-inputs/manual-<SHA>-<attempt>/release`. В конфигурации
обновляются только `ULTRA_AUTOMATION_VERSION` и `ULTRA_AUTOMATION_RELEASE_DIR`;
`.env` и иные секреты не передаются. На bridge выполняются `doctor`, затем
`operator-upgrade` и `status`. Эта отдельная команда сверяет source commit, SHA-256
manifest и config, все хеши assets и совпадение собственного исполняемого installer
с записью manifest; эти значения приходят по pinned SSH transport. Обычная команда
`upgrade` сохраняет обязательную проверку подписи GitHub Releases. Операторский
sidecar-lock рядом с canonical config сериализует выкладки из разных worktree,
передающих один и тот же `INSTALL_CONFIG`. `RETRY_FAILED=1` включает recovery
preflight для поддерживаемого retry, но не снимает защиту от повторной отправки
старого mutator. Для неудачной `--forward-only` операции есть
отдельный явный `scripts/manual-deploy.py --continue-forward-only --config
/absolute/path/to/install.config`. Он сохраняет digest исходного production-журнала
из `forward_journal_sha256`, а журнал неудавшегося кандидата хранит отдельно как
историю повтора и передаёт её digest вместе с новым кандидатом. Команда допускает
сохранённые handoff/drain и broker-bootstrap receipts при неизменных staged input,
SSH transport и lifecycle исходной операции в фазе `applying`. Installer
самостоятельно сверяет подписанный release, frozen plan, предыдущее доказательство,
stage receipts и отсутствие activation.

Для устаревшего локального журнала legacy adoption, когда оператор подтвердил,
что **все прежние целевые серверы уничтожены или переустановлены**, предусмотрено
отдельное локальное архивирование. Сохранённый SSH host key не доказывает
сохранение старого сервера или завершение старого mutator. Команда принимает только
schema 1, `adopt: true`, `stage: adoption_apply`, `mutator_dispatched: true`,
commit-derived `v0.0.*`, корректные remote attempt/hash metadata, legacy `transport_binding` как lowercase
SHA-256 и точный приватный
backup, указанный журналом. Remote attempt и исходный candidate config digest
пересчитываются по backup. Журналы с `staged_config_sha256` или forward-proof
полями, а также журнал upgrade этим способом снять нельзя.

Оператор заранее фиксирует SHA-256 текущего canonical config, исходного
`dist/manual/operation.json` и его `install.config.before-*` backup и выполняет:

```sh
python3 scripts/manual-deploy.py --archive-reimaged-adoption \
  --config /absolute/path/to/install.config \
  --acknowledge-former-hosts-reimaged \
  --archive-reason 'All former deployment targets wiped or reimaged; operator acknowledgment' \
  --journal-sha256 <original-journal-sha256> \
  --backup-sha256 <original-backup-sha256> \
  --config-sha256 <current-canonical-config-sha256>
```

Это самостоятельная операция; `ADOPT` должен отсутствовать или равняться `0`,
deployment/retry/build/probe-флаги вместе с ней запрещены. Она не требует clean
Git tree или сборки, не открывает SSH, не проверяет рабочие узлы и не запускает
выкладку. Канонический config остаётся байт-в-байт прежним с режимом 0600;
backup также сохраняется. Все входы должны быть обычными принадлежащими оператору
файлами 0600 без hard links и symlinks; state directory требует 0700.

Доказательства сохраняются в приватном каталоге
`dist/manual/operation.reimaged-adoption-<original-journal-sha256>/`:
исходные байты `operation.json` и `metadata.json` с временем, явным acknowledgment,
причиной, путём canonical config и тремя digest. Сначала metadata фиксируется через
fsync и атомарную публикацию каталога, затем исходный журнал атомарно переносится
без перезаписи назначения (`renameat2(RENAME_NOREPLACE)` на Linux); оба каталога
синхронизируются. Команда держит deployment lock и canonical config lock.
Повтор с теми же digest, config path и причиной проверяет архив и завершает
прерванный перенос либо подтверждает уже сохранённый архив. Любое несовпадение,
collision или изменение config блокирует операцию. Прерванная публикация может
оставить приватный `.reimaged-adoption-*` каталог; он сохраняется как доказательство
и не удаляется автоматически. Архивирование само по себе не подтверждает состояние
новой fleet: следующая выкладка проходит обычные build и operator gates отдельно.

После handoff O→A подтверждённый containment останавливает relay, bot и
автоматические timers всей frozen fleet. Переход от такого кандидата A к B
отклоняется с `upgrade_forward_contained_continuation_unavailable` до нового
fleet census, получения lease A и supersede A→B. Сохранённые receipts и frozen
inputs продолжают проходить проверку; lifecycle A остаётся в `applying`.
Для восстановления требуется вмешательство оператора: автоматический протокол
проверки и подготовки следующего кандидата при остановленных службах пока
не реализован. Это ограничение действует и при наличии дополнительных полей
baseline в inspection: они сами по себе не разрешают продолжение.

Containment receipt подтверждает только остановку, а не исходное состояние
bot, timers или физическую identity БД. В частности, containment останавливает
`certbot.timer` и не восстанавливает его исходные active/enabled состояния.
Их нельзя восстанавливать по догадке из уже остановленных служб. До появления
версионированного протокола с проверенной исходной baseline автоматическое
продолжение после containment не поддерживается.

Если текущий broker не поддерживает atomic lifecycle supersede, upgrade сначала
проверяет его работающую identity и выполняет broker-only bootstrap из подписанного
кандидата, удерживая predecessor lock. Для независимо обновлённого Ansible
controller frozen inventory может дополнительно закрепить его managed directory и
SHA-256 unit-файла. Fallback допускается только при отсутствии обычного совпадения и
только если единственный сохранённый root-owned private operator input подтверждает
тот же source commit, installer/runtime assets и отрендеренный unit; проверяются
хеши и происхождение сохранённой сборки, но не Minisign-подпись этого старого input.
После restart тот же lock принимается новым broker; затем выполняются свежий fleet
census, сохранение handoff intent и supersede. Повтор разрешён только для того же
кандидата; переход к новому кандидату возможен только через `--continue-forward-only`
с неизменными входами и аттестацией предыдущей попытки. Для предыдущего failed
bootstrap принимается только доказанный отказ первой read-only guard-задачи: её
request/job/receipt и diagnostic должны совпадать, а `result.json`, activation и
handoff должны отсутствовать. Остальные неполные или failed bootstrap stages,
неизвестные файлы, изменение входов, другой lifecycle и несовпадение broker identity
блокируют продолжение. Внутренняя причина guard failure не входит в sanitised
diagnostic; installer повторно проверяет полный запрос и живую identity до замены
broker. При отсутствующих, неоднозначных или повреждённых доказательствах lifecycle
остаётся закрытым в `applying`; этот путь не восстанавливает неизвестный relay и не
меняет БД.
`RETRY_FAILED=1` не разрешает использовать failed candidate как predecessor.
Для принятия уже работающего runtime используйте
явный запуск:

```sh
ADOPT=1 ULTRA_OPERATOR_IDENTITY=/secure/operator/ssh-key \
ULTRA_OPERATOR_KNOWN_HOSTS=/secure/operator/known_hosts make deploy
```

Он выполняет `doctor`, `adopt --check --adopt-runtime --bridge-native`,
`apply --adopt-runtime --bridge-native` и `status`; без `ADOPT=1` adoption не
запускается. Отдельного фонового или автоматического обновления этот механизм не
устанавливает.

До запуска изменяющего задания ошибки staging, `doctor` и read-only adoption
сравнения восстанавливают прежний локальный config и очищают журнал. После отправки
`upgrade` или `apply` при ошибке новый config и приватный журнал сохраняются, так
как удалённое задание может продолжаться. `ultra-install status` сообщает о
готовности сервисов, но не доказывает завершение старого удалённого задания и не
снимает блокировку выкладки. Для dispatched `upgrade` используйте описанный выше
явный `--forward-only` только после его preflight. Dispatched `adoption_apply`
текущий wrapper продолжить не умеет: он блокирует retry, пока отдельный протокол не
сделает fencing всех источников dispatch и host-bound подтверждение drain на frozen
target set. Для такого журнала не восстанавливайте config вручную, не удаляйте
журнал и не запускайте другой commit; одного `status` недостаточно. Канонический
`install.config` должен оставаться обычным файлом владельца с правами 0600.
Группам и другим пользователям запрещена запись.

`make deploy-build` только собирает и проверяет кандидата без изменения config и
узлов. Общая инструкция по выкладке находится в [README](../README.md).

Для принятия действующего runtime используется явный `--adopt-runtime` в
`adopt --check` и `apply`. Обычный bootstrap сохраняет отдельное назначение:
он применяет заданные параметры новой установки.

При принятии включённые выходы, приоритеты, UUID и TLS pins читаются из PostgreSQL;
для динамических узлов проверяется связь с завершённой облачной операцией и
закреплённый SSH-ключ. Снимок топологии повторно проверяется перед изменениями
и активацией bridge. Исторический bootstrap-файл не является источником членства
непустой БД. Существующие сертификаты обязательны; их скрытая регенерация запрещена.

Spec и окружение сохраняются. WARP проверяется на порту сохранённого spec без
перенастройки. Geo-assets проверяются по сохранённым SHA-256 и размеру без загрузки
новой версии. Ingress принимает только подтверждённые файлы и проверенную публикацию,
сохраняя существующий renewal hook и настройки дополнительных входов.
После переноса домена старый renewal hook принимается только вместе с прежним
подтверждённым Nginx-входом, alias hook и действующей линией сертификата.
Read-only сравнение проверяет доступность сохранённого spec для пользователя
relay после перезапуска; при откате нечитаемый spec получает нужного владельца
до запуска службы.
Бинарники проверяются по прежнему release manifest либо точному новому кандидату
при продолжении незавершённой операции. Если предыдущая попытка уже завершилась
совместимым откатом, новый `adopt` на bridge принимает работающий аварийный relay
только после новой проверки фиксированного emergency manifest, хеша и размера
бинарника, возможностей учёта и диапазона схемы БД. Для exit это исключение
не действует; неизвестный unit нельзя принять только на основании прочитанного
с сервера хеша.

Если exit доступны только с действующего bridge, оператор может запустить
`adopt --check --adopt-runtime --bridge-native` или
`apply --adopt-runtime --bridge-native` непосредственно на нём. Используется
серверный путь существующего SSH identity; приватный ключ не переносится на
локальную машину. Этот первоначальный режим требует root, согласованных
recovery metadata, установленного bridge spec и совпадения адреса с локальным
интерфейсом. Он сохраняет привязку к machine-id в журнале.
Первоначальный native executor отличается от режима установленного broker:
появление broker в середине попытки не меняет способ исполнения и исходную
блокировку stateRoot. Для отдельного повтора frozen bootstrap-этапа native
executor после проверки machine-id дополнительно получает у локального broker
дескриптор действующей reservation с точным lifecycle UUID. Оба дескриптора
удерживаются до завершения этапа; недоступный broker, снятая или retired
reservation запрещают повтор. Продолжение на другой машине запрещено. Следующая
новая операция без этого явного флага использует обычную проверку установленного controller.

Перед применением выполняются read-only inspection и проверка владения.
Нечитаемый spec, неизвестные файлы, изменённые units, pins или частично
несовместимая схема блокируют перезапись. Существующие UUID, токены,
TLS-ключи, пользовательский расход и настройки подписок принимаются без
автоматической ротации. Генерируемые идентификаторы фиксируются до первого
изменения: повтор незавершённой попытки использует тот же снимок.

Секреты bootstrap-плана передаются исполнителю через приватный временный файл,
не через stdout; Ansible удаляет файл и при ошибке потребителя. Отказ получить
lifecycle gate не запускает расписания и не освобождает чужую резервацию.
Возобновление расписаний возможно только после подтверждённого получения gate.

Для legacy relay без persistent gate переход требует свежего независимого
поколения и проверенного совместимого emergency binary. Старый управляющий
процесс останавливается в ограниченном окне обслуживания; schedules
приостанавливаются, текущая копия завершается. При ошибке до применения
возвращается проверенный прежний процесс. При ошибке после изменений
восстанавливаются конфигурация и совместимый бинарник; БД, ledger и bbolt
назад не откатываются. Успех и освобождение gate требуют проверки работы.
Первоначальная незавершённая установка сохраняет состояние для повторения.
После успешной проверки отдельная приватная запись связывает завершение с хешем
замороженного inventory. Потерянный ответ освобождения gate или ошибка записи
локального журнала повторяют только завершение и не откатывают принятую установку.
Локальность определяется приватной привязкой к физической машине: недоступность
её broker вызывает ошибку, а не переключение на SSH к тому же серверу.

Роли используют стандартные модули Ansible; команды остаются для прикладных
CLI и отдельных операций без подходящего модуля. Units имеют единственный
источник в [ролях](../deploy/ansible/roles/relay/templates/ultra-relay.service.j2),
отдельной установочной копии в Go нет.

## DNS и TLS

`DNS_PROVIDER=vultr`, `DNS_ZONE`, `DNS_TTL`, `DNS_SUBSCRIPTION_NAME` и
`DNS_VPN_NAME` задают принадлежащие ultra записи. Defaults имён — `sync` и
`edge`, TTL — 300 секунд; допустимый диапазон 120–86400. Имена согласуются
с `SUBSCRIPTION_DOMAIN` и `VPN_DOMAIN`. Зона должна быть заранее создана
и делегирована; обычное применение не регистрирует домен и не меняет apex.

По умолчанию оба входа указывают на bridge. Nginx разделяет HTTPS по имени,
использует Certbot webroot и сохраняет прежние входы при cutover.
`automation.ingress.forward_host` сохраняет отдельный forwarding-узел.
Записи и файлы принимаются по ownership receipt; чужие изменения блокируют
замену. Обновление действующего основного endpoint требует отдельного
`domain-cutover`, не выполняется молча обычным `apply`.
`domain-cutover` читает общий `ULTRA_SUBSCRIPTION_PROBE_URL` из заданного
`SECRETS_ENV_FILE` (с прежними источниками пути `BOT_ENV_FILE`/`.env`), а ручной
upgrade — из локального приватного `.env` рядом с canonical config либо файла,
явно указанного через `SUBSCRIPTION_PROBE_ENV_FILE`.
Подробности: [HTTPS-вход](subscription-ingress.md) и [TLS](../deploy/TLS.md).

## Обновление и откат

Полный релиз содержит manifest, все бинарники поддерживаемых архитектур,
recovery-tools, Ansible sources и офлайн-зависимости. Manifest фиксирует
исходный commit, SHA-256, размер, диапазон схемы и capabilities.
Неполный, изменённый или несовместимый комплект отклоняется до активации.
SQL-миграции остаются прикладными и расширяющими.

Обновление фиксирует динамическую топологию и контрольную независимую копию.
Exit обновляются по одному с проверкой передачи, затем bridge: relay,
готовность, бот. Сохраняются совместимые бинарники и исходные manifest/signature.
Текущая версия и происхождение файлов не определяются по имени symlink.
Полный успех требует актуальной копии, реплик, мониторов и квитанции попытки.

Хранение исполняемых комплектов ограничивается текущим релизом и одним
проверенным совместимым аварийным комплектом. Незавершённая операция и её
живой подписанный кандидат временно сохраняют дополнительные ссылки.
Очистка проходит под общей инфраструктурной блокировкой после проверки
полного комплекта; автоматический загрузчик также очищает доказанно устаревший
кеш перед следующим скачиванием. Ссылки текущей службы, резервной политики,
незавершённых заданий и состояния подписанного канала защищают файлы от удаления.
Приватные квитанции владения фиксируют полный состав и SHA; изменённые,
неизвестные и незафиксированные каталоги сохраняются с диагностикой.
Данные SQL, bbolt, ledger, поколения копий и история операций не очищаются
этой политикой. Терминальные служебные задания могут удалить проверенную копию
relay и immutable Ansible bundle; завершённые одноразовые задания очистки
освобождают собственный bundle при следующем проходе до проверки текущего кода,
поэтому постоянный отказ этой проверки не накапливает исполняемые комплекты
очистки. Операторские комплекты незавершённых и неудачных операций остаются
доступными для продолжения после потерянного ответа или явного повтора.
Успешные bootstrap и upgrade получают отдельную приватную квитанцию всей
операции: она связывает frozen inputs, выбранную успешную генерацию,
терминальные квитанции стадий и полные составы исполняемых деревьев.
После подтверждённого освобождения gate и завершения cleanup завершённые копии
Ansible bundles и recovery tools могут удаляться даже у текущей версии;
необходимые общие комплекты и локальные кеши зависимости защищены ссылками.
Повтор той же завершённой операции проверяет сохранившиеся метаданные.
Read-only ingress status и adopt используют временные каталоги с удалением
после освобождения lease. Дополнительные изменяющие команды пока сохраняют
операторские комплекты; расширение terminal closure и очистки относится к TODO
после приёмки MVP. Bridge-migrate сохраняет возможность rollback.
Прерванное наблюдение готовности сохраняет исходную квитанцию: отдельное
подтверждение связывает её с успешным наблюдением того же релиза; прерванные
изменяющие стадии по этому правилу не завершаются.
Локальные пользователи runtime держат shared lease до последнего subprocess;
подготовка и очистка используют exclusive lease вне удаляемого дерева.
Перед рекурсивным удалением сохраняется намерение с исходным составом:
после прерывания допускается только неизменённое подмножество известных файлов.
Неизвестный или изменённый файл сохраняет дерево.
Квитанции владения входят в поколения восстановления, чтобы восстановленный
контроллер сохранял тот же контракт очистки. Источники:
[проверка владения и ссылок](../deploy/ansible/library/ultra_release_retention.py),
[очистка релиза](../deploy/ansible/roles/release/tasks/retention.yml),
[очистка кеша](../deploy/ansible/playbooks/retain-artifacts.yml),
[квитанция всей операции и локальные зависимости](../cmd/ultra-install/operator_retention.go).

При провале проверки дальнейшая выкладка останавливается; совместимый откат
не превращает операцию в успешную. Расход, SQL, credentials и сроки автономности
назад не откатываются. Emergency binary должен подтверждать
`service-access-v1`, `provider-pool-quota-v1` и поддерживать фактическую схему.
Неизвестный manifest или fallback из прежнего квотного режима блокирует
обновление. Старая автоматическая конверсия с откатом в cache-only через Python
удалена: такой бинарник нельзя считать совместимым откатом новой операции.

Повтор незавершённого задания проверяет фактические SHA и продолжает тот же
снимок. Изменённая топология не подменяет попытку. Неудачная версия автоматически
не активируется повторно; явный retry сохраняет историю и проходит preflight.
Повторная активация создаёт отдельную генерацию `publish`, `rollback` и `commit`:
новое время проверки не меняет frozen inputs предыдущей генерации.
Проверка готовности использует время активации выбранной генерации, не квитанцию
первой попытки; источник — [bootstrap readiness](../cmd/ultra-install/ansible_automation_bootstrap.go).
Проверки контрактов: [Go upgrade](../cmd/ultra-install/ansible_upgrade_test.go),
[проверка роли через SSH](../scripts/test-ansible-release.py),
[квитанции и свежесть](../scripts/test-ansible-release-contracts.py).

## Реплики, копии и восстановление

Поддерживается один PostgreSQL 16 на отдельном сервере, который не выполняет
роль bridge или exit. В каноническом `install.config` задаются `DATABASE_IP`
и `DATABASE_SSH_KEY` (путь к операторскому ключу); `SSH_USER` общий.
Для VPN-хостов используются `BRIDGE_IP` / `BRIDGE_SSH_KEY` и
`MAIN_EXIT_IP` / `MAIN_EXIT_SSH_KEY`. Старые имена полей отклоняются.
В JSON-плане ключи находятся в `ssh_identity` соответствующей роли.
`DB_NAME` и `DB_USER` задают имена БД и прикладной роли. Файл находится в корне проекта, исключён из Git и
не содержит секретов; его можно читать. Содержимое приватных ключей и `.env`
в конфигурацию и документацию не переносится.

Bootstrap устанавливает PostgreSQL primary на DB-хост и отдельный standby cluster
на bridge, создаёт отсутствующие прикладную и replication-роли без смены
имеющихся паролей, затем настраивает закреплённый SSH-туннель:
bridge `127.0.0.1:25432` → DB `127.0.0.1:5432`. PostgreSQL слушает только loopback.
На bridge создаётся отдельный служебный ключ с разрешением forwarding только к
DB loopback; этот путь использует и приложение, и replication protocol.
Операторский SSH-ключ на bridge не копируется. Миграции применяет relay при
запуске на primary. Повторная установка с `REUSE_BRIDGE_SPEC=true` сохраняет
учётные данные и принимает только уже настроенный endpoint этого туннеля.
Перенос существующих данных выполняется явно перед такой установкой.

Старые операции создания произвольно выбранных физических реплик и переноса
primary вместе с bridge отключены. Фиксированная bridge standby настраивается
только частью штатного bootstrap. `bridge-migrate` не должен восстанавливать дамп поверх
общей работающей БД. Старый runtime adoption, использовавший физическую БД на
bridge как baseline, также недоступен; для dedicated DB используется bootstrap
с явно подготовленной конфигурацией. Аварийный restore направляет дамп на
`database_target`, отдельный SSH endpoint в приватном restore JSON. Он требует
пустую БД и отказывает при пользовательских таблицах; ключ доступа остаётся
на операторской машине. Текущий аварийный restore восстанавливает primary и
туннель, но заново не создаёт и не проверяет standby на bridge; после него
полная штатная топология ещё не восстановлена.

Копии сохраняют управляющие данные, ключи, geo-assets, сертификаты/webroot,
эксплуатационные инструменты и immutable controller. Одинаковое поколение
должно быть подтверждённо доставлено на текущий независимый узел: свежая
локальная копия и прежний статус `independent` сами по себе недостаточны.
Проверки после активации требуют данных новее watermark этой попытки.

Восстановление использует те же роли и проверенное зашифрованное поколение.
Прежний primary изолируют до активации нового. Расшифрованный staging не
становится резервным каноническим источником. В стенде production-сети,
API и Telegram запрещаются до запуска восстановленных служб.
Инструкции: [recovery](../deploy/recovery/README.md),
[полное восстановление](../deploy/recovery/RESTORE.md),
[перенос bridge](bridge-migration.md).

## Зависимости и проверки

[Requirements](../deploy/ansible/requirements.txt) закрепляют Ansible и зависимости.
Release packaging создаёт hash-locked wheel-комплекты для Linux amd64/arm64
и Python 3.12–3.14. Если окружения ещё нет, CLI подготавливает его из проверенного
release-комплекта, включая закреплённый pip, без Galaxy и сетевого pip install.
Версии ОС и пакетов определяют роли, а не второй набор shell-скриптов.

[Матрица разработки](development.md) разделяет быстрые тесты, настоящие SSH/Nginx
проверки и учение VM. Успех локальных тестов не означает, что эти роли уже
приняты на конкретной production-инфраструктуре.

### Начальная загрузка данных

Для чистого DB-хоста `DATABASE_DUMP` задаёт путь к локальному приватному
custom-format архиву `pg_dump`. Нужен локальный `pg_restore`: установщик проверяет
архив до удалённых изменений и закрепляет SHA-256 в плане и запросе операции.
Ansible передаёт архив напрямую DB-хосту, проверяет пустоту/отсутствие БД,
создаёт прикладную роль и БД, затем импортирует одной транзакцией. Действующую
непустую БД импорт не перезаписывает; повтор принимает только квитанцию,
связанную с архивом, идентификатором кластера и OID БД. Временный upload удаляется.
Поле предназначено для свежего bootstrap с `REUSE_BRIDGE_SPEC=false`; без него
создаётся чистая БД. Relay применяет миграции перед обслуживанием запросов.

Если дамп задан, имеющийся в нём месячный бюджет статического выхода остаётся
источником истины и расход не обнуляется. Конфигурация может не дублировать
бюджет. Если в восстановленной БД для настроенного выхода бюджета нет, настройка
статических бюджетов завершится ошибкой; для установки без дампа бюджет нужно
задать явно в `ULTRA_AUTOMATION_STATIC_NODES`.

Для установки всех узлов с нуля используйте `ultra-install apply --config
install.config`, а не `make deploy`: последний выполняет ручной upgrade/adoption.
До `apply` локально подготовьте все входы из конфигурации:

1. Соберите release-комплект (`make release-dist`) и укажите абсолютный путь к
   его каталогу и точную версию из `release-manifest.json` в канонической паре
   `ULTRA_AUTOMATION_RELEASE_DIR` / `ULTRA_AUTOMATION_VERSION`.
2. Создайте файл `known_hosts` с ключами всех трёх чистых серверов, проверенными
   через доверенный интерфейс провайдера. `ssh-keyscan` сам по себе не доказывает
   подлинность ключей. Укажите существующий локальный путь в
   `ULTRA_AUTOMATION_KNOWN_HOSTS_FILE`.
3. Установите локальный `pg_restore`; файл дампа должен быть приватным, в формате
   custom и проходить `pg_restore --list`.
   Подготовка offline Ansible runtime использует операторский `TMPDIR`; при
   ограниченной квоте системного `/tmp` задайте доступный каталог с достаточным
   свободным местом.
4. Проверьте DNS-записи и наличие нужных секретов в `.env`, затем выполните
   `ultra-install doctor --config install.config`. `doctor` безопасен и не
   подключается к серверам без сетевого режима.

`doctor` и локальная валидация не проверяют готовность внешнего backup target,
DNS propagation, выпуск сертификата или реальный VPN-трафик. Полная bootstrap
приёмка требует доставленной свежей копии на узел другого provider. Provider в
статической политике должен отличать реальные независимые домены отказа, а не
быть произвольной меткой.

При восстановлении непустого `exit_nodes` из дампа identity маршрута должна быть
согласована с новыми exit до активации bridge. Bootstrap разрешает привязать новые
tunnel UUID и TLS pins только к тем же включённым строкам, однозначно найденным
по IP и порту. Если endpoint-набор или соответствие строк изменились, активация
останавливается. Сама таблица, членство, пользователи и прочие поля при этом не
перезаписываются. Сохранение и согласование БД не подтверждают работоспособность
VPN после переустановки узлов: всё равно требуется проверить реальный трафик.

Служебный ключ bridge → exit хранится отдельно от операторских ключей:
`/etc/ultra-fleet` принадлежит root, имеет группу ultra-relay и права 0750;
сам ключ принадлежит ultra-relay с правами 0600. Резервная копия сохраняет
ключ и публичную часть, а восстановление возвращает права родительского каталога.
