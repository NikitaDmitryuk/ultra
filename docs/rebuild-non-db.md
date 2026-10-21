# Границы восстановления non-DB узлов

`rebuild-non-db preflight` сохраняет только непроверенные входные доказательства.
Он не разрешает переустановку или продолжение manual deploy. Текущий интерфейс
описан в [автоматизации](automation.md#offline-preflight-переустановки-non-db-узлов).

## Исполнимое восстановление с сохранённым primary

Отдельная команда `ultra-install rebuild-retained-primary` устанавливает приложения
на уже переустановленные bridge и один постоянный exit. Она не вызывает provider
reimage/delete, не продолжает прежнюю операцию и не архивирует её journal.
Это узкий операторский путь: `--accept-reimaged-fleet` явно подтверждает выполненное
оператором удаление прежних dynamic exits и переустановку известных non-DB узлов;
команда не доказывает полноту исторического fleet. Полный broker recovery ниже
по-прежнему требует независимого census и completion-протокола.

Обязательные абсолютные аргументы: `--config`, `--manifest`, `--original-journal`,
новый приватный `--state-dir`, `--backup`, `--backup-sha256`, `--python`,
`--executable`. Режим `--prepare-only` проверяет входы и сохраняет приватный
`prepared-input.json`, не меняя production и не резервируя admission.

Перед render требуются `DB_CREDENTIALS_FILE` с прежним saved bridge spec
(обычный файл оператора, 0600, без symlink) и сохранённая авторизованная tunnel
identity. DSN должен содержать прежний пароль и совпадать с configured DB name/user
и loopback tunnel endpoint. Случайный password fallback запрещён; rendered DSN
повторно сравнивается с сохранённым. Backup должен быть свежим (до 30 минут),
совпадать с указанным digest, успешно проходить age authentication и чтение
`pg_restore`; полноценное тестовое восстановление этим не подтверждается.

Primary исключён из mutation inventory по точной host identity. Его Ansible-задачи
выполняют только read-only SQL. Отдельный localhost gate перед каждой mutation play
требует успешную проверку DB: unreachable, отсутствующий результат и устаревший
success marker блокируют роли. Candidate migration list должен точно совпадать с
применённым списком; это предотвращает pending migrations при старте relay, но
обычные runtime app writes после запуска продолжаются. До и после проверяются
cluster system ID, database OID, schema и уникальная enabled main route с прежним
address/port/UUID/pin. PostgreSQL provisioning/import/authorization не выполняются.

### Одноразовый admission и остановка после сбоя

Execute сначала read-only проверяет отсутствие
`/var/lib/ultra-ansible/retained-primary-admission.json` на обоих non-DB узлах.
Затем под remote locks атомарно создаёт его через `O_EXCL`, fsync файла и каталога.
Binding включает уникальный nonce попытки. Persistent root-owned systemd drop-ins
закрывают controller/reconcile admission после reboot и ручного `systemctl start`.
Primary не получает этот fence и не перезапускается.

Любой существующий marker запрещает **все** следующие execute, включая ту же
привязку, новый state-dir, неуспешную попытку и successful Ansible receipt.
SSH-held locks недостаточны: SIGKILL runner может освободить их раньше завершения
оставшегося Ansible process tree. Автоматического terminal/drain verifier и снятия
marker нет. Даже успешный запуск оставляет admission закрытым; повторная установка
требует отдельной явной ручной reconciliation с независимой проверкой оставшихся
executor-ов. Не удаляй marker или прежние proof/journal для обхода этой проверки.
Частичный claim только одного узла также требует reconciliation.

Закрытый controller admission оставляет relay/VPN, bot и Mini App web работающими,
но блокирует новые provisioning/configuration jobs для cloud exits и DB replicas.
Каталог и quote могут читаться независимо; новый offer confirm проверяет
`TopologyReady` и при недоступном controller возвращает `controller_unavailable`
до provider create. Повторный confirm уже существующей операции может вернуть
её прежнее состояние. Доступность web и main-exit VPN не подтверждает исправность
Vultr create/replica management; для этого после безопасной reconciliation нужна
отдельная проверка нового offer/create. Controller не следует включать до разбора
незавершённых прежних операций.

Источники provisioning boundary: [cloud service](../internal/cloud/service.go),
[controller readiness](../internal/deployansible/service.go),
[runtime wiring](../cmd/ultra-relay/cloud.go).

### Reconciliation successful execute и открытие controller

`ultra-install retained-primary-reconcile inspect` проверяет сохранённый successful
execute без повторного запуска Ansible. Нужны абсолютные `--state-dir` прежней
попытки, `--config`, `--manifest`, `--original-journal` с **исходными байтами** и
`--receipt` для нового файла в существующем каталоге `0700`. Команда использует
закреплённый SSH из config; локально сохраняется отдельное доказательство, на узлах
inspect только читает состояние и удерживает существующие admission locks.

Admission marker связан с `prepared-input.json.FenceEvidenceSHA256`, а result —
с SHA-256 полного prepared input; это разные digest. Поддержаны две известные
сериализации input: исходные compact JSON bytes с порядком полей вложенных typed
структур и текущая нормализация map. Saved request binding обязан совпасть с одним
из этих digest и с result. Request сравнивается семантически без потери больших
целых чисел; duplicate keys и неизвестные верхние поля отклоняются. Проверяются
оба binding, исходный request, successful receipt/result и полный inventory
`bundle.retention.json`. Отсутствующие исторические Python/Ansible binaries и
финальный `retained-primary-receipt.json` не требуют повторной установки:
reconciliation заново проверяет текущее состояние и не дописывает историю wrapper.

Под локальным operator lock и remote infrastructure/manual locks обоих non-DB
узлов проверяются точные root-owned fences, released lifecycle, отсутствие
незавершённых prepared controller jobs и executor процессов, active services и
TLS bot/main-exit. Primary/route проверяются read-only заново; `pending/unknown`
cloud operations блокируют открытие. Общий broker recovery fence/anchor также
блокирует этот узкий путь: его completion-протокол команда не подменяет.

После inspect оператор запускает `activate-controller` с теми же аргументами и
отдельным `--receipt`: все проверки выполняются заново. Только controller получает
root-owned authorization, имя которого содержит hash нового evidence, и отдельный
systemd condition. Прежний admission JSON, original journal, execute и fences
reconcile service/timer сохраняются; общий `retained-primary-admission-open` не
создаётся. Controller запускается, проверяется его socket readiness и включается
при загрузке. EOF до explicit activation оставляет controller закрытым. Ошибка
после start останавливает controller и восстанавливает его admission drop-in.
После аварийного завершения повтор разрешён только при остановленном controller,
совпадающем authorization и повторно прошедших свежих проверках; действующий
controller команда не останавливает ради повторной проверки.

Флаг `--configure-cloud-runtime` допустим только для `activate-controller` и
добавляет узкое восстановление provider runtime после controller readiness.
Используется существующий dedicated API key; отдельная fleet SSH identity
создаётся только при отсутствии и не заимствует DB tunnel identity. До открытия
controller проверяются ownership, permissions, keypair и existing provider
drop-in; после runtime stage relay перезапускается. Команда не обращается к Vultr
API и не создаёт VPS. Новый cloud offer/create/delete проверяется отдельно.

Перед runtime mutations и повторно непосредственно перед restart проверяются
root-owned relay unit и фактический ExecStart, а также SHA-256 binary на диске.
Допустим только relay asset исходного manifest, уже связанного с successful
recovery request и проверенным retained schema; unit должен совпасть с template
из исходного sealed bundle. Здоровый старый процесс не разрешает запуск другого
staged binary с возможными pending migrations.

Источники: [CLI и проверки артефактов](../cmd/ultra-install/retained_reconcile.go),
[remote admission](../cmd/ultra-install/retained_reconcile_remote.go),
[negative/crash/replay tests](../cmd/ultra-install/retained_reconcile_test.go).

Источники: [CLI и durable fence](../cmd/ultra-install/rebuild_retained_cli.go),
[executor](../cmd/ultra-install/rebuild_non_db_execute.go),
[playbook](../deploy/ansible/playbooks/rebuild-retained-primary.yml),
[crash/replay и credential tests](../cmd/ultra-install/rebuild_retained_cli_test.go),
[DB gate tests](../scripts/test-retained-primary-gates.py).

Для локального отчёта о требованиях к прерванному forward-only upgrade доступна
команда:

```sh
ultra-install rebuild-non-db diagnose --original-journal /absolute/private/operation.json
```

Без дополнительных аргументов она читает только указанный файл с режимом `0600`, проверяет scope
`schema=1`, `stage=upgrade`, `mutator_dispatched=true`, `forward_only=true` и
выводит SHA-256 его точных байтов и стабильные коды blockers. Она не собирает
удалённые доказательства и не проверяет существование связанных артефактов:
`blocked-evidence-not-collected` означает отсутствие проверки, а не установленное
отсутствие файлов. Повторный запуск не создаёт checkpoint и не меняет journal
или lock. Команда заканчивается ошибкой `rebuild_non_db_preflight_blocked`,
с `evidence_collected=false`, `execution_supported=false`, `gate_released=false`.

Для привязки к заранее выбранным точным байтам добавь
`--expected-journal-sha256 <64 lowercase hex>`. Несовпадение SHA прекращает
диагностику без отчёта. Этот pin задаёт оператор; совпадение не подтверждает
происхождение журнала. Журнал повторно читается перед выводом: изменение его
байтов во время сбора также прекращает диагностику. Это не lease dispatch.

`requirements` в JSON связывает каждый blocker с требуемым источником и
привязками доказательства. Локальный сбор принимает повторяемый аргумент
`--artifact <kind>=/absolute/private/file` только вместе с journal pin. Допустимы
`historical-targets`, `local-quiescence`, `remote-quiescence`, `provider-outcomes`,
`retained-primary`, `independent-backup`, `primary-connectivity` и
`completion-protocol`. Для нескольких прежних узлов можно передать несколько
файлов одного kind, максимум 32 файла по 1 MiB. Каждый файл должен быть обычным,
принадлежать текущему UID, иметь `0600` и единственную hardlink; symlink, включая
родительские каталоги, запрещены. Пути должны быть различными и не совпадать с
путём журнала. Не передавай приватные ключи, DSN, `.env` или сами backups:
предназначены только сохранённые публичные observations/receipts без секретов.

`unverified_artifacts` содержит только выбранный оператором kind, SHA-256 точных
байтов и размер; пути и содержимое в вывод не попадают. Содержание и подписи
артефактов не проверяются. `verified=false` для каждого файла,
`artifacts_verified=false` и все исходные blockers сохраняются даже при наличии
файлов всех категорий. Повторный сбор тех же байтов даёт одинаковый отчёт
независимо от порядка аргументов; checkpoint не создаётся. Сохранённый JSON
позволяет сверить конкретный набор входов, но не является completion receipt,
доказательством quiescence или разрешением архивировать journal.

Коды требуют точного persisted prior target manifest с predecessor chain,
независимого local dispatch/mutator и remote mutator quiescence, связанных с
операцией provider reimage/delete receipts для каждого прежнего target,
проверенной primary identity вне списка targets, отдельного свежего backup
digest с primary/config binding, подключения с прежней authorization и
доверенного completion/retirement протокола. `manifest_sha256` релиза в manual
journal не является manifest прежних targets. Сам по себе существующий
зашифрованный dump без независимого receipt и этих привязок не снимает blocker.
Утверждения `workers_fenced` или `former_targets_reimaged` во входном journal
не превращаются в доказательства. Даже после фактической переустановки известных
узлов неполная история оставляет неизвестным исход остальных прежних targets.

Регрессии [диагностики](../cmd/ultra-install/rebuild_non_db_diagnose_test.go)
проверяют эти границы, повторяемость, неизменность journal/lock, отсутствие
вывода приватных metadata и отказ operator override.

## Текущее состояние admission fence

Broker принимает подписанный recovery request и оставляет admissions закрытым.
Свободный `infrastructure.lock` не доказывает остановку controller/Ansible:
standalone Go-оператор может погибнуть, пока дочерний controller продолжает
работу. Поэтому импорт возвращает
`recovery_independent_quiescence_required`, не выдаёт `drained`, а
completion/release отключены (`recovery_completion_unsupported`). Fence остаётся
закрытым и после рестарта broker, включая старые `completed` записи. Это
admission-only ограничение, а не готовый протокол переустановки; для release
нужен независимый verifier локальных и удалённых executor-ов, связанный с fence.

Регрессия `TestRecoveryFenceOrphanedExecutorCannotProveDrain` запускает настоящий
Go `Execute`, убивает его wrapper и подтверждает, что осиротевший controller ещё
может записать mutation witness, тогда как fence отказывает drain/completion.
См. [реализацию fence](../internal/deployansible/rebuild_fence.go) и
[тест](../internal/deployansible/rebuild_fence_test.go).

## Отсутствующие доказательства прерванного upgrade

Forward-only получает исторический fleet из точных байтов
`activate/request.json`, а не из текущего config или `operator-plan.json`.
Обязательны также `activate/job.json` и `activate/receipt.json`, связанные с
хешем этого request. При отсутствии любого из этих файлов
`discoverForwardOldOperation` отклоняет операцию. Совпадение версии, наличие
operator plan или свободный lock не заменяют доказательство отправленного fleet.
Восстановить исходные файлы можно только из независимо проверенной сохранённой
копии; создавать request/receipt по текущему состоянию нельзя.

Независимо от полноты файлов `forwardUpgradeHandoff` требует lifecycle
`applying` с прежним operation ID либо проверенный ранее зафиксированный handoff
к новому ID. Состояние `released` другого bootstrap не подтверждает остановку
workers предыдущего upgrade. Изменение одной проверки wrapper не устраняет
проверки installer и broker.

`archive_reimaged_adoption` поддерживает только прежний `adoption_apply` после
подтверждённой переустановки всего прежнего fleet. Это не archive-команда для
upgrade и не протокол сохранения отдельного primary.

Источники: [discovery и handoff](../cmd/ultra-install/upgrade_forward_handoff.go),
[archive](../scripts/manual-deploy.py),
[проверки отсутствующих доказательств](../cmd/ultra-install/upgrade_forward_missing_evidence_test.go).

## Требования к полному broker recovery-протоколу

Если исторические доказательства недоступны, нужен отдельный протокол recovery.
Следующие требования описывают полный управляемый протокол с историческим census,
provider mutation и retirement; узкая операторская команда выше его не заменяет.

1. Доверенный collector независимо собирает полный исторический и текущий fleet
   через все provider accounts и pinned SSH. Исчезнувшие узлы требуют provider
   evidence уничтожения; недоступный узел не считается остановленным. Каждое
   наблюдение связано с operation, nonce, сроком действия и точными identities.
2. Перед изменением controller останавливаются и проверяются все источники
   dispatch и прежние workers. Импорт fence должен поддерживаться broker,
   сохранять прежние lifecycle/retirement journals и связывать новый recovery ID
   с проверенным census. Заявление оператора в JSON не заменяет этот переход.
3. Retained primary подтверждается по PostgreSQL system identifier, database
   OID, роли primary, migration state и привязке подключения. Требуются остановка
   writers, неизменная политика доступа и независимо доставленная свежая копия.
   Читаемость TOC архива не доказывает успешное восстановление.
4. Installer и controller одинаково проверяют scope. Executor допускает только
   явные non-DB targets; DB install/import/restore, изменения roles, slots,
   `pg_hba` и schema исключаются. Нужно также учесть косвенные подключения:
   bridge relay вызывает `db.Open`, который применяет миграции, даже если
   Ansible не выполняет задачи на DB host. Бот использует `OpenLazy` без
   миграций. Источники: [relay runtime](../cmd/ultra-relay/runtime.go),
   [бот](../cmd/ultra-bot/main.go), [DB API](../internal/db/db.go).
5. Каждая мутация имеет durable request-bound checkpoint; сбой сохраняет fence.
   После проверки служб и неизменной DB identity broker фиксирует completion
   handoff. Только такой receipt может разрешать wrapper следующий deploy.

Сохранение отдельной primary VM само по себе не обеспечивает сохранность БД:
доступ к ней остаётся у bridge и старых workers. Поэтому переустановка bridge
до проверенного fleet fence не заменяет recovery-протокол.

## Сохранение подключения к retained primary

Обычный `bootstrap-postgres.yml` не является DB-preserving executor: он
конфигурирует primary, разрешает доступ bridge и создаёт replication slot.
Исключить из него группу `databases` недостаточно. Стадия tunnel `generate`
создаёт на bridge `/etc/ultra-db-tunnel/id_ed25519`, если ключ отсутствует,
а стадия `authorize` заменяет `authorized_keys` на primary его публичной частью.
После reimage bridge новый ключ не соответствует прежнему разрешённому ключу.
Стадия `install` устанавливает pinned host keys и службу, но не восстанавливает
прежнюю клиентскую идентичность. Открытый локальный TCP listener также не
подтверждает PostgreSQL identity или успешную аутентификацию приложения.

При неизменной политике доступа новый recovery-протокол должен до удаления
bridge сохранить его tunnel identity в зашифрованном независимом хранилище,
связать публичную часть с независимо проверенной авторизацией retained primary
и восстановить её на новом bridge до старта приложений. Приватный ключ не
попадает в receipts или обычный вывод. Отсутствующий ключ, неподтверждённая
авторизация или невозможность расшифровать сохранённую копию блокируют удаление
bridge. Смена DB authorization требует отдельного явно разрешённого контракта;
она не входит в текущий preflight и не может возникнуть как побочный эффект
обычного bootstrap.

Источники: [DB bootstrap](../deploy/ansible/playbooks/bootstrap-postgres.yml),
[генерация ключа](../deploy/ansible/roles/db_tunnel/tasks/generate.yml),
[авторизация](../deploy/ansible/roles/db_tunnel/tasks/authorize.yml),
[установка tunnel](../deploy/ansible/roles/db_tunnel/tasks/install.yml).

## Порядок реализации recovery с переустановкой

Для этого пути нужен отдельный executor вне переустанавливаемого fleet. Его
доверенный ключ и полномочия должны быть закреплены заранее в controller и
проверяющем installer; `signer_id` во входном JSON не создаёт таких полномочий.
Новый протокол не должен подделывать отсутствующие `activate/*` предыдущего
upgrade. Он выпускает собственные доказательства с точной привязкой к исходному
manual journal и всей цепочке его predecessors.

Переходы должны выполняться в следующем порядке:

1. Зафиксировать полный прежний и текущий fleet, отдельную protected primary и
   независимое хранилище recovery. Текущий список provider instances не доказывает
   прежний fleet: нужны историческая принадлежность и evidence уничтожения
   исчезнувших targets. Неполная история оставляет recovery заблокированным.
2. Получить исключительный fence на dispatch, controller, automation и старых
   workers. Сохранить controller journals и полномочия вне bridge. Сам provider
   reimage уничтожает процессы на данном узле, но не fencing на другом узле и не
   запрет новой отправки от старого controller.
3. При остановленных writers проверить прежнюю primary identity и существующее
   подключение, получить свежий backup с independently verified receipt и
   привязкой к этой primary. Успешный systemd exit или один dump hash не заменяет
   подтверждение независимого получателя. Если fence теряется, переход запрещён.
4. Для каждого явного non-DB target сохранить intent до provider mutation,
   затем подтвердить завершение reimage/delete у provider и новую host identity
   либо отсутствие уничтоженного instance. Timeout оставляет outcome неизвестным
   и fence действующим; повторная отправка destructive request без reconciliation
   запрещена. Primary identity запрещена на уровне executor и controller,
   независимо от role labels и Ansible inventory.
5. Установить новый controller и non-DB службы под тем же recovery fence,
   восстановить сохранённые journals, проверить retained primary и подключение
   с нового bridge. Автоматическое применение миграций relay должно быть отдельно
   отключено или согласовано с разрешённым изменением БД до старта службы.
6. Только после доказанного исхода каждого прежнего target и проверки primary
   выпустить request-bound completion receipt. Wrapper атомарно архивирует
   исходный journal по его точному SHA, сохраняя predecessor chain, и разрешает
   следующий deploy. Сбой до receipt не снимает gate; повторное предъявление
   receipt допускается только для тех же journal, fleet и candidate.

Эта последовательность требует изменений в provider executor, broker/controller
и manual wrapper. Offline preflight не реализует эти переходы: он явно
возвращает `former_targets_reimaged=false`, `backup_verified=false`,
`primary_connectivity_verified=false` и `journal_retirement_supported=false`.
Его receipt нельзя использовать для архивирования forward-only journal.
