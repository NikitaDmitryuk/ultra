# Границы восстановления non-DB узлов

`rebuild-non-db preflight` сохраняет только непроверенные входные доказательства.
Он не разрешает переустановку или продолжение manual deploy. Текущий интерфейс
описан в [автоматизации](automation.md#offline-preflight-переустановки-non-db-узлов).

Для локального отчёта о требованиях к прерванному forward-only upgrade доступна
команда:

```sh
ultra-install rebuild-non-db diagnose --original-journal /absolute/private/operation.json
```

Она читает только указанный файл с режимом `0600`, проверяет scope
`schema=1`, `stage=upgrade`, `mutator_dispatched=true`, `forward_only=true` и
выводит SHA-256 его точных байтов и стабильные коды blockers. Она не собирает
удалённые доказательства и не проверяет существование связанных артефактов:
`blocked-evidence-not-collected` означает отсутствие проверки, а не установленное
отсутствие файлов. Повторный запуск не создаёт checkpoint и не меняет journal
или lock. Команда заканчивается ошибкой `rebuild_non_db_preflight_blocked`,
с `evidence_collected=false`, `execution_supported=false`, `gate_released=false`.

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

## Требования к будущему исполнимому протоколу

Если исторические доказательства недоступны, нужен отдельный протокол recovery.
Следующие требования описывают границу его реализации; готовой команды пока нет.

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
