# Разработка и проверка изменений

Начни с [архитектуры](architecture.md) и относящихся к изменению тематических страниц.
Версия Go задаётся [go.mod](../go.mod), команды и версии проверяющих инструментов —
в [Makefile](../Makefile), обязательные проверки — в [CI](../.github/workflows/ci.yml).

## Выбор проверок

| Изменение | Проверка |
| --- | --- |
| Перед каждым коммитом | `make format`, затем `make lint`; проверь итоговый diff после автоформатирования |
| Только инструкции или документация | `make harness-check`; содержательная сверка с источниками |
| Состав релиза, manifest или публикация GitHub Release | `python3 scripts/test-release-assets.py`, затем `python3 scripts/test-release-assets.py --dist dist`: реальный комплект должен совпадать с manifest, SHA-256, архитектурами ELF, исходными архивами и закреплёнными offline wheels |
| Проверяющий инструмент harness | `go test ./tools/harnesscheck`; `make harness-check`; `go vet ./tools/harnesscheck` |
| Go-код | Тесты затронутых пакетов, затем `make test`, `make vet`, `make lint` |
| Конфигурация Xray, маршрутизация, failover | Тесты `./internal/config ./internal/exits ./internal/proxy`; сборка relay |
| Ansible upgrade с DNS/domain/runtime effects | `python3 scripts/test-ansible-dns-migration.py`, `test-ansible-upgrade-domain.py`, `test-ansible-upgrade-runtime.py`, `test-ansible-runtime-effects.py`, `test-ansible-accepted-resume.py`, operation mapping и syntax check закреплённым Ansible runtime |
| Forward-only lifecycle recovery / broker bootstrap | `go test ./cmd/ultra-install ./internal/deployansible`; `python3 scripts/test-manual-deploy.py`; `python3 scripts/test-forward-broker-guard.py`; operation mapping, release retention и syntax check `bootstrap-forward-broker.yml` |
| SQL, репозитории, миграции | Генерация SQLC при изменении схемы/запросов; `go test ./internal/db` с отдельной тестовой БД |
| Встроенные web-ресурсы или установочные скрипты | Тесты затронутого Go-пакета, пересборка соответствующего бинарника; для UI — `make test-ui` (Node.js 22+) и проверка затронутого сценария в браузере |

Сборка бинарников: `make build`, `make build-install`, `make build-bot`.
CI запускает независимые группы Go lint/vet, обычных Go-тестов с PostgreSQL,
race-тестов с отдельной PostgreSQL, сборки,
Ansible-валидации и SSH-интеграции, Nginx, Mini App/release-контракта и recovery
параллельно. Итоговый check `Lint, test, build` требует успеха каждой группы:
ошибка, отмена или пропуск группы не дают успешный gate. PostgreSQL-интеграция
и dump/restore выполняются в job обычных тестов с PostgreSQL 16; race-набор запускается
отдельно со своим PostgreSQL 16, чтобы не ждать завершения обычных тестов. Локальную проверку без БД
можно выполнить как `env -u DATABASE_URL make test`, чтобы не использовать случайно
унаследованный DSN. Пропущенную DB-интеграцию явно указывай в результате.

Перед каждым коммитом запусти `make format`, проверь получившийся diff, затем `make lint`.
Форматирование обязательно, а не best-effort: `goimports`, `gofmt`, `golines` и
`golangci-lint` имеют закреплённые версии в [Makefile](../Makefile). `make format`
также выполняет `go mod tidy`. CI запускает те же `make format-check` и `make lint`;
`format-check` завершится ошибкой, если форматирование изменило checkout. При обновлении
инструментов меняй версию в Makefile и подтверждай, что локальный запуск и CI используют
одинаковые команды.

## PostgreSQL, SQLC и ORM

DB-интеграционные тесты читают `DATABASE_URL`; без него вызывают `t.Skip`.
Успех `make test` не подтверждает выполнение этих тестов. Используй только выделенную
тестовую БД: [db.Open](../internal/db/db.go) не только подключается, но и применяет
миграции, а [DB-тесты](../internal/db/repo_users_test.go) записывают и удаляют данные.
Не подставляй DSN рабочего окружения и не копируй его в отчёт.
Общий [DB-test helper](../internal/db/repo_exit_nodes_test.go) создаёт отдельную схему
для каждого теста и удаляет её после закрытия pool. Тестовой роли нужны права
создания схем; `search_path` изолирован от `public`, чтобы данные тестов не смешивались.

Исходники запросов — `internal/db/queries`, схемы — `internal/db/migrations`.
[sqlc.yaml](../sqlc.yaml) задаёт генерацию Go-кода в `internal/db/sqlc` через pgx/v5.
Меняй исходные SQL, затем выполняй `make generate-db` из корня и проверяй
сгенерированный diff; ручная правка результата будет потеряна. Версия SQLC
закреплена в [Makefile](../Makefile) и совпадает с заголовками сгенерированных файлов.
Не обновляй генератор попутно и не принимай несвязанные массовые изменения генерации.

Обычные независимые CRUD-операции пользователей, администраторов, уведомлений,
подписок, участников, маршрутов и cloud используют GORM: явные
[модели существующих таблиц](../internal/db/orm_crud.go),
[cloud-модели](../internal/db/orm_cloud.go), проекции и карты обновлений. ORM заимствует
соединения из того же pgx pool через адаптер без idle-соединений: ORM не открывает
собственных физических соединений, лимит подключений остаётся общим. Инициализация не подключается
к PostgreSQL; автоматический ping, SQL-логирование с параметрами и неявные
транзакции отдельных записей отключены. ORM не выполняет миграций: источником
схемы остаются нумерованные SQL-миграции. Источник: [адаптер](../internal/db/orm.go).

Резервирование cloud-слотов и advisory locks, durable-пакеты трафика и IP-наблюдения
выполняются SQLC-запросами. Для пяти записей трафика
[очередь SQLC](../internal/db/queued_sqlc.go) сохраняет один pgx pipeline внутри
исходной транзакции; ORM не участвует в учёте трафика. При извлечении JSON-массивов
используй явные проекции `jsonb_array_elements`: анализатор SQLC 1.31.1 не описывает
поля табличного alias `jsonb_to_recordset` корректно. Проверяй сгенерированный SQL
и реальные DB-тесты, включая число запросов и rollback.

Граница ORM проходит по целостной операции. Транзакции регистрации участников,
выдачи subscription-токенов, UUID rotation, публикации маршрутов, provider pool,
квот и служебного доступа сохраняют pgx/SQLC и PostgreSQL locks. ExitNodeRepo
переиспользует SQLC-чтения и записи внутри сериализованной транзакции проверки
последнего enabled exit; его временный DB привязан к этой транзакции. Подмена
этих вызовов обычным ORM пула вывела бы их за пределы блокировки.
Atomic claims и подтверждения notification leases, оконные функции, bucket-
агрегации, lateral/JSON-проекции бюджета, миграции и проверки системного каталога
также сохраняют PostgreSQL SQL. Независимые чтения и записи используют ORM,
включая snapshots/acknowledgements участников и квот: карты условий и обновлений
сохраняют false, нули, NULL и сравнение исходной версии.
[AST-проверка](../internal/db/orm_test.go) запрещает возвращать полные SQL-операторы
в завершённые cloud, durable-трафик и IP-наблюдения; она не запрещает SQL-выражения
и не утверждает, что весь проект переведён на ORM. Не переносите сложную
транзакцию в независимые ORM-вызовы и не включайте `AutoMigrate`.
ORM здесь упрощает CRUD; она не является дополнительной гарантией сохранности
или доказательством ускорения. При изменении ORM-записей явно проверяйте нулевые
значения, прежние ошибки отсутствия строки и общий лимит пула.

Новая миграция требует трёх согласованных изменений: нового нумерованного SQL-файла,
директивы `go:embed` и записи в списке миграций в
[migrate.go](../internal/db/migrate.go). Одного файла недостаточно.
Уже применённую миграцию не переписывай для изменения поведения существующих установок:
используй следующую версию и проверь новый путь на тестовой БД.

## Встроенные ресурсы

Mini App встраивается из `internal/bot/embed/miniapp`, Admin UI — из
`internal/adminapi/static`. После правки нужен новый бинарник; изменение файлов рядом
с запущенным бинарником не обновляет embedded-ресурс. Источники:
[Mini App embed](../internal/bot/miniapp_api.go), [Admin UI embed](../internal/adminapi/static.go).

Для проверки кабинетов без Telegram и БД запусти `python3 scripts/preview-bot.py`:
`/preview/admin.html` и `/preview/member.html` используют те же JS/CSS, что и рабочие
экраны. [Демо-транспорт](../internal/bot/embed/miniapp/preview/demo.js) подменяет запросы
в памяти и не отправляет их на сервер; его подключают только страницы `preview/`.
Параметр `?state=disabled`, `pending` или `new` открывает соответствующее состояние
личного доступа; `?theme=dark` проверяет тёмную тему. [Сервер предпросмотра](../scripts/preview-bot.py) слушает только loopback
и отключает кеш. Копии рабочего JS/CSS в preview не создавай: иначе проверка макета
не проверяет поставляемый интерфейс. QR-коды строит встроенный `qrcode-generator`
1.4.4 ([исходник с лицензией MIT](../internal/bot/embed/miniapp/vendor/qrcode.js));
для графиков и QR внешние CDN не нужны.

Upgrade проецирует управляемые runtime-настройки на самом целевом узле: spec,
environment и точные rollback images не передаются в receipts. Fixed transport
проверяет installer по manifest и связывает host journal с digest неизменяемого
запроса; exit proof строится из bridge DB inspection и frozen strict SSH inventory.
Каждая повторная попытка activation использует отдельную runtime transaction.
Источники: [transport](../cmd/ultra-install/upgrade_runtime_probe.go),
[caller](../cmd/ultra-install/upgrade_runtime_integration.go).

Незавершённый manual journal с `mutator_dispatched=true` блокирует обычный повтор,
`--retry-failed` и использование release как baseline. Одноразовый `--forward-only`
принимает только exact journal прерванного upgrade: удерживает broker lease,
проверяет свежим playbook единственное дерево прежнего worker на bridge и каждом
узле замороженного inventory, записывает write-ahead handoff и затем меняет lifecycle ID.
Для legacy journal без digest staged-конфига wrapper требует совпадения канонической
конфигурации, attempt и закреплённого SSH transport, затем получает недостающий digest
read-only attestation точного remote root, manifest и request-bound job/receipt;
installer всё равно независимо проверяет конфигурацию, frozen plan и handoff.
Свободный flock, `status` и локальные поля `drained`/`quiescent` сами по себе не
доказывают остановку workers. Перед мутацией создаётся свежий DB snapshot, проверяется
читаемость custom archive через `pg_restore --list` и независимая доставка. Это не
репетиция восстановления: успешный список TOC не доказывает, что данные можно восстановить.
При ошибке forward-only не возвращает старый бинарник и не откатывает БД; он повторно
закрепляет тот же lifecycle gate, останавливает bot/relay и принадлежащие upgrade
таймеры/службы на замороженном inventory и подтверждает их состояние. Если gate или
остановку подтвердить не удалось, команда завершается ошибкой; считать production
безопасно переведённым в maintenance нельзя.

Для сбоя `--forward-only` до handoff операторский путь
`scripts/manual-deploy.py --continue-forward-only --config <canonical-config>`
сохраняет исходный production-журнал и отдельно привязывает журнал предыдущего
кандидата. Installer повторно проверяет оба журнала, staged config/release, frozen
plan, lifecycle и отсутствие activation. Допускаются сохранённый handoff с его
drain evidence и частичные broker-bootstrap stages; все файлы проверяются на
приватность, а installer сверяет содержимое bundle с подписанным Ansible archive.
Broker recovery читает controller identity из host variables единственного `bridge`
в frozen request inventory; lifecycle ID остаётся привязан к request variables.
Фикстуры должны сохранять это production-размещение полей.
В сохранённом drain stage допускаются точные генерируемые controller артефакты:
обычный приватный `execution.lock` и приватное дерево `.ansible` (Ansible HOME).
Workspace проверяется рекурсивно по владельцу, типам, правам и лимитам размера;
symlink и посторонние элементы stage блокируют продолжение. Наличие lock-файла
не подтверждает quiescence: operator lease, lifecycle и свежий fleet census
проверяются независимо.
Историческое дерево предыдущего успешного upgrade может содержать inspect, host,
runtime и Ansible job artifacts; безопасное дерево проверяется без предположения,
что в нём ровно три элемента, а request/job/receipt activation сверяются отдельно.

Если действующий controller не поддерживает атомарный supersede, recovery под
удерживаемым predecessor OFD проверяет broker по systemd MainPID, executable и
unit hashes, устанавливает только immutable broker runtime/unit из подписанного
кандидата и перезапускает controller. Он повторно принимает тот же OFD, проверяет
неизменный `oldID/applying`, делает новый полный fleet census и только затем
сохраняет intent и вызывает атомарный supersede. Повтор может продолжить только тот
же кандидат с подтверждёнными request/job/receipt; неоднозначный либо неполный
bootstrap stage блокирует действие. При аварии процесс может потерять kernel OFD,
но durable `applying` gate остаётся закрытым, пока новый controller не примет тот
же ID и descriptor. Rollback неизвестного relay и изменение БД этим recovery-путём
не выполняются.

Изменение staged input/SSH transport, неизвестные файлы, чужая broker identity,
activation, retirement-конфликт или несовпадение remote attestation блокируют
продолжение. `--retry-failed` не заменяет этот путь и не разрешает использовать
неудавшийся candidate как predecessor.

Retirement ledger устанавливает сохраняемый floor контроллера. Rollback и restore
на узел с ledger блокируются до первой мутации; backup включает оба lifecycle journal
и аутентифицирует `controller_enforcement_floor`. Collector всегда перечитывает
фиксированный retirement ledger даже при старой backup policy.
Restore поколения с таким floor выдаёт `controller_enforcement_migration_required`:
текущий формат не доказывает совместимость восстановленного контроллера.
Более старый snapshot на новом узле не содержит актуального floor: для его безопасной
миграции нужен независимый от snapshot монотонный checkpoint enforcement/retirement.
Эти ограничения не доказывают quiescence ранее прерванной попытки.
Источники: [manual gate](../scripts/manual-deploy.py),
[rollback preflight](../deploy/ansible/roles/release/tasks/controller-rollback-preflight.yml),
[проверка restore](../deploy/recovery/restore_common.py).

Роли и systemd-шаблоны Ansible встраиваются в `ultra-install` из
[deploy/ansible](../deploy/ansible/assets.go). Изменение установленного YAML отдельно
от бинарника не меняет уже зафиксированное задание: оно использует собственный
неизменяемый комплект. Источники системной подготовки и PostgreSQL —
[роль host](../deploy/ansible/roles/host/tasks/main.yml) и
[роль postgres](../deploy/ansible/roles/postgres/tasks/main.yml).

SSH-проверки, `make install`, выдача сертификатов и эксплуатационные скрипты могут
обращаться к рабочим узлам. Они не входят в безопасную локальную проверку изменений.
Условия их применения описаны в [README](../README.md),
[MOBILE_INSTALL](../deploy/MOBILE_INSTALL.md) и [TLS](../deploy/TLS.md).

При обновлении бинарников сначала останови бота, запусти relay и дождись готовности
Xray, затем запускай бота: `Type=simple` не означает готовность локального прокси,
а загрузка geo-правил может занять дольше нескольких секунд. Готовность нового relay
можно проверить по `reload.count > 0` и пустому `reload.error` в `/v1/hardening`;
после этого отдельно проверь полный туннель. Бот открывает ту же БД и обращается
к Telegram через локальный прокси при запуске. Источники:
[запуск relay](../cmd/ultra-relay/main.go), [запуск бота](../cmd/ultra-bot/main.go),
[systemd unit](../deploy/ansible/roles/relay/templates/ultra-relay.service.j2).

## Проверка контекста

`make harness-check` запускает локальный Go-инструмент без LLM и сетевых запросов.
Он читает `AGENTS.md` и Markdown в `docs/`, проверяет ссылки на файлы, достижимость страниц
из `AGENTS.md` и размер входной инструкции. Он не определяет истинность
текста или полезность записи и не требует изменения документации
при каждой правке кода. Правила отбора находятся в [AGENTS.md](../AGENTS.md).

Для навигации используй обычные inline Markdown-ссылки на файлы с относительными путями.
Фрагменты `#section` не проверяются; внешние URL не запрашиваются. Ссылки внутри блоков
кода не являются навигацией. Новая тематическая страница должна быть связана из уже
доступной страницы. Документация отражает текущее устройство и эксплуатационные
ограничения проекта; планы и результаты отдельных задач остаются в задаче или PR.

## Транспортные проверки

В локальных транспортных тестах REALITY готовность TCP listener не означает завершение асинхронного
определения post-handshake records. Закреплённая библиотека проверяет незавершённое
определение с шагом пять секунд; запуск тестового потока с коротким deadline раньше
готовности создаёт ложный отказ UDP или HTTP до передачи первого ответа. Фикстуры ждут
подтверждённые результаты детектора для своего адреса до запуска deadline потока
и очищают только собственные ключи после закрытия серверов. Таймаут передачи
и проверка исчерпания квоты остаются прежними.
Источники: [accounting-фикстура и регрессия](../internal/config/accounting_integration_test.go),
[проверка опубликованных профилей](../internal/config/profile_integration_test.go).

`TestActualNginxPrimaryXHTTPServerFirstInteractiveSmallPayload` проверяет основной
TLS/H2 → Nginx → XHTTP вход с ограничителем трафика: короткое приветствие сервера
должно доходить до отправки клиентских данных, затем проходит обмен малыми сообщениями.
Тест использует конфигурацию из установщика и временный Docker-контейнер; обычный
`go test` пропускает его без `ULTRA_TEST_NGINX_IMAGE`. В CI он обязателен с закреплённым
Nginx 1.24. Для локального запуска задай этот параметр как в CI и запусти тест по имени.
Контейнер слушает только loopback и удаляется после проверки. Успешный тест не
подтверждает поведение пинга в Happ на устройстве.
Источник: [проверка](../internal/config/primary_serverfirst_integration_test.go).

`TestHappBridgeFailoverLocalTransfer` проверяет неизменный клиентский JSON при отказе
и возврате двух REALITY bridge (TCP и XHTTP), включая блокировку после отказа обоих.
JSON-профили используют BurstObservatory с `sampling: 1`: результат читается как
снимок, а отказ определяется последней проверкой. В закреплённом Xray 26.9.30
обычный Observatory содержит конфликт чтения
`Observer.GetObservation` / `LeastPingStrategy.PickOutbound` и записи
`Observer.updateStatusForResult`. Не выключайте race для маскировки этого дефекта:
обычный проход транспортов не означает отсутствие гонки. Не заменяйте
BurstObservatory обычным Observatory без проверки race.
Источник: [тест](../internal/config/happ_integration_test.go),
[upstream Observer](https://github.com/XTLS/Xray-core/blob/b26a91de4f32/app/observatory/observer.go).

При проверке исчерпания квоты сначала подтвердить HTTP-успех контрольного ответа
и фактическое пересечение лимита в учтённом расходе. HTTP-ошибка внешнего тестового
сервиса не является отказом квоты. Замедленное чтение клиента может продолжаться
из уже полученного буфера после reload: после подтверждения маршрута снять
ограничение чтения и проверить неполный ответ, затем новое соединение через fallback.
Серверное прекращение потока отдельно проверяют
[транспортные тесты](../internal/config/profile_integration_test.go), а учёт расхода —
[DB-тесты квот](../internal/db/repo_quota_test.go).

Для запуска [DB-тестов](../internal/db/repo_subscription_test.go) нужен отдельный тестовый PostgreSQL.
Инструкции клиента и матрица ручной приёмки — в [Happ](happ.md).

Используется официальный Xray 26.9.30 без форка, закреплённый по коммиту
релиза `b26a91de4f32`: upstream-тег `v26.9.30` не соответствует major-версии
Go-модуля, поэтому в `go.mod` записана его проверяемая pseudo-version.
`make test-race` запускает все пакеты и транспорты, включая XHTTP, без пропуска тестов.
Vision нового Xray по-прежнему использует unsafe pointer arithmetic, несовместимую
с `checkptr` Go 1.27.1. Поэтому сохранён прежний флаг отключения `checkptr` только
для `proxy/vless/...`; race instrumentation остаётся включённой для всех пакетов.
При следующем обновлении повторить прогон без этого флага.
Xray 26.9.30 по умолчанию блокирует private IP для VLESS в freedom outbound;
локальные транспортные тесты явно разрешают только loopback. Производственные
конфигурации сохраняют новую защиту upstream.
В изолированном QEMU-стенде диапазон `198.18.0.0/15` тоже попадает под эту защиту:
успешный прямой HTTP-запрос не означает, что адрес доступен через VLESS.
[DoH стенда](../deploy/recovery/vm_doh.py) выдаёт для тестовых HTTPS-сервисов
публично маршрутизируемый fixture-адрес; только гостевая машина с маркером стенда добавляет
маршрут `/32` и
OUTPUT DNAT TCP:443 к прежнему `198.18.0.20:443` (QEMU guestfwd).
Общего маршрута в Интернет нет, `restrict=on` сохраняется. Это позволяет проверять
производственную конфигурацию Xray без отключения защиты внутренних адресов.
При сравнении прямого и туннельного запросов сохраняйте один сервер, SNI, CA и путь;
TLS sniffing может заменить IP назначения доменом из SNI.

Полная синтетическая topology-проверка использует отдельные VM и собственные ключи;
[vm_topology.py](../deploy/recovery/vm_topology.py) ограничивает TCG translation cache
параметром `tb-size=32`, чтобы шесть гостей не расходовали память на неограниченный
кеш эмуляции. Dedicated DB требует двух дополнительных VM; полный acceptance
после изменения топологии ещё не подтверждён. До запуска [vm_acceptance.py](../deploy/recovery/vm_acceptance.py)
вызовите `vm_topology_fixture.py dependencies --workspace <private-directory>`.
Команда запускает только пакеты тестовых payload/DoH-служб и возвращает
`prepared`/`pending`; pending завершается кодом 2. Повторная проверка не прерывает
активную package transaction. `payload_targets` не устанавливает пакеты скрыто внутри
SSH-запроса: отсутствие prerequisites является явной ошибкой до установки приложения
и до начала измерения восстановления.
После остановки контейнера `vm_topology.py resume --workspace <private-directory>
--memory-mb <original-value>` запускает сохранённые диски и seed без смены SSH pins
или checkpoint приёмки. Затем повторите `verify`: прежняя проверка изоляции
не переносится на новые процессы. Живой QEMU с любым диском стенда запрещает resume.

gVisor сохраняет версию, требуемую Xray: HEAD `fcb40d1a9af6` не собирается
обычным Go из-за смешения пакетов `stack` и `bridge` в `pkg/tcpip/stack`.
Форк `apernet/quic-go` также сохраняет коммит Xray: тег `v0.62.0` объявляет
другой module path (`github.com/quic-go/quic-go`) и не является совместимым
обновлением этого модуля. При следующем обновлении повторить сборку этих зависимостей.
REALITY закреплён через `replace` на совместимом официальном `e1986a4d31ca`,
с проверкой границ неполных TLS-записей и закрытием соединений детектора.
Обновление должно сохранять совместимость старого ClientHello HAPP и ABI Vision:
закреплённый Xray читает `Conn.rawInput` через unsafe как `bytes.Buffer`;
переход зависимости на указатель несовместим. Версия и замена модуля задаются
в [go.mod](../go.mod). При обновлении проверяй старый и современный Chrome ClientHello,
неполные TLS-записи, race, TCP/XHTTP и передачу внутреннего HTTPS TLS 1.3 с reload.
`TestHappLegacyClientHelloLocalTransfer` проверяет `hellochrome_120`,
`TestPublishedProfilesLocalTransfer` — HTTPS и reload. Обычный HTTP не включает
переход Vision в direct copy и не доказывает совместимость зависимости.
[Проверки детектора REALITY](../internal/config/reality_detector_test.go) защищают
обработку неполных TLS-записей и закрытие соединений после ошибки handshake.
Целевой TLS `ServerHello` закреплённой REALITY поддерживает X25519 и
X25519MLKEM768. Поэтому camouflage endpoint в тестах устойчивого учёта явно
выбирает TLS 1.3 и X25519: настройки групп по умолчанию в новой версии Go могут
дать иной обмен ключами и сорвать аутентификацию до проверки квоты. Регрессия
проверяет реальный согласованный TLS, а UDP/direct/Vision — передачу через него.
Источники: [проверки учёта](../internal/config/accounting_integration_test.go),
[граница upstream](https://github.com/XTLS/REALITY/blob/e1986a4d31ca/tls.go).

Гонка `splithttp.WaitReadCloser` исправлена upstream в
[PR #6694](https://github.com/XTLS/Xray-core/pull/6694).
Транспортные тесты проверяют публикацию профилей, передачу данных и reload/failover
через реальные соединения, не конструируя приватные структуры Xray.

TLS-сертификаты серверных транспортов загружаются с `oneTimeLoading: true`,
чтобы исключить конкурентную публикацию сертификата внутренним ticker Xray.
После замены файлов сертификата требуется контролируемый reload или перезапуск
relay; автоматическое перечитывание Xray отключено, включая OCSP ticker.
При эксплуатации с автоматическим продлением сертификата настрой deploy-hook
`systemctl restart ultra-relay` после успешного продления. Перезапуск кратко
прерывает активные соединения. Не применяй этот hook к одному лишь сертификату бота.


При сравнении разобранных конфигураций Xray учитывай вложенные `TypedMessage.Value`:
обычный `proto.Equal` сравнивает эти байты, включая случайный порядок map-заголовков.
[Runner](../internal/proxy/runner.go) нормализует вложенные protobuf перед сравнением;
[регрессионный тест](../internal/proxy/runner_test.go) проверяет неизменные XHTTP-заголовки
и ровно один reload при реальном изменении. Исходные файлы конфигурации продолжают
разбираться заново, чтобы изменения сертификатов и geo-ресурсов учитывались.

## Проверки кабинетов и облачных операций

`make test-ui` включает личный кабинет, импорт Happ и изолированный макет.
`internal/cloud` тестируется с подменённым провайдером: тесты не покупают VPS.
DB-интеграция дополнительно проверяет конкурентное резервирование слотов,
создание профилей при одновременной регистрации и публикации, а также сохранение
журнала после создания нового экземпляра репозитория.
Новые роли доступа проверяйте через личный и административный API отдельно;
успех административного запроса не доказывает изоляцию владельцев.


Bridge закрепляет bootstrap-адреса имени Yandex DoH в `dns.hosts`, сохраняя проверку
TLS по имени. Без этого правило `domain:yandex.net` направляет разрешение имени
резолвера в него самого и Xray пишет `tries to resolve itself`. При изменении адресов
сверяй [официальный каталог Yandex DNS](https://dns.yandex.ru/) и проверяй
[bootstrap-тест](../internal/config/xray_dns_test.go); не заменяй это незаметным
fallback пользовательских запросов на системный DNS.

## Изолированный транспортный шлюз

`TestExperimentalGatewayTLSAuthAccountingAndRestart` передаёт TCP и UDP/XUDP через отдельный XHTTP/TLS процесс в закрытый VLESS-вход: подтверждает однократный учёт, блокировку отключённого UUID и отсутствие reload основного процесса при перезапуске эксперимента. Проверки локальные и не доказывают устойчивость в сети оператора.

`scripts/test-bridge-subscription.py` проверяет шаблоны роли Nginx, а `scripts/test-ansible-ingress.py` и `scripts/test-ansible-owned-file.py` — переходы публикации, идемпотентность и отказ от перезаписи чужих файлов без SSH. Проверки модулей запускаются Python из закреплённого окружения Ansible. `make test-ui` проверяет состояния основного/экспериментального входа. Новые поля входа сохраняются при `ReuseSpec`; тест защищает их от потери при повторной установке.

## Проверка автономного relay

Тесты локального хранения и приёма трафика описаны в
[локальном состоянии](runtime-state.md). PostgreSQL 16 в CI обязателен; тестовая
DSN задаётся сервисом workflow. Бот использует lazy pool без миграций, миграции
принадлежат relay. Отдельно проверяйте холодный запуск бота при недоступных Telegram
и PostgreSQL, отказ обязательного listener и восстановление кеша подписок.
Источники: [запуск](../cmd/ultra-bot/main.go), [проверка отказа listener](../cmd/ultra-bot/reliability_test.go).

[Проверка интервала переключения exit](../cmd/ultra-relay/exit_acceptance_test.go)
запускается отдельно: `env -u DATABASE_URL ULTRA_EXIT_ACCEPTANCE_LOCAL=1 go test
./cmd/ultra-relay -run '^TestExitAcceptanceProductionCadence$' -count=1 -timeout=2m`.
Она использует настоящий автономный runtime и производственный интервал health
10 секунд, изолированные loopback-входы, собственный журнал и фиктивного владельца.
Отключаются только потоки тестовых TCP-forwarders; рабочие exit не меняются.
Обычные быстрые runtime-тесты используют интервал 100 мс и сами по себе не проверяют
производственное время переключения. WAN-режим этой проверки требует отдельно
разрешённого приватного fixture с двумя exit и ожидаемыми IP; он не запускается
обычными тестами и не заменяет проверку Happ на устройстве. IP HTTPS-выхода заранее
подтверждается независимо на каждом exit: при `anti_censor.warp_proxy` сайты видят
адрес WARP, а не публичный адрес VM. Не подменяйте ожидание IP результатом неудачной
проверки; маршрут TCP через WARP задаёт [генератор exit](../internal/config/xray_exit.go).
Изоляция входа должна сохранять `mimic_preset` и `xray_wire`: они определяют в том
числе Host, TLS-имя, заголовки и режим туннеля по умолчанию. WAN-проверка сравнивает
исходные и изолированные outbound-настройки до подстановки тестовых адресов;
отдельная регрессия обнаруживает потерю этих параметров.
Диагностическое `gate_reachable` означает доступность локального forwarder;
соединение с настоящим exit отражают отдельные счётчики upstream dial.
Успешный curl на exit через системный DNS не подтверждает путь Xray через DoH:
полную проверку выполняет запрос через соответствующий туннель.

[Совместный нагрузочный тест](../cmd/ultra-relay/combined_load_integration_test.go)
использует выделенную PostgreSQL через loopback `DATABASE_URL` и собственную
временную схему. Пять клиентов передают TCP/UDP одновременно с checkpoint,
доставкой статистики, потерей ответа после коммита, проверяемым копированием
неизменяемого зашифрованного артефакта и отказом exit. После остановки проверяются
полная выгрузка очереди и равенство расходов локальным резервам. Это проверка
совместной локальной работы. Дополнительный
[сценарий дампа под нагрузкой](../scripts/test-load-pg-recovery.py) запускает этот
тест, дожидается подтверждённого трафика пяти владельцев, выполняет `pg_dump`
его изолированной схемы во время передачи и восстанавливает её в новую временную
БД того же тестового контейнера. Проверяются схема 24 и расходы пяти владельцев;
созданная БД удаляется. Запуск: `DATABASE_URL=<test DSN> python3
scripts/test-load-pg-recovery.py --container <test PostgreSQL16 container>`.
Разрешены только loopback и тестовые БД `ultra_test`/`ultra_ci`; порт контейнера
должен совпадать с DSN. CI запускает сценарий обязательно. Эта проверка не
подтверждает копирование всех ключей под нагрузкой, полное восстановление VM
или поведение Happ на Android.

## Проверки исполнителя Ansible

Offline runtime архив нормализует владельца в tar-заголовках до root, а роль
контроллера явно задаёт root при распаковке. Иначе UID сборочной машины переносится
на сервер и проверка владения отклоняет комплект с `retention_foreign_tree`.
Регрессия в `scripts/test-ansible-release-retention.py` проверяет оба уровня;
ограничение на чужого владельца не ослабляется. Модуль возвращает безопасный
`reason_code` без путей и подробностей системных исключений.
В UTF-8 окружении CPython 3.14 создаёт в venv дополнительную ссылку `𝜋thon`:
локальный inventory разрешает только это точное имя с целью `python3`.
Регрессия `TestOperatorRuntimePython314Alias` сохраняет отказ для других целей
и похожих имён; общий запрет произвольных ссылок остаётся действующим.

`scripts/test-ansible-release-retention.py` проверяет локально предел хранения
исполняемых комплектов, отказ удалять неизвестные или изменённые файлы,
сохранение ссылок незавершённой операции и подписанного канала, повтор после
прерывания записи владения, а также очистку только терминальных служебных
payload без удаления квитанций и операторских входов.


`make test-ansible` запускает закреплённый `ansible-lint` и syntax checks.
`make test-ansible-exit` требует Docker и Ansible: он применяет роль через настоящий
SSH в одноразовом контейнере, проверяет сохранение UUID/сертификата и отсутствие
повторной активации неизменной конфигурации. Service manager контейнера подменён;
этот тест не подтверждает настоящий systemd boot или передачу через туннель.
Отдельная регрессия сохраняет Jinja-подобный текст буквально и проверяет отсутствие
lookup на управляющем узле. Генерируются только временные fixture-ключи; production-конфигурация не читается.

`scripts/test-ansible-forward-role.py --ansible-playbook <absolute executable>`
проверяет роль forwarding через настоящий SSH и Nginx: listeners, повтор без
reload, восстановление прежних файлов после ошибки проверки или reload и отказ
перезаписывать чужой файл. Systemd в контейнере заменён тестовым исполнителем;
эта проверка не подтверждает загрузку настоящей VM.

`go test -race ./internal/deployansible ./internal/cloudinstall ./cmd/ultra-install`
проверяет приватность входов, отказ изменённому заданию, повтор результата,
отсутствие ложного успеха, дескрипторный допуск и продолжение очереди после перезапуска worker.
Тест Unix-сокета требует разрешённых локальных сокетов. DB-интеграция к этому
набору не относится; её проверяют отдельно на выделенном PostgreSQL.

Входы Ansible передаются как JSON-совместимый контейнер с `!unsafe`, а не набор
помеченных скаляров: загрузчик закреплённого Ansible 2.20 повторно определяет тип
отдельного `!unsafe`-скаляра даже в кавычках. Это могло менять строковые права,
пароли или настройки. `scripts/test-ansible-input-types.py` проверяет сохранение
типов и запрет вычисления вложенных выражений через настоящий DataLoader/Templar.

Диагностические shell-скрипты получают только разрешённые несекретные параметры
через `ultra-install config-values`: общий Go-парсер формирует NUL-пары,
оболочка назначает их через `printf -v`, без `eval` и второго разбора файла.
Перед их запуском нужен собранный или установленный `ultra-install`;
`ULTRA_INSTALL_BIN` позволяет указать его абсолютный путь. Секретные ключи
в `install.config` и NUL внутри значения отклоняются.
