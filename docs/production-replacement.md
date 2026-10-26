# Полная замена production

`make deploy` — единственный штатный путь по умолчанию для полной замены
non-DB production. Он разворачивает выбранный committed candidate на bridge и
exit как новую установку; допускается полный простой и потеря состояния этих
узлов. Отдельный upgrade/adoption, продолжение старой выкладки и её rollback
не являются поддерживаемыми режимами.

Старые deployment journals, admission markers, worker jobs, receipts и прочее
состояние старой выкладки отбрасываются вместе со старым non-DB окружением. Они
не возобновляются, не откатываются и не согласуются с новой установкой. Старый
journal не блокирует новую замену. Неиспользуемые legacy runbooks и команды не
являются путём развёртывания.

## Граница базы данных

PostgreSQL primary, прикладные таблицы, данные и версия миграций сохраняются.
Обычная замена не создаёт дамп, не восстанавливает, не импортирует и не мигрирует
прикладную базу. Для replica status bootstrap может восстановить только служебные
каталожные объекты `ultra_monitor` (схему, функцию и grants). Для отсутствующей
standby на новом bridge разрешено пересоздать только неактивный потерянный
physical slot `ultra_bridge` после проверки identity primary и replication login;
пользовательские роли и пароли не меняются. DB host не входит
в набор заменяемых узлов. На bridge cleanup также сохраняет DB tunnel, standby
data directory и `ultra-postgres-replica.service`, чтобы физическая реплика
продолжала работать. Если standby отсутствует, bootstrap создаёт её через
`pg_basebackup` по каноническому управляемому пути. Существующий PGDATA не
перезаписывается; потерянный slot при существующем PGDATA, активный slot при
отсутствующем PGDATA, отсутствующий slot или replication role останавливают
замену. После запуска обязательны streaming и replay свежего WAL marker.
`make deploy` проверяет узлы из текущей конфигурации,
последней успешно выложенной конфигурации и всех конфигураций неуспешных попыток
после неё: бывшие bridge/exit тоже очищаются, даже если их уже убрали из списка.
Последняя успешная конфигурация сохраняется как
`dist/manual/last-deployed.config`, а неуспешные снимки — в закрытом каталоге
`dist/manual/replacement-attempts/`. Снимок сохраняется до запуска первого
fencing-шага и остаётся до успешной замены, чтобы следующая попытка учла каждый
парк, на котором могла частично начаться предыдущая. Ошибка read-only admission
до fencing не оставляет снимок и не блокирует исправленную конфигурацию.
При успехе последняя успешная конфигурация обновляется, а снимки попыток удаляются.
Эти файлы служат только инвентарём целей; старые операции по ним не возобновляются.
При первом запуске, когда таких снимков ещё нет, единственный известный список
целей — текущая конфигурация. Если до первого запуска из неё уже удалили старые
узлы, перед заменой сохраните прежнюю конфигурацию как
`dist/manual/last-deployed.config` с правами 0600. Команда
фиксирует identity и schema primary до замены и сравнивает их после неё. Если
кандидату нужна новая прикладная схема,
это отдельная явно спланированная операция, а
не часть обычной замены.

Обычный `make deploy` не требует предоставленного оператором backup, backup
digest, restore receipt или дополнительного ACK.

До первого remote fencing installer read-only проверяет фиксированный локальный
execution namespace. Повреждённый fence, running или отсутствующий receipt,
неизвестная операция и активный локальный исполнитель останавливают замену до
отключения сервисов. Точная failed generation прежней канонической replacement
может быть автоматически оставлена как evidence: её неизменяемый request должен
описывать только текущие и явно сохранённые предыдущие цели с pinned root transport,
а `primary-before.json` именно её workspace — ту же identity primary.

Перед остановкой приложений на всём non-DB парке replacement проверяет и
подготавливает root SSH liveness: `ClientAliveInterval 10`, `ClientAliveCountMax 2`.
Управляемый Include добавляется только в конец `sshd_config`, а root-only policy
проверяется через `sshd -t` и `sshd -T -C`: остальные effective root-настройки и
настройки non-root не меняются. Конфликт, чужой файл, неизвестный suffix после
managed Include или ошибка reload останавливают работу до app fencing; изменение
обоих файлов откатывается. До записи проверяются `ssh.service` MainPID/ExecStart,
реальный executable и startup args listener: поддерживается штатный
`/usr/sbin/sshd -D` с optional `-e`; custom `-f`/`-o`, неизвестные overrides и
заменённый executable закрывают gate. Проверенный listener получает SIGHUP через
pidfd, независимо от ExecReload unit. Активация обязательна и при идентичных
управляемых файлах: предыдущий процесс мог завершиться до reload.
Primary SSH config не затрагивается.

Census не исключает и не завершает чужие SSH/PAM sessions. Он повторяет полную
проверку до 40 секунд и отслеживает все наблюдавшиеся SSH-деревья процессов, SID и PAM scope
после смены UID или reparenting. Timeout и неизвестные helpers оставляют gate закрытым.
Server-side liveness ограничивает жизнь новых неотвечающих SSH clients даже когда
TCP proxy удерживает backend-соединение; уже открытые до policy сеансы не получают
новую настройку. Responsive sessions и отделившиеся workers по-прежнему блокируют
замену. Первый rollout не может считать старые unknown sessions безопасными.

Перед fencing проверяется локальная quiescence. Затем под глобальным admission
lock штатная замена обнаруживает и останавливает весь non-DB парк, проверяет
remote sessions, workers и primary transactions, повторяет identity/schema/routes
primary и локальную quiescence. Только после этих проверок existing abandonment
protocol сохраняет failed receipt/dispatch и закрывает точную generation. Cleanup
и новый bootstrap выполняются после retirement; старый workspace не возобновляется.
Ошибка любой проверки сохраняет fence и запрещает cleanup/bootstrap.
От первой мутации до завершения bootstrap фиксированный account-global reservation
исключает любой другой поддерживаемый mutating dispatch, включая промежуток после
retirement. Дочерний bootstrap получает тот же locked descriptor с проверкой private
record, PID/start родителя и точного workspace; переменные окружения сами по себе
доступа не дают. Native SSH выполняется под локальным supervisor, который удерживает
lock и собственный ограниченный deadline при смерти родителя.

После успешного завершения reservation удаляется. Ошибка после начала remote
изменений сохраняет private marker и immutable scope. Следующий канонический запуск
может автоматически принять только запись умершего владельца с завершёнными
локальными исполнителями, теми же сохранёнными целями и identity primary; он заново
проводит полный remote fencing и quiescence перед cleanup. Живой исполнитель,
неизвестная область или повреждённая запись продолжают блокировать запуск.
Без fence порядок обычной замены сохраняется под тем же reservation. Локальный execution namespace не является
простым disposable каталогом bridge: его нельзя очищать вместо этих проверок.

Backup и restore PostgreSQL остаются отдельными явными инструментами для
аварийного восстановления или специально порученной операции с данными. Они не
являются предварительным условием `make deploy` и не должны применяться поверх
здоровой primary. См. [резервное копирование и восстановление](../deploy/recovery/README.md)
и [контракт отдельной БД](replication.md).

## Вспомогательная автоматизация и функциональность сервиса

Recovery preparation, backup readiness и automation recovery не блокируют
штатную VPN-замену. Bootstrap всё равно устанавливает controller, fleet identity
и Vultr provider integration, чтобы пользовательские операции создания,
проверки, замены и удаления cloud nodes оставались доступны. Замена сохраняет
и запускает Telegram-бота и Mini App.

## Источники

[ADR 0023](adr/0023-destructive-production-replacement.md),
[установка и эксплуатационная автоматизация](automation.md),
[перенос bridge](bridge-migration.md).
